# Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
# Copyright (c) 2026 Chainguard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Common library for Cinc Auditor scanning scripts.
# Source this file from scanning scripts; do not execute directly.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: cinc-common.sh is a library and must be sourced, not executed." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Global variables
# ---------------------------------------------------------------------------
# Caller must set before calling library functions:
#   SCRIPT_DIR          - absolute path to the directory containing the
#                         calling script (typically tools/)
#   IMAGE               - container image reference to scan
#   LABEL               - environment label (default: dev)
#   RESULTS_DIR_INPUT   - directory for output files (default: ./results)
#   USE_EMBEDDED_PROFILE- true/false (default: true)
#   ROOTFS_MOUNT        - host path to bind-mount as /rootfs in cinc-auditor
#   EXTRA_AUDITOR_ARGS  - optional array of additional docker run args
#                         (initialised to empty below; append before calling
#                         cinc_run_auditor)
#
# Variables set by library functions (available to the caller afterward):
#   RESULTS_DIR, OUTPUT_JSON, OUTPUT_HTML, IMAGE_NAME_NO_DIGEST
#   IMAGE_DIGEST, ASLR_VALUE, INSPEC_EXIT_CODE
#   PROFILE_PATH, PROFILE_DIR, PROFILE_SOURCE
#   REPORT_SCRIPT_HOST, REPORT_SCRIPT_CONTAINER

# ---------------------------------------------------------------------------
# Default configuration (override via environment before sourcing)
# ---------------------------------------------------------------------------
CINC_AUDITOR_IMAGE="${CINC_AUDITOR_IMAGE:-cgr.dev/chainguard/cinc-auditor:latest}"
ASLR_HELPER_IMAGE="${ASLR_HELPER_IMAGE:-${CINC_AUDITOR_IMAGE}}"
ASLR_SETTING_LOCATION="${ASLR_SETTING_LOCATION:-/proc/sys/kernel/randomize_va_space}"
REPORT_SCRIPT_XCCDF_LOCATION="${REPORT_SCRIPT_XCCDF_LOCATION:-/usr/share/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml}"
USE_EMBEDDED_PROFILE=true
EXTRA_AUDITOR_ARGS=()
# Additional arguments passed to cinc-auditor exec (e.g. --input key=value).
# Append before calling cinc_run_auditor.
EXTRA_INSPEC_ARGS=()
# Host path to an InSpec input file (YAML) used to override inspec.yml defaults.
# Set via the scan scripts' --input-file flag (see cinc_set_input_file). When
# set, the runners bind-mount it read-only into the auditor container and pass
# --input-file with the container path — the host path is meaningless inside the
# container, which is why stuffing "--input-file <host-path>" into
# EXTRA_INSPEC_ARGS does NOT work. Empty = no input file.
INPUT_FILE=""
# Fixed path the input file is mounted at inside the auditor container.
INPUT_FILE_CONTAINER="/cinc-input-overrides.yml"
# Path to the rootfs inside the cinc-auditor container.  Defaults to /rootfs
# for bind-mount-based scripts.  Override (e.g. /proc/<PID>/root) for scripts
# that access the filesystem via --pid=host without a bind mount.
ROOTFS_CONTAINER_PATH=""

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
cinc_check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "Error: docker is not installed or not in PATH" >&2
        exit 1
    fi
}

cinc_check_ruby() {
    $USE_EMBEDDED_PROFILE && return 0

    if ! command -v ruby >/dev/null 2>&1; then
        echo "Error: Ruby is required to generate the HTML report" >&2
        exit 1
    fi

    # The HTML report's XCCDF enrichment uses rexml, a bundled gem that is not
    # guaranteed present on Ruby 3.4+. Missing rexml is non-fatal — the report
    # still generates without the XCCDF-derived metadata (see
    # libraries/stig_mappings.rb) — so warn rather than exit.
    if ! ruby -e "require 'rexml/document'" >/dev/null 2>&1; then
        echo "Warning: the 'rexml' gem is not available; the HTML report will omit" >&2
        echo "         XCCDF enrichment. Run 'gem install rexml' for full reports." >&2
    fi
}

# ---------------------------------------------------------------------------
# Positional argument parsing
# ---------------------------------------------------------------------------
# Parse image [label [results-dir]] from "$@" (remaining args after flag parsing).
# Sets: IMAGE, LABEL, RESULTS_DIR_INPUT
# Returns 1 if the image argument is missing.
cinc_parse_positional_args() {
    if [ $# -lt 1 ]; then
        return 1
    fi
    IMAGE="$1"
    LABEL="${2:-dev}"
    RESULTS_DIR_INPUT="${3:-./results}"
}

# Validate and record the --input-file path. Resolves it to an absolute path
# (bind mounts require one) and stores it in INPUT_FILE; the runners then mount
# it into the auditor container and pass --input-file. Returns 1 (with a
# message) if the path is missing or not a regular file, so callers can print
# usage and exit.
cinc_set_input_file() {
    local f="$1"
    if [ -z "$f" ]; then
        echo "Error: --input-file requires a path" >&2
        return 1
    fi
    if [ ! -f "$f" ]; then
        echo "Error: --input-file '$f' is not a readable file" >&2
        return 1
    fi
    INPUT_FILE="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"
}

# ---------------------------------------------------------------------------
# Profile and output path setup
# ---------------------------------------------------------------------------
# Requires: SCRIPT_DIR, USE_EMBEDDED_PROFILE
# Sets: PROFILE_PATH, PROFILE_DIR, PROFILE_SOURCE,
#       REPORT_SCRIPT_HOST, REPORT_SCRIPT_CONTAINER
cinc_setup_profile_paths() {
    PROFILE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    REPORT_SCRIPT_HOST="${SCRIPT_DIR}/generate_stig_html.rb"
    REPORT_SCRIPT_CONTAINER="/usr/share/chainguard-inspec/tools/generate_stig_html.rb"
    if $USE_EMBEDDED_PROFILE; then
        PROFILE_PATH="/usr/share/chainguard-inspec/"
        PROFILE_SOURCE="embedded"
    else
        PROFILE_PATH="/profile"
        PROFILE_SOURCE="local bind mount"
    fi
}

# Requires: IMAGE, RESULTS_DIR_INPUT
# Optional: $1 = filename suffix appended to the safe image name (default: stig)
# Sets: RESULTS_DIR, SAFE_IMAGE_NAME, TIMESTAMP, OUTPUT_JSON, OUTPUT_HTML,
#       IMAGE_NAME_NO_DIGEST
cinc_setup_output_paths() {
    local suffix="${1:-stig}"
    mkdir -p "${RESULTS_DIR_INPUT}"
    RESULTS_DIR="$(cd "${RESULTS_DIR_INPUT}" && pwd)"
    SAFE_IMAGE_NAME="$(echo "${IMAGE}" | tr '/:@' '-')-${suffix}"
    TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    OUTPUT_JSON="${RESULTS_DIR}/${SAFE_IMAGE_NAME}-${TIMESTAMP}.json"
    OUTPUT_HTML="${RESULTS_DIR}/${SAFE_IMAGE_NAME}-${TIMESTAMP}.html"
    IMAGE_NAME_NO_DIGEST="$(echo "${IMAGE}" | cut -d'@' -f1)"
}

# ---------------------------------------------------------------------------
# Scan header / footer
# ---------------------------------------------------------------------------
# $1 = scan type description (e.g. "Filesystem reconstruction", "Live overlay")
cinc_print_scan_header() {
    local scan_type="${1:-Scan}"
    echo "============================================================"
    echo "Chainguard GPOS STIG Compliance Scan (${scan_type})"
    echo "============================================================"
    echo "Image:       ${IMAGE_NAME_NO_DIGEST}"
    echo "Label:       ${LABEL}"
    echo "Results:     ${RESULTS_DIR}"
    echo "Profile:     ${PROFILE_SOURCE}"
    echo ""
}

cinc_print_scan_complete() {
    echo ""
    echo "============================================================"
    echo "Scan complete"
    echo "============================================================"
    echo "JSON Results:  $(basename "${OUTPUT_JSON}")"
    echo "HTML Report:   $(basename "${OUTPUT_HTML}")"
    echo "Results saved in: ${RESULTS_DIR}"
    echo "============================================================"
}

# ---------------------------------------------------------------------------
# Image management
# ---------------------------------------------------------------------------
cinc_pull_image() {
    echo "Checking container image availability..."
    if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
        echo "Image found locally; skipping docker pull."
    else
        echo "Pulling container image with docker..."
        docker pull "${IMAGE}" >/dev/null
    fi
}

# Sets: IMAGE_DIGEST
cinc_get_image_digest() {
    echo "Gathering image digest..."
    IMAGE_DIGEST="$(docker image inspect "${IMAGE}" \
        --format '{{index .RepoDigests 0}}' 2>/dev/null \
        | grep -o 'sha256:[a-f0-9]*' || echo "unknown")"
}

# ---------------------------------------------------------------------------
# ASLR capture
# ---------------------------------------------------------------------------
# Sets: ASLR_VALUE
cinc_capture_aslr() {
    echo "Capturing runtime kernel settings..."
    ASLR_VALUE="$(docker run --rm --pid=host --platform linux/amd64 \
        --entrypoint cat \
        "${ASLR_HELPER_IMAGE}" "${ASLR_SETTING_LOCATION}" 2>/dev/null \
        || echo "unavailable")"
    if [ "${ASLR_VALUE}" = "unavailable" ]; then
        echo "Warning: Unable to capture ASLR setting from host kernel" >&2
    fi
}

# Verify a target container is still running. Scan modes that read a *live*
# container depend on this: the live scan reads /proc/<PID>/root (the PID must
# be alive) and the docker:// transport execs into the container (it must be
# running). A target that has exited yields empty/unreliable results, so abort
# with an actionable error instead. (Modes that read a static snapshot —
# cinc-chainguard.sh's `docker export`, or the overlay merged dir, which stays
# mounted until `docker rm` — do not need this.)
#
# $1 = container id
# $2 = phase label for the message (e.g. "after startup", "after the scan")
# $3 = optional hint line with mode-specific guidance
# Returns 0 if running, 1 (after printing guidance to stderr) otherwise.
cinc_require_target_running() {
    local container_id="$1" phase="$2" hint="${3:-}"
    local running
    running="$(docker inspect --format '{{.State.Running}}' "${container_id}" 2>/dev/null || echo false)"
    [ "${running}" = "true" ] && return 0

    local status exit_code
    status="$(docker inspect --format '{{.State.Status}}' "${container_id}" 2>/dev/null || echo unknown)"
    exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${container_id}" 2>/dev/null || echo unknown)"
    {
        echo "Error: target container ${container_id} is not running (${phase}); status=${status}, exit code=${exit_code}."
        echo "       Container logs:"
        docker logs "${container_id}" 2>&1 | tail -n 10 | sed 's/^/       /'
        [ -n "${hint}" ] && echo "       ${hint}"
    } >&2
    return 1
}

# ---------------------------------------------------------------------------
# Cinc Auditor execution
# ---------------------------------------------------------------------------
# Requires: RESULTS_DIR, OUTPUT_JSON
#           USE_EMBEDDED_PROFILE, PROFILE_PATH, PROFILE_DIR
#           CINC_AUDITOR_IMAGE
# Optional: ROOTFS_MOUNT         - host path to bind-mount as the rootfs
#                                  (leave empty to skip the bind mount, e.g.
#                                  when using --pid=host + /proc/<PID>/root)
#           ROOTFS_CONTAINER_PATH- path to rootfs inside cinc-auditor container
#                                  (defaults to /rootfs)
#           EXTRA_AUDITOR_ARGS   - array of additional docker run arguments
# Sets: INSPEC_EXIT_CODE
cinc_run_auditor() {
    local inspec_json_basename
    inspec_json_basename="$(basename "${OUTPUT_JSON}")"
    local rootfs_path="${ROOTFS_CONTAINER_PATH:-/rootfs}"

    echo "Running Cinc Auditor..."
    set +e
    # --user 0:0 lets the auditor read every file in the target regardless of
    # owner/mode. --privileged is a blanket grant (all capabilities, device
    # access, relaxed seccomp/AppArmor) that is broader than the read-only
    # bind-mount scans strictly need; live mode does need host /proc access
    # (--pid=host, added by the caller). Narrowing this to the specific
    # capabilities each mode requires is a tracked follow-up. See the README
    # "Required privileges".
    local auditor_args=(
        --rm
        --privileged
        --platform linux/amd64
        --user 0:0
        -e ROOTFS_DIR="${rootfs_path}"
        -v "${RESULTS_DIR}:/results:rw"
    )

    if [ -n "${ROOTFS_MOUNT:-}" ]; then
        auditor_args+=(-v "${ROOTFS_MOUNT}:${rootfs_path}:ro")
    fi

    # When using the local profile, do NOT bind-mount the repository root: cinc-
    # auditor / InSpec 7.x reads a directory profile as a control-less gem
    # resource pack if any *.gemspec exists anywhere under the profile path (e.g.
    # test/vendor/bundle created by `bundle install`). Mount only the profile's
    # own files into /profile so local dev artifacts can't hijack control
    # discovery. See docs/testing.md and inspec/inspec#7934.
    if ! $USE_EMBEDDED_PROFILE; then
        auditor_args+=(
            -v "${PROFILE_DIR}/inspec.yml:/profile/inspec.yml:ro"
            -v "${PROFILE_DIR}/controls:/profile/controls:ro"
            -v "${PROFILE_DIR}/libraries:/profile/libraries:ro"
        )
    fi

    if [ "${#EXTRA_AUDITOR_ARGS[@]}" -gt 0 ]; then
        auditor_args+=("${EXTRA_AUDITOR_ARGS[@]}")
    fi

    # Bind-mount the input-override file into the auditor container so
    # --input-file can resolve it (the host path is not visible in-container).
    if [ -n "${INPUT_FILE}" ]; then
        auditor_args+=(-v "${INPUT_FILE}:${INPUT_FILE_CONTAINER}:ro")
    fi

    local inspec_args=(
        --no-create-lockfile
        --reporter cli
        --reporter "json:/results/${inspec_json_basename}"
        --input "rootfs=${rootfs_path}"
    )

    if [ -n "${INPUT_FILE}" ]; then
        inspec_args+=(--input-file "${INPUT_FILE_CONTAINER}")
    fi

    if [ "${#EXTRA_INSPEC_ARGS[@]}" -gt 0 ]; then
        inspec_args+=("${EXTRA_INSPEC_ARGS[@]}")
    fi

    docker run "${auditor_args[@]}" \
        "${CINC_AUDITOR_IMAGE}" \
        exec "${PROFILE_PATH}" \
          "${inspec_args[@]}"
    INSPEC_EXIT_CODE=$?
    set -e
}

cinc_check_exit_code() {
    echo "InSpec exit code: ${INSPEC_EXIT_CODE}"
    if [ "${INSPEC_EXIT_CODE}" -ne 0 ] && \
       [ "${INSPEC_EXIT_CODE}" -ne 100 ] && \
       [ "${INSPEC_EXIT_CODE}" -ne 101 ]; then
        echo "Error: InSpec execution failed (exit code ${INSPEC_EXIT_CODE})" >&2
        exit "${INSPEC_EXIT_CODE}"
    fi
}

cinc_check_json_output() {
    if [ ! -f "${OUTPUT_JSON}" ]; then
        echo "Error: Expected JSON results not found at ${OUTPUT_JSON}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------
# Requires: USE_EMBEDDED_PROFILE, CINC_AUDITOR_IMAGE,
#           REPORT_SCRIPT_CONTAINER (embedded) or REPORT_SCRIPT_HOST (local),
#           OUTPUT_JSON, OUTPUT_HTML, RESULTS_DIR,
#           IMAGE_NAME_NO_DIGEST, LABEL, IMAGE_DIGEST,
#           REPORT_SCRIPT_XCCDF_LOCATION
cinc_generate_html_report() {
    echo "Generating STIG HTML report..."
    local html_exit_code
    if $USE_EMBEDDED_PROFILE; then
        docker run --rm \
            --platform linux/amd64 \
            -v "${RESULTS_DIR}:/results:rw" \
            --user 0:0 \
            -e LANG=en_US.UTF-8 \
            -e LC_ALL=en_US.UTF-8 \
            --entrypoint /usr/bin/ruby \
            "${CINC_AUDITOR_IMAGE}" \
            "${REPORT_SCRIPT_CONTAINER}" \
            "/results/$(basename "${OUTPUT_JSON}")" \
            "/results/$(basename "${OUTPUT_HTML}")" \
            --container-name "${IMAGE_NAME_NO_DIGEST}" \
            --container-label "${LABEL}" \
            --container-sha256 "${IMAGE_DIGEST}" \
            --xccdf-path "${REPORT_SCRIPT_XCCDF_LOCATION}"
        html_exit_code=$?
    else
        ruby "${REPORT_SCRIPT_HOST}" \
            "${OUTPUT_JSON}" \
            "${OUTPUT_HTML}" \
            --container-name "${IMAGE_NAME_NO_DIGEST}" \
            --container-label "${LABEL}" \
            --container-sha256 "${IMAGE_DIGEST}" \
            --xccdf-path "${REPORT_SCRIPT_XCCDF_LOCATION}"
        html_exit_code=$?
    fi

    if [ "${html_exit_code}" -ne 0 ]; then
        echo "Warning: HTML report generation failed (exit code ${html_exit_code})" >&2
    else
        echo "HTML report generated at ${OUTPUT_HTML}"
    fi
}
