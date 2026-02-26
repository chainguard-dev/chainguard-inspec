#!/bin/bash
#
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

# Filesystem reconstruction scan using Cinc Auditor

set -euo pipefail

CINC_AUDITOR_IMAGE=${CINC_AUDITOR_IMAGE:-cgr.dev/chainguard-private/cinc-auditor:latest}
ASLR_HELPER_IMAGE=${ASLR_HELPER_IMAGE:-$CINC_AUDITOR_IMAGE}
ASLR_SETTING_LOCATION="${ASLR_SETTING_LOCATION:-/proc/sys/kernel/randomize_va_space}"
USE_EMBEDDED_PROFILE=true
USE_TMPFS=true
TMPFS_BASE=""
ROOTFS_DIR=""

cleanup() {
    set +e
    if [ -n "$ROOTFS_DIR" ] && [ -d "$ROOTFS_DIR" ]; then
        echo "Removing temporary rootfs directory..."
        rm -rf "$ROOTFS_DIR"
    fi
    if [ -n "${PROJECT_TMP_DIR:-}" ] && [ -d "$PROJECT_TMP_DIR" ]; then
        echo "Removing project temporary directory..."
        rm -rf "$PROJECT_TMP_DIR"
    fi
}

trap cleanup EXIT

usage() {
    cat <<'USAGE'
Usage: cinc-chainguard.sh [--use-tmpfs|--no-tmpfs] [--tmpfs-base <dir>] [--use-local-profile] <image> [label] [results-dir]

Arguments:
  --use-tmpfs          Force extraction into tmpfs (default, uses /dev/shm on Linux)
  --no-tmpfs           Disable tmpfs extraction and use on-disk workspace
  --tmpfs-base DIR     Specify an explicit tmpfs directory to use for extraction
  --use-local-profile  Mount local `chainguard_stig/` and run reports with host Ruby (developer mode)
  image            Container image to scan (required)
  label            Environment label (default: dev)
  results-dir      Directory to write JSON/HTML outputs (default: ./results)

Note: tmpfs extraction (--use-tmpfs) works on Linux with /dev/shm.
      On macOS, use --no-tmpfs for disk-based extraction.
      Always runs DISA STIG compliance scan using chainguard_stig profile.

Example:
  ./cinc-chainguard.sh --no-tmpfs cgr.dev/chainguard/nginx:latest dev
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --use-tmpfs)
            USE_TMPFS=true
            shift
            ;;
        --no-tmpfs)
            USE_TMPFS=false
            shift
            ;;
        --tmpfs-base)
            if [ $# -lt 2 ]; then
                echo "Error: --tmpfs-base requires a directory argument" >&2
                usage
                exit 1
            fi
            TMPFS_BASE="$2"
            shift 2
            ;;
        --use-local-profile)
            USE_EMBEDDED_PROFILE=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Error: unknown option $1" >&2
            usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

IMAGE="$1"
LABEL="${2:-dev}"
RESULTS_DIR_INPUT="${3:-./results}"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed or not in PATH" >&2
    exit 1
fi

if ! $USE_EMBEDDED_PROFILE && ! command -v ruby >/dev/null 2>&1; then
    echo "Error: Ruby is required to generate the HTML report" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_TMP_DIR="$SCRIPT_DIR/.tmp"

PROFILE_DIR="$SCRIPT_DIR/.."
REPORT_SCRIPT_HOST="$SCRIPT_DIR/generate_stig_html.rb"
PROFILE_PATH="/opt/chainguard-stig/"
REPORT_SCRIPT_CONTAINER="/opt/chainguard-stig/tools/generate_stig_html.rb"
PROFILE_SOURCE="embedded"

if ! $USE_EMBEDDED_PROFILE; then
    PROFILE_PATH="/profile"
    PROFILE_SOURCE="local bind mount"
fi

# Convert RESULTS_DIR to absolute path
mkdir -p "$RESULTS_DIR_INPUT"
RESULTS_DIR="$(cd "$RESULTS_DIR_INPUT" && pwd)"

SAFE_IMAGE_NAME="$(echo "$IMAGE" | tr '/:@' '-')"
SAFE_IMAGE_NAME="${SAFE_IMAGE_NAME}-stig"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_JSON="$RESULTS_DIR/${SAFE_IMAGE_NAME}-${TIMESTAMP}.json"
OUTPUT_HTML="$RESULTS_DIR/${SAFE_IMAGE_NAME}-${TIMESTAMP}.html"

IMAGE_NAME_NO_DIGEST="$(echo "$IMAGE" | cut -d'@' -f1)"

echo "============================================================"
echo "Chainguard GPOS STIG Compliance Scan (Filesystem reconstruction)"
echo "============================================================"
echo "Image:       $IMAGE_NAME_NO_DIGEST"
echo "Label:       $LABEL"
echo "Results:     $RESULTS_DIR"
echo "Profile:     $PROFILE_SOURCE"
echo ""

echo "Checking container image availability..."
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Image found locally; skipping docker pull."
else
    echo "Pulling container image with docker..."
    docker pull "$IMAGE" >/dev/null
fi

echo "Gathering image digest..."
IMAGE_DIGEST="$(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null | grep -o 'sha256:[a-f0-9]*' || echo "unknown")"

# Determine extraction base (tmpfs optional)
TEMP_ROOT_BASE="$PROJECT_TMP_DIR"

if $USE_TMPFS; then
    TMPFS_CANDIDATE="${TMPFS_BASE:-/dev/shm}"
    if [ -d "$TMPFS_CANDIDATE" ] && [ -w "$TMPFS_CANDIDATE" ]; then
        TEMP_ROOT_BASE="$TMPFS_CANDIDATE"
        echo "Using tmpfs base directory: $TEMP_ROOT_BASE"
    else
        echo "Warning: requested tmpfs base '$TMPFS_CANDIDATE' unavailable; using disk under $TEMP_ROOT_BASE" >&2
    fi
fi

mkdir -p "$TEMP_ROOT_BASE"
ROOTFS_DIR=$(mktemp -d "$TEMP_ROOT_BASE/chainguard-rootfs-XXXXXX")
export ROOTFS_DIR
echo "Temporary rootfs directory: $ROOTFS_DIR"
echo "Capturing runtime kernel settings..."
# ASLR is a host kernel setting - reuse the auditor image to read it
ASLR_VALUE="$(docker run --rm --pid=host --platform linux/amd64 \
    --entrypoint cat \
    "$ASLR_HELPER_IMAGE" "${ASLR_SETTING_LOCATION}" 2>/dev/null || echo "unavailable")"

if [ "$ASLR_VALUE" = "unavailable" ]; then
    echo "Warning: Unable to capture ASLR setting from host kernel" >&2
fi

CONTAINER_ID="$(docker create "$IMAGE")"
echo "Exporting filesystem from container $CONTAINER_ID..."
docker export "$CONTAINER_ID" | tar -C "$ROOTFS_DIR" -xf - --no-same-owner --exclude='dev/*'

docker rm "$CONTAINER_ID" >/dev/null

# Write captured runtime data to extracted filesystem
mkdir -p "$ROOTFS_DIR/.runtime_capture"
echo "$ASLR_VALUE" > "$ROOTFS_DIR/.runtime_capture/aslr_setting"
chmod 644 "$ROOTFS_DIR/.runtime_capture/aslr_setting"

# Ensure common symlink targets exist for tools that expect terminfo directories
mkdir -p "$ROOTFS_DIR/usr/share/terminfo"
echo "Ensured terminfo directory exists under rootfs"

# Normalize permissions on sensitive files for scanning
echo "Normalizing permissions on sensitive files"
if [ -f "$ROOTFS_DIR/etc/shadow" ]; then
    chmod 600 "$ROOTFS_DIR/etc/shadow"
fi

if [ -f "$ROOTFS_DIR/etc/passwd" ]; then
    chmod 644 "$ROOTFS_DIR/etc/passwd"
fi

if [ ! -d "$ROOTFS_DIR/etc" ]; then
    echo "Error: failed to reconstruct filesystem" >&2
    rm -rf "$ROOTFS_DIR"
    exit 1
fi

INSPEC_JSON_BASENAME="$(basename "$OUTPUT_JSON")"

echo "Running Cinc Auditor against reconstructed filesystem..."
set +e
AUDITOR_ARGS=(
    --rm
    --privileged
    --platform linux/amd64
    --user 0:0
    -e ROOTFS_DIR=/rootfs
    -v "$ROOTFS_DIR:/rootfs:ro"
    -v "$RESULTS_DIR:/results:rw"
)

if ! $USE_EMBEDDED_PROFILE; then
    AUDITOR_ARGS+=(-v "$PROFILE_DIR:/profile:ro")
fi

docker run "${AUDITOR_ARGS[@]}" \
    "$CINC_AUDITOR_IMAGE" \
    exec "$PROFILE_PATH" \
      --no-create-lockfile \
      --reporter cli \
      --reporter "json:/results/$INSPEC_JSON_BASENAME" \
      --input rootfs=/rootfs
INSPEC_EXIT_CODE=$?
set -e

echo "InSpec exit code: $INSPEC_EXIT_CODE"
if [ $INSPEC_EXIT_CODE -ne 0 ] && [ $INSPEC_EXIT_CODE -ne 100 ] && [ $INSPEC_EXIT_CODE -ne 101 ]; then
    echo "Error: InSpec execution failed (exit code $INSPEC_EXIT_CODE)" >&2
    exit $INSPEC_EXIT_CODE
fi

# Check for JSON output
if [ ! -f "$OUTPUT_JSON" ]; then
    echo "Error: Expected JSON results not found at $OUTPUT_JSON" >&2
    exit 1
fi

# Generate STIG HTML report
echo "Generating STIG HTML report..."
if $USE_EMBEDDED_PROFILE; then
    docker run --rm \
        --platform linux/amd64 \
        -v "$RESULTS_DIR:/results:rw" \
        -e LANG=en_US.UTF-8 \
        -e LC_ALL=en_US.UTF-8 \
        --entrypoint /opt/cinc-auditor/embedded/bin/ruby \
        "$CINC_AUDITOR_IMAGE" \
        "$REPORT_SCRIPT_CONTAINER" \
        "/results/$(basename "$OUTPUT_JSON")" \
        "/results/$(basename "$OUTPUT_HTML")" \
        --container-name "$IMAGE_NAME_NO_DIGEST" \
        --container-label "$LABEL" \
        --container-sha256 "$IMAGE_DIGEST"
    HTML_EXIT_CODE=$?
else
    ruby "$REPORT_SCRIPT_HOST" \
        "$OUTPUT_JSON" \
        "$OUTPUT_HTML" \
        --container-name "$IMAGE_NAME_NO_DIGEST" \
        --container-label "$LABEL" \
        --container-sha256 "$IMAGE_DIGEST"
    HTML_EXIT_CODE=$?
fi

if [ $HTML_EXIT_CODE -ne 0 ]; then
    echo "Warning: HTML report generation failed (exit code $HTML_EXIT_CODE)" >&2
else
    echo "HTML report generated at $OUTPUT_HTML"
fi

echo ""
echo "============================================================"
echo "Scan complete"
echo "============================================================"
echo "JSON Results:  $(basename "$OUTPUT_JSON")"
echo "HTML Report:   $(basename "$OUTPUT_HTML")"
echo "Results saved in: $RESULTS_DIR"
echo "============================================================"
