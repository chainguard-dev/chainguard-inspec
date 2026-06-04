#!/bin/bash
#
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

# Docker transport scan using Cinc Auditor (docker:// backend)
#
# Extracts a statically-linked busybox binary from a source image, then
# starts the target container with busybox bind-mounted at the paths
# cinc-auditor requires (/bin/sh, /usr/bin/cat, /usr/bin/sleep,
# /usr/bin/stat, /usr/bin/uname).  Cinc Auditor connects to the running
# container via the docker:// transport.
#
# /usr/bin/sleep is used as the container keep-alive entrypoint, avoiding
# any dependency on anchore-keep-alive or a host-installed busybox.
#
# Requirements:
#   - Docker
#   - A statically-linked busybox source image (default: busybox:musl).
#     The binary must be statically linked so it runs inside distroless
#     target images that lack shared libraries.
#     Override with BUSYBOX_SOURCE_IMAGE.  The cinc-auditor image can also
#     be used once it is publicly available, reducing the number of image
#     dependencies.
#   - The busybox binary path inside the source image (default: /bin/busybox)
#     Override with BUSYBOX_BINARY_PATH.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/cinc-common.sh
source "${SCRIPT_DIR}/lib/cinc-common.sh"

BUSYBOX_SOURCE_IMAGE="${BUSYBOX_SOURCE_IMAGE:-cgr.dev/chainguard/busybox-static:latest}"
BUSYBOX_BINARY_PATH="${BUSYBOX_BINARY_PATH:-/usr/bin/busybox}"

CONTAINER_ID=""
BUSYBOX_TMPDIR=""
BUSYBOX_CTR=""

cleanup() {
    set +e
    if [ -n "${CONTAINER_ID}" ]; then
        echo "Stopping and removing target container..."
        docker stop "${CONTAINER_ID}" >/dev/null 2>&1 || true
        docker rm "${CONTAINER_ID}" >/dev/null 2>&1 || true
    fi
    if [ -n "${BUSYBOX_CTR}" ]; then
        docker rm "${BUSYBOX_CTR}" >/dev/null 2>&1 || true
    fi
    if [ -n "${BUSYBOX_TMPDIR}" ]; then
        rm -rf "${BUSYBOX_TMPDIR}"
    fi
}

trap cleanup EXIT

usage() {
    cat <<'USAGE'
Usage: cinc-chainguard-docker-transport.sh [--use-local-profile] <image> [label] [results-dir]

Arguments:
  --use-local-profile  Mount local profile and run reports with host Ruby (developer mode)
  image            Container image to scan (required)
  label            Environment label (default: dev)
  results-dir      Directory to write JSON/HTML outputs (default: ./results)

Environment variables:
  BUSYBOX_SOURCE_IMAGE   Image to extract a statically-linked busybox from
                         (default: busybox:musl).  The binary must be
                         statically linked to run inside distroless target
                         images.  Once the cinc-auditor image is publicly
                         available it can be used here to reduce the number
                         of image dependencies.
  BUSYBOX_BINARY_PATH    Path of the busybox binary inside BUSYBOX_SOURCE_IMAGE
                         (default: /bin/busybox)

Note: Uses the docker:// cinc-auditor transport.  The target container is
      started with busybox bind-mounted at /bin/sh, /usr/bin/cat,
      /usr/bin/sleep, /usr/bin/stat and /usr/bin/uname so that
      cinc-auditor can execute commands inside it regardless of whether
      those utilities are present in the image.

      Works on Linux, macOS, and Windows (Docker Desktop).

      For private Chainguard images, run 'chainctl auth configure-docker'
      before invoking this script.

Example:
  ./cinc-chainguard-docker-transport.sh cgr.dev/chainguard/crane:latest dev
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
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

if ! cinc_parse_positional_args "$@"; then
    usage
    exit 1
fi

cinc_check_docker
cinc_check_ruby
cinc_setup_profile_paths
cinc_setup_output_paths "stig"
cinc_print_scan_header "Docker transport"
cinc_pull_image
cinc_get_image_digest

# ---------------------------------------------------------------------------
# Extract busybox from the source image
# ---------------------------------------------------------------------------
echo "Pulling busybox source image (${BUSYBOX_SOURCE_IMAGE})..."
if ! docker image inspect "${BUSYBOX_SOURCE_IMAGE}" >/dev/null 2>&1; then
    docker pull "${BUSYBOX_SOURCE_IMAGE}" >/dev/null
fi

echo "Extracting busybox binary..."
BUSYBOX_CTR="$(docker create "${BUSYBOX_SOURCE_IMAGE}" "${BUSYBOX_BINARY_PATH}")"

# Use /dev/shm (tmpfs) on Linux for fast cleanup; fall back to mktemp on macOS.
if [ "$(uname -s)" = "Linux" ] && [ -d /dev/shm ]; then
    BUSYBOX_TMPDIR="$(mktemp -d /dev/shm/cinc-busybox.XXXXXX)"
else
    BUSYBOX_TMPDIR="$(mktemp -d)"
fi

docker cp "${BUSYBOX_CTR}:${BUSYBOX_BINARY_PATH}" "${BUSYBOX_TMPDIR}/busybox"
docker rm "${BUSYBOX_CTR}"
BUSYBOX_CTR=""
chmod +x "${BUSYBOX_TMPDIR}/busybox"
echo "Busybox extracted to ${BUSYBOX_TMPDIR}/busybox"

# ---------------------------------------------------------------------------
# Start target container with busybox bind-mounted
# ---------------------------------------------------------------------------
echo "Starting target container with busybox utilities..."
CONTAINER_ID="$(docker run -d \
    -v "${BUSYBOX_TMPDIR}/busybox:/bin/sh" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/base64" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/cat" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/echo" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/readlink" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/sleep" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/stat" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/test" \
    -v "${BUSYBOX_TMPDIR}/busybox:/usr/bin/uname" \
    --entrypoint /bin/sh \
    "${IMAGE}" -c 'trap exit TERM INT; /usr/bin/sleep infinity & wait $!')"

# Verify the container is still running
if ! docker inspect "${CONTAINER_ID}" --format '{{.State.Running}}' \
        2>/dev/null | grep -q "^true$"; then
    EXIT_CODE="$(docker inspect "${CONTAINER_ID}" \
        --format '{{.State.ExitCode}}' 2>/dev/null || echo 'unknown')"
    echo "Error: target container exited immediately after starting (exit code: ${EXIT_CODE})." >&2
    echo "       Container logs:" >&2
    docker logs "${CONTAINER_ID}" 2>&1 | sed 's/^/       /' >&2
    echo "       Check that the image accepts the busybox bind mounts." >&2
    exit 1
fi

echo "Target container: ${CONTAINER_ID}"

# ---------------------------------------------------------------------------
# Run cinc-auditor via docker:// transport
# ---------------------------------------------------------------------------
# cinc-auditor connects directly to the running container via the Docker
# socket; no rootfs bind mount is needed on the auditor side.
cinc_run_docker_transport() {
    local inspec_json_basename
    inspec_json_basename="$(basename "${OUTPUT_JSON}")"

    echo "Running Cinc Auditor (docker:// transport)..."
    set +e
    local auditor_args=(
        --rm
        --privileged
        --platform linux/amd64
        --user 0:0
        -v "${RESULTS_DIR}:/results:rw"
        -v /var/run/docker.sock:/var/run/docker.sock
    )

    # Mount only the profile's own files into /profile (not the repo root): cinc-
    # auditor / InSpec 7.x reads a directory profile as a control-less gem
    # resource pack if any *.gemspec exists anywhere under the profile path (e.g.
    # test/vendor/bundle). See docs/testing.md and inspec/inspec#7934.
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

    docker run "${auditor_args[@]}" \
        "${CINC_AUDITOR_IMAGE}" \
        exec "${PROFILE_PATH}" \
          --no-create-lockfile \
          --reporter cli \
          --reporter "json:/results/${inspec_json_basename}" \
          -t "docker://${CONTAINER_ID}" \
          --user root
    INSPEC_EXIT_CODE=$?
    set -e
}

cinc_run_docker_transport
cinc_check_exit_code
cinc_check_json_output
cinc_generate_html_report
cinc_print_scan_complete
