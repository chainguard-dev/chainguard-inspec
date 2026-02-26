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

# Live overlay filesystem scan using Cinc Auditor
#
# Accesses the container's overlay2 merged directory directly via
# docker inspect GraphDriver.Data.MergedDir, avoiding full filesystem
# extraction.  Much faster than the export/tar approach for large images.
#
# Requirements:
#   - Linux host (overlay2 paths live inside a VM on macOS/Windows Docker Desktop)
#   - Docker daemon using the overlay2 storage driver
#   - Root or equivalent privileges to read paths under /var/lib/docker/overlay2/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/cinc-common.sh
source "${SCRIPT_DIR}/lib/cinc-common.sh"

CONTAINER_ID=""
START_CONTAINER=false
ASLR_CAPTURE_DIR=""

cleanup() {
    set +e
    if [ -n "${CONTAINER_ID}" ]; then
        if $START_CONTAINER; then
            docker stop "${CONTAINER_ID}" >/dev/null 2>&1 || true
        fi
        echo "Removing target container..."
        docker rm "${CONTAINER_ID}" >/dev/null 2>&1 || true
    fi
    if [ -n "${ASLR_CAPTURE_DIR}" ] && [ -d "${ASLR_CAPTURE_DIR}" ]; then
        rm -rf "${ASLR_CAPTURE_DIR}"
    fi
}

trap cleanup EXIT

usage() {
    cat <<'USAGE'
Usage: cinc-chainguard-overlay.sh [--start-container] [--use-local-profile] <image> [label] [results-dir]

Arguments:
  --start-container    Start the container before inspecting its overlay filesystem.
                       Use this if the overlay is not mounted after docker create alone
                       on your Docker configuration.
  --use-local-profile  Mount local profile and run reports with host Ruby (developer mode)
  image            Container image to scan (required)
  label            Environment label (default: dev)
  results-dir      Directory to write JSON/HTML outputs (default: ./results)

Note: Requires a Linux host with Docker using the overlay2 storage driver.
      The merged overlay path (/var/lib/docker/overlay2/.../merged) is only
      readable by root.

      Does NOT work with Docker Desktop on macOS or Windows: the overlay2
      filesystem resides inside the Docker Desktop Linux VM and is not
      accessible as a host path.  Use cinc-chainguard.sh (filesystem
      extraction) on those platforms instead.

Example:
  ./cinc-chainguard-overlay.sh cgr.dev/chainguard/nginx:latest dev
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --start-container)
            START_CONTAINER=true
            shift
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

if ! cinc_parse_positional_args "$@"; then
    usage
    exit 1
fi

# Overlay2 merged dirs live inside the Docker Desktop VM on macOS/Windows.
if [ "$(uname -s)" != "Linux" ]; then
    echo "Error: overlay scan requires a Linux host." >&2
    echo "       On macOS/Windows use cinc-chainguard.sh (filesystem extraction) instead." >&2
    exit 1
fi

cinc_check_docker
cinc_check_ruby
cinc_setup_profile_paths
cinc_setup_output_paths "stig"
cinc_print_scan_header "Live overlay"
cinc_pull_image
cinc_get_image_digest
cinc_capture_aslr

echo "Creating container from image..."
CONTAINER_ID="$(docker create "${IMAGE}")"

if $START_CONTAINER; then
    echo "Starting container ${CONTAINER_ID}..."
    # Images without a persistent entrypoint will exit immediately; that is fine —
    # the overlay remains mounted until docker rm.
    docker start "${CONTAINER_ID}" >/dev/null 2>&1 || true
fi

# Verify the storage driver before trying to read MergedDir.
STORAGE_DRIVER="$(docker inspect "${CONTAINER_ID}" \
    --format '{{.GraphDriver.Name}}')"
if [ "${STORAGE_DRIVER}" != "overlay2" ]; then
    echo "Error: expected overlay2 storage driver, got '${STORAGE_DRIVER}'." >&2
    echo "       This script requires Docker to use the overlay2 storage driver." >&2
    exit 1
fi

MERGED_DIR="$(docker inspect "${CONTAINER_ID}" \
    --format '{{.GraphDriver.Data.MergedDir}}')"

if [ -z "${MERGED_DIR}" ]; then
    echo "Error: MergedDir is empty for container ${CONTAINER_ID}." >&2
    exit 1
fi

if [ ! -d "${MERGED_DIR}/etc" ]; then
    echo "Error: overlay filesystem at ${MERGED_DIR} does not look like a valid rootfs." >&2
    echo "       Try --start-container to ensure the overlay is mounted before inspection." >&2
    exit 1
fi

echo "Container overlay filesystem: ${MERGED_DIR}"

# ASLR is a host kernel setting — it cannot be read from the image filesystem.
# Write the captured value into a temporary directory and mount it into the
# cinc-auditor container at /rootfs/.runtime_capture so the controls can read
# it, without touching the overlay's writable upper layer.
ASLR_CAPTURE_DIR="$(mktemp -d)"
echo "${ASLR_VALUE}" > "${ASLR_CAPTURE_DIR}/aslr_setting"
chmod 644 "${ASLR_CAPTURE_DIR}/aslr_setting"
EXTRA_AUDITOR_ARGS+=(-v "${ASLR_CAPTURE_DIR}:/rootfs/.runtime_capture:ro")

ROOTFS_MOUNT="${MERGED_DIR}"
cinc_run_auditor
cinc_check_exit_code
cinc_check_json_output
cinc_generate_html_report
cinc_print_scan_complete
