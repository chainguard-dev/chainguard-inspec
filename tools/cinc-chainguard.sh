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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/cinc-common.sh
source "${SCRIPT_DIR}/lib/cinc-common.sh"

USE_TMPFS=true
TMPFS_BASE=""
ROOTFS_DIR=""
PROJECT_TMP_DIR="${SCRIPT_DIR}/.tmp"

cleanup() {
    set +e
    if [ -n "${ROOTFS_DIR}" ] && [ -d "${ROOTFS_DIR}" ]; then
        echo "Removing temporary rootfs directory..."
        rm -rf "${ROOTFS_DIR}"
    fi
    if [ -n "${PROJECT_TMP_DIR:-}" ] && [ -d "${PROJECT_TMP_DIR}" ]; then
        echo "Removing project temporary directory..."
        rm -rf "${PROJECT_TMP_DIR}"
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

if ! cinc_parse_positional_args "$@"; then
    usage
    exit 1
fi

cinc_check_docker
cinc_check_ruby
cinc_setup_profile_paths
cinc_setup_output_paths "stig"
cinc_print_scan_header "Filesystem reconstruction"
cinc_pull_image
cinc_get_image_digest

# Determine extraction base (tmpfs optional)
TEMP_ROOT_BASE="${PROJECT_TMP_DIR}"

if $USE_TMPFS; then
    TMPFS_CANDIDATE="${TMPFS_BASE:-/dev/shm}"
    if [ -d "${TMPFS_CANDIDATE}" ] && [ -w "${TMPFS_CANDIDATE}" ]; then
        TEMP_ROOT_BASE="${TMPFS_CANDIDATE}"
        echo "Using tmpfs base directory: ${TEMP_ROOT_BASE}"
    else
        echo "Warning: requested tmpfs base '${TMPFS_CANDIDATE}' unavailable; using disk under ${TEMP_ROOT_BASE}" >&2
    fi
fi

mkdir -p "${TEMP_ROOT_BASE}"
ROOTFS_DIR=$(mktemp -d "${TEMP_ROOT_BASE}/chainguard-rootfs-XXXXXX")
export ROOTFS_DIR
echo "Temporary rootfs directory: ${ROOTFS_DIR}"

cinc_capture_aslr

CONTAINER_ID="$(docker create "${IMAGE}")"
echo "Exporting filesystem from container ${CONTAINER_ID}..."
docker export "${CONTAINER_ID}" | tar -C "${ROOTFS_DIR}" -xf - --no-same-owner --exclude='dev/*'
docker rm "${CONTAINER_ID}" >/dev/null

# Inject captured runtime data into extracted filesystem
mkdir -p "${ROOTFS_DIR}/.runtime_capture"
echo "${ASLR_VALUE}" > "${ROOTFS_DIR}/.runtime_capture/aslr_setting"
chmod 644 "${ROOTFS_DIR}/.runtime_capture/aslr_setting"

# Ensure common symlink targets exist for tools that expect terminfo directories
mkdir -p "${ROOTFS_DIR}/usr/share/terminfo"
echo "Ensured terminfo directory exists under rootfs"

# Normalize permissions on sensitive files for scanning
echo "Normalizing permissions on sensitive files"
if [ -f "${ROOTFS_DIR}/etc/shadow" ]; then
    chmod 600 "${ROOTFS_DIR}/etc/shadow"
fi
if [ -f "${ROOTFS_DIR}/etc/passwd" ]; then
    chmod 644 "${ROOTFS_DIR}/etc/passwd"
fi

if [ ! -d "${ROOTFS_DIR}/etc" ]; then
    echo "Error: failed to reconstruct filesystem" >&2
    exit 1
fi

ROOTFS_MOUNT="${ROOTFS_DIR}"
cinc_run_auditor
cinc_check_exit_code
cinc_check_json_output
cinc_generate_html_report
cinc_print_scan_complete
