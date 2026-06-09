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

# Live container scan using Cinc Auditor via --pid=host and /proc/<PID>/root
#
# Starts the target container and runs cinc-auditor with --pid=host, passing
# /proc/<PID>/root as the rootfs input.  All filesystem access happens inside
# the cinc-auditor container, so this approach needs no host-side overlay2 path
# (unlike cinc-chainguard-overlay.sh).  Supported on Linux and macOS; Windows
# (Docker Desktop) is untested.
#
# The AslrCheck control resolves ASLR via ${rootfs}/proc/sys/kernel/randomize_va_space,
# which is accessible through the target container's mounted /proc, so no
# separate ASLR capture or injection is required.
#
# Note: this script starts the container's actual workload.  Do not use with
# images that have undesirable side-effects when run; use cinc-chainguard.sh
# (filesystem extraction) for those instead.
#
# The target must stay running for the whole scan: its filesystem is read live
# through /proc/<PID>/root.  A workload that exits (e.g. a service that needs
# config/a backend to stay up) makes /proc/<PID>/root vanish and every control
# then finds nothing, so the script verifies the container is still running
# after a brief startup settle and again after the scan, aborting with an
# actionable error rather than reporting empty results.  Use one of the other
# approaches for images that are not self-sustaining.  See the README
# "Required privileges".
#
# Privileges: the auditor runs --privileged --pid=host as uid 0 in the
# container; under rootful Docker that is real host root (so a non-root invoker
# in the docker group works), under rootless Docker it requires real root to
# read another container's /proc/<PID>/root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/cinc-common.sh
source "${SCRIPT_DIR}/lib/cinc-common.sh"

CONTAINER_ID=""

cleanup() {
    set +e
    if [ -n "${CONTAINER_ID}" ]; then
        echo "Stopping and removing target container..."
        docker stop "${CONTAINER_ID}" >/dev/null 2>&1 || true
        docker rm "${CONTAINER_ID}" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

usage() {
    cat <<'USAGE'
Usage: cinc-chainguard-live.sh [--use-local-profile] <image> [label] [results-dir]

Arguments:
  --use-local-profile  Mount local profile and run reports with host Ruby (developer mode)
  image            Container image to scan (required)
  label            Environment label (default: dev)
  results-dir      Directory to write JSON/HTML outputs (default: ./results)

Note: This script starts the container's actual workload.  Do not use with
      images that have undesirable side-effects when run; use
      cinc-chainguard.sh (filesystem extraction) for those instead.

      Supported on Linux and macOS (Windows/Docker Desktop untested): all
      filesystem access happens inside the cinc-auditor container, so no
      host-side overlay2 path is required.

      For private Chainguard images, run 'chainctl auth configure-docker'
      before invoking this script.

Example:
  ./cinc-chainguard-live.sh cgr.dev/chainguard/nginx:latest dev
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
cinc_print_scan_header "Live container"
cinc_pull_image
cinc_get_image_digest

echo "Starting target container..."
CONTAINER_ID="$(docker run -d "${IMAGE}")"

TARGET_PID="$(docker inspect "${CONTAINER_ID}" --format '{{.State.Pid}}')"

if [ "${TARGET_PID:-0}" -eq 0 ]; then
    echo "Error: container ${CONTAINER_ID} exited before it could be inspected." >&2
    echo "       The live scan requires the container to remain running." >&2
    echo "       For distroless or short-lived images use cinc-chainguard.sh instead." >&2
    exit 1
fi

echo "Target container PID: ${TARGET_PID}"

# Guidance shown if the target is not running at either checkpoint below.
TARGET_RUNNING_HINT="Use one of the other approaches (cinc-chainguard.sh / overlay / docker-transport) for short-lived or non-self-sustaining images."

# Give the workload a moment to settle, then confirm it is still up before
# spending a full scan on a target that was never going to stay alive (e.g. a
# service that needs config or a backend).  Override the settle with
# CINC_LIVE_SETTLE_SECONDS (0 disables the wait).
sleep "${CINC_LIVE_SETTLE_SECONDS:-3}"
cinc_require_target_running "${CONTAINER_ID}" "after startup" "${TARGET_RUNNING_HINT}" || exit 1

EXTRA_AUDITOR_ARGS+=(--pid=host)
ROOTFS_MOUNT=""
ROOTFS_CONTAINER_PATH="/proc/${TARGET_PID}/root"

cinc_run_auditor
# If the workload exited during the scan, /proc/<PID>/root vanished and the
# results are unreliable; fail clearly instead of reporting empty findings.
cinc_require_target_running "${CONTAINER_ID}" "after the scan" "${TARGET_RUNNING_HINT}" || exit 1
cinc_check_exit_code
cinc_check_json_output
cinc_generate_html_report
cinc_print_scan_complete
