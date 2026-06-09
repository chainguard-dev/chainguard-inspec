#!/usr/bin/env bash
#
# Copyright (c) 2026 Chainguard
# SPDX-License-Identifier: Apache-2.0
#
# Tests for cinc_require_target_running() in tools/lib/cinc-common.sh.
#
# This is an integration test: it starts and stops real (tiny) containers and
# checks the helper's behaviour. Requires Docker and the public
# cgr.dev/chainguard/wolfi-base image (override with TEST_IMAGE).
# Run directly:  test/tools/cinc_require_target_running_test.sh

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../tools/lib/cinc-common.sh
source "${TEST_DIR}/../../tools/lib/cinc-common.sh"

TEST_IMAGE="${TEST_IMAGE:-cgr.dev/chainguard/wolfi-base:latest}"
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# --- a running container: helper succeeds silently --------------------------
cid="$(docker run -d --rm "${TEST_IMAGE}" sleep 300)"
out="$(cinc_require_target_running "${cid}" "after startup" "some hint" 2>&1)"
rc=$?
if [ "${rc}" -eq 0 ] && [ -z "${out}" ]; then
    pass "running container -> rc 0, silent"
else
    fail "running container should be rc 0 and silent (rc=${rc}, out='${out}')"
fi
docker rm -f "${cid}" >/dev/null 2>&1

# --- a stopped container: helper fails with phase + hint + logs -------------
cid="$(docker run -d "${TEST_IMAGE}" sh -c 'echo boom-marker >&2; exit 3')"
docker wait "${cid}" >/dev/null 2>&1   # block until it has exited
out="$(cinc_require_target_running "${cid}" "after the scan" "USE-ANOTHER-APPROACH" 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ] \
    && grep -q "after the scan" <<<"${out}" \
    && grep -q "USE-ANOTHER-APPROACH" <<<"${out}" \
    && grep -q "exit code=3" <<<"${out}" \
    && grep -q "boom-marker" <<<"${out}"; then
    pass "stopped container -> non-zero with phase, hint, exit code, and logs"
else
    fail "stopped container message incomplete (rc=${rc}, out='${out}')"
fi
docker rm -f "${cid}" >/dev/null 2>&1

if [ "${fails}" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
fi
echo "${fails} TEST(S) FAILED"
exit 1
