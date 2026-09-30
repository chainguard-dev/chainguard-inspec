#!/usr/bin/env bash
#
# Copyright (c) 2026 Chainguard
# SPDX-License-Identifier: Apache-2.0
#
# Tests for cinc_resolve_profile_versions() and cinc_warn_if_profile_stale()
# in tools/lib/cinc-common.sh.
#
# The warning exists because a stale auditor image silently evaluates stale
# controls: an image from before the CA-bundle sidecar work compared a
# months-old pinned digest against a current bundle and reported
# CaBundleHashTest failing on a compliant image. These cases pin that the
# warning fires when the versions differ and stays quiet when they agree.
#
# Mostly hermetic: the embedded-profile lookup is exercised against a real
# image built on the fly from the public wolfi-base (override with TEST_IMAGE),
# so the `--entrypoint cat` contract is tested against a real container rather
# than a stub. Requires Docker.
# Run directly:  test/tools/cinc_profile_staleness_test.sh

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../tools/lib/cinc-common.sh
source "${TEST_DIR}/../../tools/lib/cinc-common.sh"

TEST_IMAGE="${TEST_IMAGE:-cgr.dev/chainguard/wolfi-base:latest}"
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

work="$(mktemp -d)"
trap 'rm -rf "${work}"; docker rmi -f cinc-staleness-test:embedded >/dev/null 2>&1' EXIT

# A checkout whose inspec.yml records 9.9.9. The `version:` key is deliberately
# not the first line, and an indented `version:` is present, so the parser is
# shown to anchor at column 0 rather than grabbing the first match.
mkdir -p "${work}/checkout"
cat > "${work}/checkout/inspec.yml" <<'YAML'
name: test_profile
inputs:
  - name: x
    version: 1.2.3
version: 9.9.9
supports:
  - platform: linux
YAML

# An "auditor image" carrying an embedded profile recording 0.0.4.
mkdir -p "${work}/img"
printf 'name: embedded\nversion: 0.0.4\n' > "${work}/img/inspec.yml"
cat > "${work}/img/Dockerfile" <<DOCKER
FROM ${TEST_IMAGE}
COPY inspec.yml /usr/share/chainguard-inspec/inspec.yml
DOCKER
if ! docker build -q -t cinc-staleness-test:embedded "${work}/img" >/dev/null 2>&1; then
    echo "SKIP: could not build the test image (no Docker or no ${TEST_IMAGE})"
    exit 0
fi

PROFILE_DIR="${work}/checkout"
PROFILE_SOURCE="embedded"
CINC_AUDITOR_IMAGE="cinc-staleness-test:embedded"

# --- embedded lookup reads the image, not the checkout ----------------------
USE_EMBEDDED_PROFILE=true
cinc_resolve_profile_versions
if [ "${PROFILE_VERSION}" = "0.0.4" ] && [ "${CHECKOUT_PROFILE_VERSION}" = "9.9.9" ]; then
    pass "embedded mode reads the image (0.0.4) and the checkout (9.9.9)"
else
    fail "embedded mode: got embedded='${PROFILE_VERSION}' checkout='${CHECKOUT_PROFILE_VERSION}'" \
         "(expected 0.0.4 / 9.9.9)"
fi

# --- mismatch warns, names both versions and both remedies ------------------
out="$(cinc_warn_if_profile_stale 2>&1)"
if grep -q 'does not match this checkout' <<<"${out}" \
    && grep -q '0\.0\.4' <<<"${out}" \
    && grep -q '9\.9\.9' <<<"${out}" \
    && grep -q 'docker pull' <<<"${out}" \
    && grep -q -- '--use-local-profile' <<<"${out}"; then
    pass "version mismatch -> warns with both versions and both remedies"
else
    fail "mismatch warning incomplete: '${out}'"
fi

# --- a digest-pinned image gets advice that can actually work ---------------
# `docker pull <repo>@sha256:...` returns the same bytes, so suggesting it
# would be advice that cannot work.
saved_image="${CINC_AUDITOR_IMAGE}"
CINC_AUDITOR_IMAGE="cgr.dev/chainguard/cinc-auditor@sha256:c3d1d71520f8590954f8dbc07524ffb1eb00cfce00d468eceb5519470fe912b0"
out="$(cinc_warn_if_profile_stale 2>&1)"
if ! grep -q 'docker pull' <<<"${out}" \
    && grep -q 'pinned to a digest' <<<"${out}" \
    && grep -q -- '--use-local-profile' <<<"${out}"; then
    pass "digest-pinned image -> no futile 'docker pull <digest>' suggestion"
else
    fail "digest-pinned image should not suggest pulling the digest: '${out}'"
fi
CINC_AUDITOR_IMAGE="${saved_image}"

# --- a tag-referenced image does suggest the pull ---------------------------
out="$(cinc_warn_if_profile_stale 2>&1)"
if grep -q "docker pull ${CINC_AUDITOR_IMAGE}" <<<"${out}"; then
    pass "tag-referenced image -> suggests docker pull"
else
    fail "tag-referenced image should suggest the pull: '${out}'"
fi

# --- the warning goes to stderr, so it survives a piped stdout --------------
if [ -z "$(cinc_warn_if_profile_stale 2>/dev/null)" ] \
    && [ -n "$(cinc_warn_if_profile_stale 2>&1 >/dev/null)" ]; then
    pass "warning is written to stderr, not stdout"
else
    fail "warning should go to stderr only"
fi

# --- matching versions stay silent ------------------------------------------
CHECKOUT_PROFILE_VERSION="0.0.4"
out="$(cinc_warn_if_profile_stale 2>&1)"
if [ -z "${out}" ]; then
    pass "matching versions -> silent"
else
    fail "matching versions should be silent, got: '${out}'"
fi

# --- an unknown version stays silent rather than warning on nothing ---------
CHECKOUT_PROFILE_VERSION="unknown"
PROFILE_VERSION="0.0.4"
out="$(cinc_warn_if_profile_stale 2>&1)"
CHECKOUT_PROFILE_VERSION="9.9.9"
PROFILE_VERSION="unknown"
out2="$(cinc_warn_if_profile_stale 2>&1)"
if [ -z "${out}" ] && [ -z "${out2}" ]; then
    pass "an unknown version on either side -> silent"
else
    fail "unknown versions should not warn (got '${out}' / '${out2}')"
fi

# --- local-profile mode: no comparison to make, and no probe ----------------
USE_EMBEDDED_PROFILE=false
CINC_AUDITOR_IMAGE="cinc-staleness-test:does-not-exist"
cinc_resolve_profile_versions
out="$(cinc_warn_if_profile_stale 2>&1)"
if [ "${PROFILE_VERSION}" = "9.9.9" ] && [ -z "${out}" ]; then
    pass "local-profile mode reports the checkout version and never warns"
else
    fail "local mode: got version='${PROFILE_VERSION}' warning='${out}' (expected 9.9.9 / silent)"
fi

# --- the parser: only a real version gets through --------------------------
# Every rejected shape below would otherwise be printed in the scan header as
# the profile's version and compared against the other side, producing a
# spurious staleness warning. The check's failure mode must be silence.
while IFS='|' read -r want desc input; do
    [ -n "${desc}" ] || continue
    got="$(printf '%b' "${input}" | cinc_parse_profile_version)"
    if [ "${got}" = "${want}" ]; then
        pass "parser: ${desc}"
    else
        fail "parser: ${desc} -> want '${want}', got '${got}'"
    fi
done <<'CASES'
1.1.0|a bare version|version: 1.1.0
1.1.0|a trailing comment after the value|version: 1.1.0 # released
1.1.0|a tab after the colon|version:\t1.1.0
1.1.0|CRLF line endings|version: 1.1.0
1.1.0|duplicate keys take the last, as YAML does|version: 0.0.4\nversion: 1.1.0
1.1.0|an indented version: is ignored|inputs:\n  - name: x\n    version: 9.9.9\nversion: 1.1.0
|a double-quoted value is not a bare version|version: "1.1.0"
|a single-quoted value is not a bare version|version: '1.1.0'
|a comment where the value should be|version: # not set yet
|a block scalar indicator|version: |
|an empty value|version:
|a commented-out key|# version: 1.1.0
|a different key that starts the same|versions: 1.1.0
|no version key at all|name: profile
CASES

# --- PRODUCTION SHELL MODE -------------------------------------------------
# The scan scripts all run `set -euo pipefail`; this harness cannot, because it
# deliberately calls functions and inspects $?. So the cases that matter under
# errexit are run in a `bash -euo pipefail -c` subshell instead.
#
# This is not ceremony. The first version of this feature aborted every scan
# with ZERO output whenever the auditor image had no readable embedded profile,
# and the in-process case below still returned 0 and passed, because `-e` was
# off here but on in production. A test that runs in a different shell mode
# than the code it guards cannot see that whole class of bug.
run_under_errexit() {
    # $1 = CINC_AUDITOR_IMAGE, $2 = USE_EMBEDDED_PROFILE
    # The library refuses to run as $0, so it is passed as $1 and arg0 is a
    # throwaway. The subshell is the whole point: `-e` is on here, as it is in
    # every scan script, and off in this harness.
    bash -euo pipefail -c '
        source "$1"
        CINC_AUDITOR_IMAGE="$2"
        USE_EMBEDDED_PROFILE="$3"
        PROFILE_DIR="$4"
        cinc_resolve_profile_versions
        echo "REACHED-END ${PROFILE_VERSION}"
    ' bash "${TEST_DIR}/../../tools/lib/cinc-common.sh" "$1" "$2" "${work}/checkout" 2>&1
}

for case_spec in \
    "cinc-staleness-test:embedded|true|0.0.4|a good embedded profile" \
    "${TEST_IMAGE}|true|unknown|an image with no embedded profile" \
    "cinc-staleness-test-nope:absent|true|unknown|an unpullable image" \
    "cinc-staleness-test-nope:absent|false|9.9.9|local mode, image irrelevant"
do
    IFS='|' read -r img mode want_ver desc <<<"${case_spec}"
    out="$(run_under_errexit "${img}" "${mode}")"
    rc=$?
    if [ "${rc}" -eq 0 ] && grep -q "REACHED-END ${want_ver}" <<<"${out}"; then
        pass "under set -euo pipefail: ${desc} -> continues, version ${want_ver}"
    else
        fail "under set -euo pipefail: ${desc} should continue with ${want_ver}" \
             "(rc=${rc}, output='${out}')"
    fi
done

# --- an unreadable checkout inspec.yml must not abort either ---------------
# Same failure family as the docker probe, on the other side: sed exits
# non-zero on a file it cannot read, and the assignment would abort the scan.
# This one fires in --use-local-profile mode too, where there is no container
# involved at all.
if [ "$(id -u)" -eq 0 ]; then
    echo "SKIP: unreadable-file case is meaningless as root"
else
    mkdir -p "${work}/unreadable"
    cp "${work}/checkout/inspec.yml" "${work}/unreadable/inspec.yml"
    chmod 000 "${work}/unreadable/inspec.yml"
    out="$(bash -euo pipefail -c '
        source "$1"
        USE_EMBEDDED_PROFILE=false
        PROFILE_DIR="$2"
        CINC_AUDITOR_IMAGE="unused"
        cinc_resolve_profile_versions
        echo "REACHED-END ${PROFILE_VERSION}"
    ' bash "${TEST_DIR}/../../tools/lib/cinc-common.sh" "${work}/unreadable" 2>&1)"
    rc=$?
    chmod 644 "${work}/unreadable/inspec.yml"
    if [ "${rc}" -eq 0 ] && grep -q 'REACHED-END unknown' <<<"${out}"; then
        pass "an unreadable checkout inspec.yml -> unknown, scan continues"
    else
        fail "unreadable checkout inspec.yml should degrade to unknown (rc=${rc}, out='${out}')"
    fi
fi

# --- a directory where inspec.yml should be --------------------------------
# `[ -r dir ]` is TRUE for a directory, so the readability test does not catch
# this; what keeps the scan alive is that cinc_parse_profile_version is total.
# Worth pinning because sed's own status is not dependable here: reading a
# directory exits 4 under GNU sed and 0 under busybox, and these scripts run
# against both.
mkdir -p "${work}/dirpath/inspec.yml"
out="$(bash -euo pipefail -c '
    source "$1"
    USE_EMBEDDED_PROFILE=false
    PROFILE_DIR="$2"
    CINC_AUDITOR_IMAGE="unused"
    cinc_resolve_profile_versions
    echo "REACHED-END ${PROFILE_VERSION}"
' bash "${TEST_DIR}/../../tools/lib/cinc-common.sh" "${work}/dirpath" 2>&1)"
rc=$?
if [ "${rc}" -eq 0 ] && grep -q 'REACHED-END unknown' <<<"${out}"; then
    pass "a directory at the inspec.yml path -> unknown, scan continues"
else
    fail "a directory at the inspec.yml path should degrade to unknown (rc=${rc}, out='${out}')"
fi

# --- the real scan script still reports its own error, not silence ----------
# The regression this guards made `tools/cinc-chainguard.sh` exit 125 with no
# output at all when the auditor image was unpullable.
scan_out="$(CINC_AUDITOR_IMAGE="cinc-staleness-test-nope:absent" \
    timeout 120 "${TEST_DIR}/../../tools/cinc-chainguard.sh" \
    "${TEST_IMAGE}" staleness-probe 2>&1)"
if grep -q 'Chainguard GPOS STIG Compliance Scan' <<<"${scan_out}"; then
    pass "a broken auditor image still produces the scan header, not silence"
else
    fail "scan produced no header with a broken auditor image (output='${scan_out}')"
fi

# --- a missing embedded profile degrades to unknown, does not fail ----------
# NOTE: this runs without -e, so it pins the return value only. The errexit
# behaviour is covered by the production-shell-mode block above.
USE_EMBEDDED_PROFILE=true
CINC_AUDITOR_IMAGE="${TEST_IMAGE}"   # no /usr/share/chainguard-inspec
cinc_resolve_profile_versions
rc=$?
if [ "${rc}" -eq 0 ] && [ "${PROFILE_VERSION}" = "unknown" ]; then
    pass "image without an embedded profile -> unknown, rc 0"
else
    fail "missing embedded profile should be non-fatal and unknown (rc=${rc}, v='${PROFILE_VERSION}')"
fi

if [ "${fails}" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
fi
echo "${fails} test(s) FAILED"
exit 1
