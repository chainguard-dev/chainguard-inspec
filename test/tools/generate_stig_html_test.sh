#!/usr/bin/env bash
#
# Copyright (c) 2026 Chainguard
# SPDX-License-Identifier: Apache-2.0
#
# Regression test for tools/generate_stig_html.rb UTF-8 handling.
#
# The cinc-auditor JSON report routinely contains non-ASCII characters (a
# control's source comments, STIG descriptions: em-dashes, smart quotes,
# arrows). The generator reads that report and writes an HTML document that
# declares <meta charset="UTF-8">. Under a minimal container's default
# C/POSIX locale, Ruby's Encoding.default_external is US-ASCII, so without
# explicit UTF-8 handling File.read + JSON.parse raises
# Encoding::InvalidByteSequenceError (and File.write would mis-transcode on a
# Latin-1 locale).
#
# This test forces that locale (LC_ALL=C) and feeds a report containing
# non-ASCII bytes, asserting the generator succeeds and the characters round
# -trip into the HTML. It also passes a non-ASCII --container-label to cover
# the option-string normalization.
#
# NOTE: the failure only reproduces with a json gem strict enough to raise on
# invalid byte sequences (the gem bundled with ruby 3.4 / wolfi's json 2.19.x
# does; very old json gems silently coerce). Keep the LC_ALL=C below: dropping
# it, or running under a UTF-8 locale, hides the regression.
#
# Run directly:  test/tools/generate_stig_html_test.sh

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../.." && pwd)"
GENERATOR="${REPO_ROOT}/tools/generate_stig_html.rb"

fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

if ! command -v ruby >/dev/null 2>&1; then
    echo "SKIP: ruby not available"
    exit 0
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

fixture="${workdir}/report.json"
output="${workdir}/report.html"

# A minimal-but-valid inspec/cinc JSON report whose strings carry the same
# kinds of non-ASCII bytes a real report does: an em-dash, smart quotes, and
# an arrow.
cat > "${fixture}" <<'JSON'
{
  "profiles": [
    {
      "name": "utf8-regression",
      "title": "Fixture — “smart quotes” and an arrow →",
      "controls": [
        {
          "id": "utf8-1",
          "title": "Control with non-ASCII — like the report that broke this",
          "desc": "reliably evaluate account correctness — a crafted short line",
          "impact": 0.5,
          "results": [
            { "status": "passed", "code_desc": "File /etc/passwd is expected to exist" }
          ]
        }
      ]
    }
  ]
}
JSON

# Sanity: this regression only manifests with a json gem strict enough to
# raise on invalid byte sequences under a US-ASCII default_external. If the
# active gem silently coerces (very old json), the assertions below can't tell
# a fixed generator from an unfixed one -- warn loudly rather than report a
# misleading pass.
if LC_ALL=C ruby -e 'require "json"; JSON.parse(File.read(ARGV[0]))' "${fixture}" >/dev/null 2>&1; then
    echo "WARN: json $(ruby -e 'require "json"; print JSON::VERSION') does not raise on" \
         "non-UTF-8 input under US-ASCII; this environment cannot exercise the regression."
fi

# Force the C/POSIX locale so default_external is US-ASCII -- the condition
# under which the unfixed generator crashed. Pass a non-ASCII container label
# too, to exercise option-string normalization.
LC_ALL=C LANG=C ruby "${GENERATOR}" "${fixture}" "${output}" \
    --container-label 'Café-prod —' >/dev/null 2>"${workdir}/stderr"
rc=$?

if [ "${rc}" -ne 0 ]; then
    fail "generator exited ${rc} under LC_ALL=C (encoding regression?)"
    sed 's/^/    /' "${workdir}/stderr"
elif [ ! -s "${output}" ]; then
    fail "generator produced no/empty HTML output"
else
    pass "generator succeeded under LC_ALL=C and wrote HTML"

    # The non-ASCII report content must survive into the HTML (LC_ALL=C grep
    # so the match is byte-exact regardless of the host locale).
    if LC_ALL=C grep -q -- '—' "${output}"; then
        pass "non-ASCII report content (em-dash) round-tripped into HTML"
    else
        fail "em-dash from the report is missing/mangled in the HTML"
    fi

    if LC_ALL=C grep -q 'Café-prod' "${output}"; then
        pass "non-ASCII --container-label normalized into HTML"
    else
        fail "non-ASCII container label is missing/mangled in the HTML"
    fi
fi

if [ "${fails}" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
fi
echo "${fails} TEST(S) FAILED"
exit 1
