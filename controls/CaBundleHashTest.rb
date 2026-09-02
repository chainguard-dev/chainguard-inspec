# Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates
# Copyright (c) 2026 Chainguard
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

control 'oval:org.CABundleHash:def:1' do
  impact 0.5
  title 'Validate SHA-256 hash of CA bundle'
  desc 'Ensure the CA bundle exists and its SHA-256 matches the digest recorded in the sidecar apko writes beside it at build time, or an explicitly supplied expected hash.'

  # STIG rule mappings

  tag stig_rules: [
    'SV-263659r982563_rule'
  ]

  tag stig_severities: ['medium']

  tag ccis: ['CCI-004909']

  # Exactly one 64-hex digest recorded for ca-certificates.crt. sha256sum's
  # binary mode writes the filename with a leading '*', which the OVAL pattern
  # (oval:org.CABundleHash:obj:4) allows, so we allow it too.
  stamp_line = /^([0-9a-fA-F]{64})[ \t]+\*?ca-certificates\.crt$/

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  certs_dir = File.join(rootfs, 'etc/ssl/certs')
  bundle_path = File.join(certs_dir, 'ca-certificates.crt')
  # Derived from certs_dir, not re-joined from rootfs, so the stamp can never
  # drift to a different directory than the bundle it describes.
  stamp_path = File.join(certs_dir, '.ca-certificates.crt.sha256')

  # An input declared `value: ''` resolves to "", but one declared with no
  # value at all resolves to an Inspec::Input::NO_VALUE_SET sentinel that is
  # truthy and stringifies to a non-empty inspect string. Testing for a
  # non-empty String is correct for both, and for nil.
  override = input('expected_cacert_hash')
  override = nil unless override.is_a?(String) && !override.strip.empty?
  override = override&.strip&.downcase

  stamp_file = file(stamp_path)
  # The stamp only detects drift, not tampering: whoever can rewrite the
  # bundle can rewrite the stamp beside it too. What this catches is a bundle
  # modified after the image was built (e.g. a downstream build step that
  # edits the bundle without re-running update-ca-certificates), not an
  # adversary who already controls the filesystem.
  #
  # Downcased so the comparison is case-insensitive, matching OVAL ste:1's
  # operation="case insensitive equals".
  #
  # .scrub before matching: the sidecar is adversary-influenceable in exactly
  # the tampering scenario this control targets, and non-UTF8 bytes in it
  # would otherwise raise ArgumentError here, at control-body scope — turning
  # the whole control into a code error and losing the stamp finding, the
  # bundle-existence evidence, and the hash comparison, unrescued by an
  # override. A clean finding is a strictly better outcome than that.
  stamp_digests = stamp_file.content.to_s.scrub.lines.filter_map { |l| l[stamp_line, 1] }.map(&:downcase)

  expected_hash = override || (stamp_digests.length == 1 ? stamp_digests.first : nil)

  # Where the expected digest came from, so a reviewer reading the report can
  # tell an override apart from a stamp read. Mirrors AslrCheck's origin block.
  # Guarded on expected_hash so this is pure evidence: when the stamp block
  # below is the one that's failing, this block would otherwise also fail,
  # attributing a resolution that never happened to the sidecar reading path
  # — two findings for one cause, one of them false.
  if expected_hash
    describe 'Expected CA bundle digest origin' do
      it "resolved from #{override ? 'the expected_cacert_hash input' : "the sidecar #{stamp_path}"}" do
        expect(expected_hash).not_to be_nil
      end
    end
  end

  # An override is trusted, but the report should still say whether the
  # sidecar apko wrote backs it up. Always passes when an override is set —
  # the state lives in the example's description, the way NoUsersCheck
  # reports each account's status. "Contradicted" is the expected shape for a
  # bundle changed by a derived build layer after the image was built, which
  # is the override's whole purpose.
  if override
    # Neutral factual wording, deliberately without "corroborated" /
    # "NOT corroborated" polarity: this block always passes (see below), so a
    # reader skimming statuses sees green regardless of which branch fired,
    # and text that says "NOT corroborated" next to a PASS reads as
    # contradictory. Stating what the stamp records lets the reader judge
    # significance themselves.
    corroboration =
      if stamp_digests.length == 1 && stamp_digests.first == override
        "override in effect; #{stamp_path} records the same digest"
      elsif stamp_digests.length == 1
        "override in effect; #{stamp_path} records a different digest " \
          "(#{stamp_digests.first}), expected for a bundle changed after " \
          'the image was built'
      elsif !stamp_file.exist?
        "override in effect; no sidecar at #{stamp_path} to corroborate it"
      else
        "override in effect; #{stamp_path} records #{stamp_digests.length} " \
          'digest lines, so it cannot corroborate'
      end

    describe 'Supplied expected_cacert_hash corroboration' do
      it corroboration do
        expect(override).not_to be_nil
      end
    end
  end

  # Without an override the stamp is mandatory: an image that simply omits it
  # would otherwise have nothing to compare against and pass by default.
  #
  # Requiring exactly one digest line is stricter than the datastream, not a
  # mirror of it: obj:4 carries <ind:instance datatype="int">1</ind:instance>,
  # which restricts collection to the first matching line, so tst:4's
  # check_existence="only_one_exists" degenerates to "at least one line
  # exists, and the first one is used" — it can never fail on a duplicate.
  # Confirmed against oscap: a standalone OVAL replicating obj:4/tst:4 returns
  # true for a stamp with two matching lines, where this control fails.
  # That's a deliberate divergence, chosen because failing closed is safer and
  # no real build path emits duplicate stamp lines. Do not "fix" this to
  # match only_one_exists literally when syncing a future datastream release —
  # that would reintroduce silently trusting the first of several lines.
  unless override
    describe "CA bundle checksum stamp file #{stamp_path}" do
      it 'records exactly one SHA-256 digest for ca-certificates.crt' do
        detail =
          if !stamp_file.exist?
            'file does not exist'
          elsif stamp_file.content.nil?
            # Path exists but file() couldn't read it — a directory, or
            # unreadable by this auditor — not a format problem, so don't
            # send the operator hunting for a malformed digest line.
            stamp_file.file? ? 'exists but is not readable' : 'exists but is not a regular file'
          elsif stamp_digests.empty?
            "no line matching #{stamp_line.source}"
          else
            "#{stamp_digests.length} digest lines: #{stamp_digests.inspect}"
          end
        expect(stamp_digests.length).to eq(1),
          "expected exactly one recorded digest for ca-certificates.crt in #{stamp_path}, " \
          "but #{detail}. Set the expected_cacert_hash input to override the stamp."
      end
    end
  end

  bundle_file = file(bundle_path)

  describe bundle_file do
    it { should exist }
    it { should be_file }
  end

  # Guarded so an unresolvable expected hash surfaces as the stamp finding
  # above rather than as a confusing "expected nil" comparison here.
  if expected_hash
    describe bundle_file do
      its('sha256sum') { should eq expected_hash }
    end
  end
end
