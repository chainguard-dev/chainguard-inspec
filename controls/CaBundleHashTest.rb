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

  # See SidecarDigest for why this is drift detection, not tamper evidence.
  # The scenario that motivates it here specifically is a downstream build
  # step that edits the bundle without re-running update-ca-certificates,
  # regenerating the bundle but leaving the stamp stale.
  stamp_result = SidecarDigest.resolve(self, stamp_path, 'ca-certificates.crt')

  expected_hash = override || stamp_result.digest

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
      if stamp_result.digest == override
        "override in effect; #{stamp_path} records the same digest"
      elsif stamp_result.resolved?
        "override in effect; #{stamp_path} records a different digest " \
          "(#{stamp_result.digest}), expected for a bundle changed after " \
          'the image was built'
      elsif stamp_result.detail.include?('does not exist')
        "override in effect; no sidecar at #{stamp_path} to corroborate it"
      else
        "override in effect; #{stamp_result.detail}, so it cannot corroborate"
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
        # stamp_result.detail already names stamp_path (SidecarDigest's
        # detail strings are always self-contained), so this template does
        # not repeat it.
        expect(stamp_result).to be_resolved,
          'expected exactly one recorded digest for ca-certificates.crt, ' \
          "but #{stamp_result.detail}. Set the expected_cacert_hash input to override the stamp."
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

  # --- Java truststore (OVAL tst:5 / tst:6 / tst:7, stigs e0faacb) ---
  #
  # Java images ship a JKS/PKCS12 truststore beside the PEM bundle, with its own
  # apko sidecar. tst:5 is check_existence="none_exist", so an image without one
  # has nothing to verify and passes — most images are in that case.
  #
  # java_dir is derived from certs_dir, and the sidecar from java_dir, so the
  # truststore and the sidecar describing it cannot drift onto different paths.
  # Both must stay rootfs-relative: this scanner's own host may well have a real
  # /etc/ssl/certs/java/cacerts, and an absolute path here would silently audit
  # that instead of the image.
  java_dir = File.join(certs_dir, 'java')
  truststore_path = File.join(java_dir, 'cacerts')
  truststore_file = file(truststore_path)

  if truststore_file.exist?
    truststore_sidecar_path = File.join(java_dir, '.cacerts.sha256')
    truststore_sidecar = ::SidecarDigest.resolve(self, truststore_sidecar_path, 'cacerts')

    describe "Java truststore checksum sidecar #{truststore_sidecar_path}" do
      it 'records exactly one SHA-256 digest for cacerts' do
        expect(truststore_sidecar).to be_resolved,
          "#{truststore_sidecar.detail}. The truststore at #{truststore_path} " \
          'cannot be verified without it.'
      end
    end

    if truststore_sidecar.resolved?
      describe truststore_file do
        its('sha256sum') { should eq truststore_sidecar.digest }
      end
    end
  else
    describe "Java truststore #{truststore_path}" do
      it 'is absent, so this image carries no truststore to verify' do
        expect(truststore_file.exist?).to be(false)
      end
    end
  end
end
