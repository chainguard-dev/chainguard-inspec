require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'digest'
require 'json'

RSpec.describe 'oval:org.CABundleHash:def:1' do
  let(:rootfs) { Dir.mktmpdir }
  let(:bundle_dir) { File.join(rootfs, 'etc/ssl/certs') }
  let(:bundle_path) { File.join(bundle_dir, 'ca-certificates.crt') }
  # Realistic-looking but synthetic CA bundle content
  let(:bundle_content) do
    <<~BUNDLE
      # This is a test CA bundle fixture
      -----BEGIN CERTIFICATE-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestcertificatecontent
      AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP
      -----END CERTIFICATE-----
    BUNDLE
  end
  let(:bundle_hash) { Digest::SHA256.hexdigest(bundle_content) }
  let(:wrong_hash) { 'a' * 64 }
  let(:stamp_path) { File.join(bundle_dir, '.ca-certificates.crt.sha256') }

  before { FileUtils.mkdir_p(bundle_dir) }
  after { FileUtils.rm_rf(rootfs) }

  context 'when the CA bundle exists and the hash matches' do
    before { File.write(bundle_path, bundle_content) }

    it 'passes' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_passing
    end
  end

  context 'when the CA bundle exists but the hash does not match' do
    before { File.write(bundle_path, bundle_content) }

    it 'fails' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: wrong_hash)
      expect(result).to be_failing
    end
  end

  context 'when the CA bundle file is absent' do
    it 'fails on the exist? check, not merely because the override happens to fail elsewhere' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_failing
      expect(result.failure_messages.join("\n")).to include('to exist'),
        "expected the failure to say the bundle does not exist.\n#{result.diagnostic}"
    end
  end

  # The CA bundle path exists but is a directory, not a file. The control asserts
  # both `should exist` (a directory satisfies this) and `should be_file` (it does
  # not). Every fixture reaching this branch supplies an override, so the hash
  # comparison would fail regardless — the be_file-specific assertion below is
  # what actually exercises this branch distinctly from the absent case.
  context 'when the CA bundle path is a directory instead of a file' do
    before { FileUtils.mkdir_p(bundle_path) }

    it 'fails on the be_file check specifically' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_failing
      expect(result.failure_messages.join("\n")).to include('file?'),
        "expected the failure to say the path is not a file.\n#{result.diagnostic}"
      expect(result.failure_messages.join("\n")).not_to include('to exist'),
        "a directory satisfies the exist? check; only be_file should fail here.\n#{result.diagnostic}"
    end
  end

  # The realistic distroless case: no bundle, no sidecar, and no override.
  # Must fail rather than pass vacuously.
  context 'when the CA bundle file is absent and no override is given' do
    it 'fails' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect(result).to be_failing
    end
  end

  # The tab alternative in the stamp regex's [ \t]+ separator is otherwise
  # unexercised — every other fixture uses the two-space sha256sum format.
  context 'when the stamp separates the digest and filename with a tab' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash}\tca-certificates.crt\n")
    end

    it 'passes' do
      expect(run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # A sidecar can be adversary-influenceable in exactly the tampering scenario
  # this control targets. Non-UTF8 bytes ahead of an otherwise well-formed line
  # must not raise ArgumentError out of the control body (which would collapse
  # the whole control to an opaque "Control Source Code Error", losing the
  # stamp finding, the bundle-existence evidence, and the hash comparison, with
  # no override able to rescue it). The wrong-filename line keeps this
  # deterministic: it proves parsing proceeded past the garbage bytes and
  # reached a normal "no line matching" finding that names the sidecar, rather
  # than crashing with a generic encoding error that would not.
  context 'when the stamp contains non-UTF8 bytes ahead of a well-formed digest line' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "\xff\xfe garbage\n#{bundle_hash}  some-other-file.crt\n",
                 encoding: 'ASCII-8BIT')
    end

    it 'fails as a normal stamp finding, not a code error' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect_stamp_finding(result)
      expect(result.failure_messages.join("\n")).to include('no line matching'),
        "expected a normal 'no line matching' finding, proving .scrub let parsing " \
        "proceed instead of raising ArgumentError.\n#{result.diagnostic}"
    end
  end

  # A sidecar path that exists but isn't a regular file (e.g. a directory) is a
  # different problem than a malformed digest line, and the operator should not
  # be sent chasing a format bug that doesn't exist.
  context 'when the stamp path is a directory instead of a file' do
    before do
      File.write(bundle_path, bundle_content)
      FileUtils.mkdir_p(stamp_path)
    end

    it 'fails, naming the condition rather than a format problem' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect_stamp_finding(result)
      expect(result.failure_messages.join("\n")).to include('not a regular file'),
        "expected the failure to say the stamp path is not a regular file, not a format problem.\n" \
        "#{result.diagnostic}"
      expect(result.failure_messages.join("\n")).not_to include('no line matching'),
        "a directory sidecar is not a format problem; the failure should not blame the regex.\n" \
        "#{result.diagnostic}"
    end
  end

  # --- stamp-file resolution (stigs c8bfbd2) ---
  #
  # With no expected_cacert_hash override, the expected digest comes from the
  # sidecar apko writes next to the bundle. A missing, unparseable, or
  # duplicated stamp is a finding rather than a vacuous pass.
  # Requiring exactly one digest line is stricter than the datastream, not a
  # mirror of it — see the comment above the mandatory-stamp block in
  # CaBundleHashTest.rb for why (obj:4's instance=1 entity means oscap's
  # only_one_exists degenerates to "at least one line, first one used").

  context 'when no override is given and the stamp matches the bundle' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash}  ca-certificates.crt\n")
    end

    it 'passes' do
      expect(run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # sha256sum's binary-mode format prefixes the filename with '*'. The OVAL
  # pattern allows it, so we must too.
  context 'when the stamp uses binary-mode format (asterisk before the filename)' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash} *ca-certificates.crt\n")
    end

    it 'passes' do
      expect(run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # Asserts the digest actually came from the stamp: the failure must quote the
  # stamp's value as the expected one. Checking only `be_failing` would not
  # discriminate — the control fails this fixture today too, comparing against
  # the pinned default rather than the stamp.
  context 'when the stamp disagrees with the bundle' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{wrong_hash}  ca-certificates.crt\n")
    end

    it 'fails, having taken the expected digest from the stamp' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect(result).to be_failing
      expect(result.failure_messages.join("\n")).to include(wrong_hash),
        "expected the failure to quote the stamp's digest #{wrong_hash} as the " \
        "expected value, which is how we know the stamp was read at all.\n" \
        "#{result.diagnostic}"
    end
  end

  # Shared assertion for the cases where the stamp itself is the problem. The
  # failure must name the stamp file. Asserting only `be_failing` would not
  # discriminate: today the control fails every no-override fixture by comparing
  # the bundle against an unrelated pinned default, so such a test passes now and
  # would keep passing if the stamp logic were later deleted.
  def expect_stamp_finding(result)
    expect(result).to be_failing
    expect(result.failure_messages.join("\n")).to include('.ca-certificates.crt.sha256'),
      "expected the failure to name the stamp file as the reason.\n#{result.diagnostic}"
  end

  # The whole point of tst:4: without it, an image that simply omits the stamp
  # would have nothing to compare against and could pass by default.
  context 'when the stamp file is absent and no override is given' do
    before { File.write(bundle_path, bundle_content) }

    it 'fails, naming the missing stamp, rather than passing vacuously' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect_stamp_finding(result)
      # Own discriminating substring, independent of failure_messages'
      # message-over-code_desc preference: proves this is the "stamp doesn't
      # exist" branch of detail, not merely a failure that happens to mention
      # the stamp path (e.g. from code_desc, which also names the path).
      expect(result.failure_messages.join("\n")).to include('file does not exist'),
        "expected the failure to say the stamp file does not exist.\n#{result.diagnostic}"
    end
  end

  context 'when the stamp file exists but contains no usable digest line' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "not a checksum line\n")
    end

    it 'fails, naming the unparseable stamp' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect_stamp_finding(result)
      expect(result.failure_messages.join("\n")).to include('no line matching'),
        "expected the failure to say no line matched the stamp pattern.\n#{result.diagnostic}"
    end
  end

  # A digest recorded for some other file must not be accepted for the bundle.
  context 'when the stamp names a different file' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash}  some-other-file.crt\n")
    end

    it 'fails, naming the stamp with no entry for ca-certificates.crt' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect_stamp_finding(result)
      expect(result.failure_messages.join("\n")).to include('no line matching'),
        "expected the failure to say no line matched the stamp pattern.\n#{result.diagnostic}"
    end
  end

  # Requiring exactly one line here is stricter than the datastream: obj:4's
  # instance=1 entity means oscap would still accept this stamp (it just uses
  # the first line, per only_one_exists's degenerate semantics). We fail
  # closed instead — no real packaging path emits duplicate stamp lines, and a
  # stamp that does is worth surfacing rather than silently resolving.
  context 'when the stamp contains two digest lines for the bundle' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{wrong_hash}  ca-certificates.crt\n#{bundle_hash}  ca-certificates.crt\n")
    end

    it 'fails, naming the stamp with more than one entry' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect_stamp_finding(result)
      expect(result.failure_messages.join("\n")).to include('2 digest lines'),
        "expected the failure to name the duplicate-line count.\n#{result.diagnostic}"
    end
  end

  # --- override precedence ---
  #
  # update-ca-certificates regenerates the bundle but NOT the stamp, so a
  # legitimately cert-customized image has a stale stamp. The override is how
  # such an image stays scannable; it must therefore beat the stamp.

  context 'when an override is given and the stamp is stale' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{wrong_hash}  ca-certificates.crt\n")
    end

    it 'passes, because the override wins over the stamp' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_passing
    end
  end

  # An image with a hand-placed bundle apko never built has no sidecar at
  # all. The override must not additionally demand one.
  context 'when an override is given and no stamp exists' do
    before { File.write(bundle_path, bundle_content) }

    it 'passes without requiring a stamp file' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_passing
    end
  end

  # OVAL ste:1 compares the hash case-insensitively. A user pasting an uppercase
  # digest into the override must not produce a spurious finding.
  context 'when the override is given in uppercase' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash}  ca-certificates.crt\n")
    end

    it 'passes, because the digest comparison is case-insensitive' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash.upcase)
      expect(result).to be_passing
    end
  end

  # Same for a stamp file written with uppercase hex.
  context 'when the stamp records the digest in uppercase' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash.upcase}  ca-certificates.crt\n")
    end

    it 'passes, because the digest comparison is case-insensitive' do
      expect(run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # The corroboration evidence must never turn into a finding — an override with
  # no stamp to check it against still passes. These assert both the control's
  # verdict and the exact corroboration text in the reporter JSON: passing
  # examples carry their description in code_desc, which is part of raw_json,
  # so a regression that drops or garbles the evidence wording is caught even
  # though it never flips pass/fail. Text kept in lockstep with the
  # `corroboration =` branches in CaBundleHashTest.rb.
  #
  # Matched by the stamp file's basename, not the full stamp_path: in Docker
  # mode the fixture is bind-mounted at a fixed /fixture, so the path the
  # control reports is not this spec's host tmpdir path (see
  # docker-mode-rootfs-fixture-remap in project notes). The basename is the
  # part that's actually invariant across transports.
  context 'when an override is given and the stamp contradicts it' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{wrong_hash}  ca-certificates.crt\n")
    end

    it 'passes and records that the stamp records a different digest' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_passing
      expect(result.raw_json).to include(
        "#{File.basename(stamp_path)} records a different digest " \
        "(#{wrong_hash}), expected for a bundle changed after the image was built"
      )
    end
  end

  context 'when an override is given and the stamp agrees with it' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash}  ca-certificates.crt\n")
    end

    it 'passes and records that the stamp records the same digest' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_passing
      expect(result.raw_json).to include(
        "#{File.basename(stamp_path)} records the same digest"
      )
    end
  end

  # The "Expected CA bundle digest origin" evidence must actually discriminate
  # between an override and a stamp read: swapping the ternary in
  # CaBundleHashTest.rb (so an override reports "resolved from the stamp" and
  # vice versa) left all examples green until these assertions were added —
  # the compliance artefact would otherwise attribute an operator-supplied
  # digest to a file the operator did not write, or vice versa.
  #
  # Scoped to this one result's own code_desc, not a raw_json-wide substring
  # search: the reporter JSON also embeds the control's full source under
  # "code" (comments, string literals, the lot), so a plain
  # `raw_json.include?(...)` can be satisfied by the source text itself —
  # e.g. the bare stamp filename literal on the `stamp_path = File.join(...)`
  # line — regardless of what the control actually resolved at runtime.
  # Isolating the one example's code_desc avoids that false-positive class.
  #
  # Anchored on File.basename for the sidecar direction, not the full
  # stamp_path: in Docker mode the fixture is bind-mounted at a fixed
  # /fixture, so the path the control reports is not this spec's host tmpdir
  # path (see docker-mode-rootfs-fixture-remap in project notes).
  def digest_origin_code_desc(result)
    data = JSON.parse(result.raw_json)
    control = data.dig('profiles', 0, 'controls').find { |c| c['id'] == result.control_id }
    entry = control && control['results'].find { |r| r['code_desc'].to_s.start_with?('Expected CA bundle digest origin') }
    entry && entry['code_desc']
  end

  context 'when an override is given, the digest origin evidence' do
    before { File.write(bundle_path, bundle_content) }

    it 'names the expected_cacert_hash input' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_passing
      code_desc = digest_origin_code_desc(result)
      expect(code_desc).to include('resolved from the expected_cacert_hash input'),
        "expected the origin evidence to name the override input, got #{code_desc.inspect}.\n#{result.diagnostic}"
    end
  end

  context 'when no override is given and the stamp resolves the digest, the digest origin evidence' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash}  ca-certificates.crt\n")
    end

    it 'names the sidecar' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs)
      expect(result).to be_passing
      code_desc = digest_origin_code_desc(result)
      expect(code_desc).to include('resolved from the sidecar'),
        "expected the origin evidence to name the sidecar, not the input, got #{code_desc.inspect}.\n#{result.diagnostic}"
      expect(code_desc).to include(File.basename(stamp_path)),
        "expected the origin evidence to name the sidecar file, got #{code_desc.inspect}.\n#{result.diagnostic}"
    end
  end

  # Guard against the NO_VALUE_SET footgun: an empty override must fall through
  # to the stamp, not be treated as a supplied (and unmatchable) value.
  context 'when the override is an empty string' do
    before do
      File.write(bundle_path, bundle_content)
      File.write(stamp_path, "#{bundle_hash}  ca-certificates.crt\n")
    end

    it 'falls through to the stamp and passes' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: '')
      expect(result).to be_passing
    end
  end

  # The realistic override value is produced by command substitution, e.g.
  # --input expected_cacert_hash="$(sha256sum ... | cut -d' ' -f1)", which
  # leaves a trailing newline; a leading space is plausible too depending on
  # how the value is quoted. .strip is applied at both call sites (the
  # is-a-supplied-value check, and the value used for comparison) — this
  # exercises both, since a value that survived stripping wrong would either
  # be treated as absent or fail to match.
  context 'when the override has surrounding whitespace' do
    before { File.write(bundle_path, bundle_content) }

    it 'passes, because the override is stripped before use' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: " #{bundle_hash}\n")
      expect(result).to be_passing
    end
  end
end
