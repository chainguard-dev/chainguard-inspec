require 'spec_helper'
require_relative '../../../libraries/sidecar_digest'

# Pure-Ruby unit tests. SidecarDigest reads an apko sidecar — one
# `sha256sum`-format line naming the file it describes — and reports either the
# single recorded digest or why it could not. Everything goes through
# `context.file(path)`, so these use plain doubles: no cinc-auditor, no Docker.
RSpec.describe SidecarDigest do
  def context_double(exist:, file: true, content: nil)
    ctx = double('context')
    allow(ctx).to receive(:file).and_return(
      double('file', exist?: exist, file?: file, content: content)
    )
    ctx
  end

  def resolve(exist:, file: true, content: nil, basename: 'cacerts')
    described_class.resolve(context_double(exist: exist, file: file, content: content),
                            '/rootfs/etc/ssl/certs/java/.cacerts.sha256', basename)
  end

  let(:digest) { 'a' * 64 }

  describe 'a well-formed sidecar' do
    [
      ['two-space text mode',   "%<d>s  cacerts\n"],
      ['binary mode asterisk',  "%<d>s *cacerts\n"],
      ['tab separated',         "%<d>s\tcacerts\n"],
      ['no trailing newline',   '%<d>s  cacerts'],
      ['preceded by a comment', "# generated\n%<d>s  cacerts\n"]
    ].each do |name, template|
      it "resolves the digest when the line is #{name}" do
        result = resolve(exist: true, content: format(template, d: digest))
        expect(result.digest).to eq(digest)
        expect(result).to be_resolved
        expect(result.detail).to be_nil
      end
    end

    it 'downcases the digest so the comparison is case-insensitive' do
      result = resolve(exist: true, content: "#{digest.upcase}  cacerts\n")
      expect(result.digest).to eq(digest)
    end
  end

  describe 'a sidecar that cannot be used' do
    it 'reports a missing file' do
      result = resolve(exist: false)
      expect(result).not_to be_resolved
      expect(result.digest).to be_nil
      # The exact phrase, not just "does not exist": ca_bundle_hash_spec.rb
      # pins the contiguous substring "file does not exist" and cannot be
      # touched, so this must catch a wording regression there too.
      expect(result.detail).to include('file does not exist')
    end

    # content is nil for a directory and for a file the scanner cannot read.
    # Reporting "no line matching <regex>" for either sends the reader after a
    # format bug in a file that may be perfectly well formed.
    it 'distinguishes a directory from a format problem' do
      result = resolve(exist: true, file: false, content: nil)
      expect(result.detail).to include('not a regular file')
      expect(result.detail).not_to include('no line matching')
    end

    it 'distinguishes an unreadable file from a format problem' do
      result = resolve(exist: true, file: true, content: nil)
      expect(result.detail).to include('not readable')
      expect(result.detail).not_to include('no line matching')
    end

    it 'reports a sidecar with no matching line' do
      result = resolve(exist: true, content: "not a checksum line\n")
      expect(result.detail).to include('no line matching')
    end

    # A digest recorded for some other file must not be accepted.
    it 'reports a sidecar naming a different file' do
      result = resolve(exist: true, content: "#{digest}  something-else\n")
      expect(result.detail).to include('no line matching')
    end

    it 'reports a hex string of the wrong length' do
      result = resolve(exist: true, content: "#{'a' * 65}  cacerts\n")
      expect(result.detail).to include('no line matching')
    end

    # instance=1 means only_one_exists cannot fail on duplicates upstream; we
    # fail closed anyway, consistently with the system-bundle case.
    it 'reports more than one digest line, naming the count' do
      result = resolve(exist: true, content: "#{digest}  cacerts\n#{'b' * 64}  cacerts\n")
      expect(result).not_to be_resolved
      expect(result.detail).to include('2 digest lines')
    end
  end

  describe 'robustness' do
    # Non-UTF8 bytes would otherwise raise ArgumentError from the regex match.
    # At control-body scope that collapses the whole control into a code error.
    it 'scrubs invalid bytes rather than raising' do
      result = resolve(exist: true, content: "\xff\xfe junk\n#{digest}  cacerts\n")
      expect(result.digest).to eq(digest)
    end

    # The basename is interpolated into the pattern, so a caller passing one
    # with regex metacharacters must not change what the pattern means.
    it 'treats the basename literally' do
      result = resolve(exist: true, content: "#{digest}  ca-certificates.crt\n",
                       basename: 'ca.certificates.crt')
      expect(result).not_to be_resolved
    end
  end
end
