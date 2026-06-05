require 'spec_helper'
require_relative '../../../libraries/apk_db'

# Pure-Ruby unit tests for the ApkDb helper. Unlike the control specs (which
# run end-to-end under cinc-auditor), the matching logic here is plain Ruby and
# is exercised directly for speed and precision.
#
# The central concern is Wolfi *version streams*: a package name may carry a
# digit-led version suffix (openssh -> openssh-9.7) and must still match, while
# a separate word-led subpackage (openssh -> openssh-keygen) must NOT match
# unless it is listed explicitly.
RSpec.describe ApkDb do
  # A realistic slice of /usr/lib/apk/db/installed with a mix of bare names,
  # version streams, and word-suffix subpackages.
  let(:installed_db) do
    <<~APK_DB
      C:Q1aaaa==
      P:openssh-9.7
      V:9.7_p1-r0
      A:x86_64

      C:Q1bbbb==
      P:openssh-keygen
      V:9.7_p1-r0
      A:x86_64

      C:Q1cccc==
      P:openssl-3.1
      V:3.1.4-r0
      A:x86_64

      C:Q1dddd==
      P:openssl-dev
      V:3.1.4-r0
      A:x86_64

      C:Q1eeee==
      P:python-3.12
      V:3.12.0-r0
      A:x86_64

      C:Q1ffff==
      P:python-3.12-dev
      V:3.12.0-r0
      A:x86_64

      C:Q1gggg==
      P:musl
      V:1.2.5-r0
      A:x86_64
    APK_DB
  end

  describe '.package_present?' do
    it 'matches an exact bare package name' do
      expect(ApkDb.package_present?(installed_db, 'musl')).to be true
    end

    it 'matches a digit-led version-stream variant (openssh -> openssh-9.7)' do
      expect(ApkDb.package_present?(installed_db, 'openssh')).to be true
    end

    it 'matches a two-component version stream (openssl -> openssl-3.1)' do
      expect(ApkDb.package_present?(installed_db, 'openssl')).to be true
    end

    it 'matches a dotted version stream (python -> python-3.12)' do
      expect(ApkDb.package_present?(installed_db, 'python')).to be true
    end

    it 'does NOT match a word-suffix subpackage (openssh vs openssh-keygen only)' do
      db = "P:openssh-keygen\nV:9.7_p1-r0\n"
      expect(ApkDb.package_present?(db, 'openssh')).to be false
    end

    it 'does NOT match a word-suffix subpackage of a version stream (openssl-dev)' do
      db = "P:openssl-dev\nV:3.1.4-r0\n"
      expect(ApkDb.package_present?(db, 'openssl')).to be false
    end

    it 'does NOT match a word suffix following a version stream (python-3.12-dev)' do
      db = "P:python-3.12-dev\nV:3.12.0-r0\n"
      expect(ApkDb.package_present?(db, 'python-3.12')).to be false
    end

    it 'still matches an explicitly listed subpackage by its own exact name' do
      expect(ApkDb.package_present?(installed_db, 'openssh-keygen')).to be true
    end

    it 'does NOT treat a longer bare name as a match (openssh vs opensshd)' do
      db = "P:opensshd\nV:1.0-r0\n"
      expect(ApkDb.package_present?(db, 'openssh')).to be false
    end

    it 'does NOT match an unrelated package sharing a prefix family (openssh vs openssl)' do
      db = "P:openssl-3.1\nV:3.1.4-r0\n"
      expect(ApkDb.package_present?(db, 'openssh')).to be false
    end

    it 'returns false for an absent package' do
      expect(ApkDb.package_present?(installed_db, 'dropbear')).to be false
    end

    it 'returns false for empty content' do
      expect(ApkDb.package_present?('', 'openssh')).to be false
    end
  end

  describe '.matched_package_name' do
    it 'returns the full version-stream name for evidence (openssh -> openssh-9.7)' do
      expect(ApkDb.matched_package_name(installed_db, 'openssh')).to eq('openssh-9.7')
    end

    it 'returns the bare name when an exact match is present' do
      expect(ApkDb.matched_package_name(installed_db, 'musl')).to eq('musl')
    end

    it 'returns nil when the package is absent' do
      expect(ApkDb.matched_package_name(installed_db, 'dropbear')).to be_nil
    end

    it 'returns nil for a word-suffix subpackage that is not listed' do
      db = "P:openssh-keygen\nV:9.7_p1-r0\n"
      expect(ApkDb.matched_package_name(db, 'openssh')).to be_nil
    end
  end

  describe '.installed_db_content' do
    # The control passes `self`; the context responds to #file(path) with an
    # InSpec file resource. We stub that transport-safe interface here.
    let(:resource) { double('file_resource') }
    let(:context) { double('control_context') }

    it 'returns the file content when the db exists' do
      allow(context).to receive(:file).with('/db').and_return(resource)
      allow(resource).to receive(:exist?).and_return(true)
      allow(resource).to receive(:content).and_return("P:musl\n")
      expect(ApkDb.installed_db_content(context, '/db')).to eq("P:musl\n")
    end

    it 'returns an empty string when the db does not exist (never raises)' do
      allow(context).to receive(:file).with('/db').and_return(resource)
      allow(resource).to receive(:exist?).and_return(false)
      expect(ApkDb.installed_db_content(context, '/db')).to eq('')
    end
  end
end
