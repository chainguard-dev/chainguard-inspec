require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'digest'

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
    it 'fails' do
      result = run_control('oval:org.CABundleHash:def:1', rootfs: rootfs,
                           expected_cacert_hash: bundle_hash)
      expect(result).to be_failing
    end
  end
end
