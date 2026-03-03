require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe 'oval:org.PackageSignature:def:1' do
  let(:rootfs) { Dir.mktmpdir }
  let(:apk_dir) { File.join(rootfs, 'etc/apk') }
  let(:repos_path) { File.join(apk_dir, 'repositories') }

  after { FileUtils.rm_rf(rootfs) }

  context 'when /etc/apk/repositories does not exist' do
    # No before block — apk_dir is not created

    it 'is skipped' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_skipped
    end
  end

  context 'when repositories use only HTTPS URLs matching allowed prefixes' do
    before do
      FileUtils.mkdir_p(apk_dir)
      File.write(repos_path, <<~REPOS)
        https://apk.cgr.dev/chainguard
        https://packages.wolfi.dev/os
      REPOS
    end

    it 'passes' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when a repository uses http://' do
    before do
      FileUtils.mkdir_p(apk_dir)
      File.write(repos_path, <<~REPOS)
        http://apk.cgr.dev/chainguard
      REPOS
    end

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when a repository uses HTTPS but does not match any allowed prefix' do
    before do
      FileUtils.mkdir_p(apk_dir)
      File.write(repos_path, <<~REPOS)
        https://evil.example.com/packages
      REPOS
    end

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when a repository URL contains credentials that normalize to an allowed prefix' do
    before do
      FileUtils.mkdir_p(apk_dir)
      # Credentials are stripped before prefix matching; this normalizes to
      # https://apk.cgr.dev/chainguard which matches the default allowed prefix
      File.write(repos_path, <<~REPOS)
        https://token:s3cr3t@apk.cgr.dev/chainguard
      REPOS
    end

    it 'passes' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_passing
    end
  end
end
