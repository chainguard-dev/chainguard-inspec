require 'spec_helper'
require 'tmpdir'
require 'fileutils'

# PackageSignature allows a repository when its HOST equals, or is a subdomain
# of, one of the allowed domains (default: the bare cgr.dev / wolfi.dev domains
# in inspec.yml). Matching is host-anchored and fails closed — see Path B in the
# A3 handoff. These specs cover the allow/deny decision; HTTPS enforcement is a
# separate assertion in the control.
RSpec.describe 'oval:org.PackageSignature:def:1' do
  let(:rootfs) { Dir.mktmpdir }
  let(:apk_dir) { File.join(rootfs, 'etc/apk') }
  let(:repos_path) { File.join(apk_dir, 'repositories') }

  after { FileUtils.rm_rf(rootfs) }

  # Write a single repository line to /etc/apk/repositories.
  def write_repo(line)
    FileUtils.mkdir_p(apk_dir)
    File.write(repos_path, "#{line}\n")
  end

  context 'when /etc/apk/repositories does not exist' do
    it 'is skipped' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_skipped
    end
  end

  # --- HTTPS enforcement (unchanged behavior) ---

  context 'when a repository uses http://' do
    before { write_repo('http://apk.cgr.dev/chainguard') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # --- ALLOWED: host equals or is a subdomain of an allowed domain ---

  context 'when the repo host is exactly an allowed domain' do
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

  context 'when the repo host is a subdomain of an allowed domain' do
    before { write_repo('https://customer.apk.cgr.dev/some-uuid/') }

    it 'passes' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when the repo host is a subdomain of the virtualapk domain' do
    before { write_repo('https://example.virtualapk.cgr.dev/foo') }

    it 'passes' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when a repository URL contains credentials that strip to an allowed host' do
    # Credentials (userinfo) are stripped before host extraction; this reduces
    # to host apk.cgr.dev, an allowed domain.
    before { write_repo('https://token:s3cr3t@apk.cgr.dev/chainguard') }

    it 'passes' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # --- DENIED: host is not an allowed domain or subdomain ---

  context 'when the host is unrelated to any allowed domain' do
    before { write_repo('https://evil.example.com/packages') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when an allowed domain appears only in the URL path' do
    before { write_repo('https://evil.example.com/mirror/apk.cgr.dev/chainguard') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when an allowed domain is a suffix of a larger host (suffix attack)' do
    before { write_repo('https://apk.cgr.dev.evil.com/chainguard') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when the host merely looks like an allowed domain (no dot boundary)' do
    before { write_repo('https://evilapk.cgr.dev/foo') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when a percent-encoded slash precedes the allowed domain' do
    before { write_repo('https://evil.domain%2Fapk.cgr.dev/x') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when a percent-encoded slash follows the allowed domain' do
    before { write_repo('https://apk.cgr.dev%2Fevil.domain/x') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when an allowed domain is in the userinfo but the real host is hostile' do
    before { write_repo('https://apk.cgr.dev@evil.com/x') }

    it 'fails' do
      expect(run_control('oval:org.PackageSignature:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # --- Empty allow-list ⇒ deny-all (flips the old skip behavior) ---

  context 'when the allowed_repositories override is empty' do
    before { write_repo('https://apk.cgr.dev/chainguard') }

    it 'fails (empty allow-list denies all)' do
      result = run_control('oval:org.PackageSignature:def:1', rootfs: rootfs,
                           allowed_repositories: '[]')
      expect(result).to be_failing
    end
  end
end
