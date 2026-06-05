require 'spec_helper'
require_relative '../../../libraries/repo_matcher'

# Pure-Ruby unit tests for the RepoMatcher helper. Unlike package_signature_spec
# (which runs end-to-end under cinc-auditor), the URL/host parsing here is plain
# Ruby and is exercised directly for speed and precision. The security-critical
# behavior is host-anchored, fail-closed matching — see Path B in the A3 handoff.
RSpec.describe RepoMatcher do
  describe '.normalize_repo_url' do
    it 'strips token userinfo credentials' do
      expect(RepoMatcher.normalize_repo_url('https://token@apk.cgr.dev/x'))
        .to eq('https://apk.cgr.dev/x')
    end

    it 'strips user:password userinfo credentials' do
      expect(RepoMatcher.normalize_repo_url('https://token:s3cr3t@apk.cgr.dev/x'))
        .to eq('https://apk.cgr.dev/x')
    end

    it 'leaves a URL without credentials unchanged' do
      expect(RepoMatcher.normalize_repo_url('https://apk.cgr.dev/chainguard'))
        .to eq('https://apk.cgr.dev/chainguard')
    end

    it 'handles http as well as https' do
      expect(RepoMatcher.normalize_repo_url('http://u@h.example/x'))
        .to eq('http://h.example/x')
    end

    it 'treats userinfo as credentials even when it looks like an allowed host' do
      # The real host is whatever follows the @ — here, evil.com.
      expect(RepoMatcher.normalize_repo_url('https://apk.cgr.dev@evil.com/x'))
        .to eq('https://evil.com/x')
    end

    it 'leaves a bare domain (no scheme) unchanged' do
      expect(RepoMatcher.normalize_repo_url('apk.cgr.dev')).to eq('apk.cgr.dev')
    end
  end

  describe '.host' do
    it 'extracts the host from a full URL' do
      expect(RepoMatcher.host('https://apk.cgr.dev/chainguard')).to eq('apk.cgr.dev')
    end

    it 'lowercases the host' do
      expect(RepoMatcher.host('https://APK.CGR.DEV/x')).to eq('apk.cgr.dev')
    end

    it 'returns a bare domain as-is' do
      expect(RepoMatcher.host('apk.cgr.dev')).to eq('apk.cgr.dev')
    end

    it 'keeps subdomains' do
      expect(RepoMatcher.host('https://customer.apk.cgr.dev/some-uuid/'))
        .to eq('customer.apk.cgr.dev')
    end

    it 'strips a port' do
      expect(RepoMatcher.host('https://apk.cgr.dev:443/x')).to eq('apk.cgr.dev')
    end

    it 'strips credentials before extracting the host' do
      expect(RepoMatcher.host('https://token:s3cr3t@apk.cgr.dev/x')).to eq('apk.cgr.dev')
    end

    it 'resolves a userinfo spoof to the real host' do
      expect(RepoMatcher.host('https://apk.cgr.dev@evil.com/x')).to eq('evil.com')
    end

    it 'does NOT URL-decode: a percent-encoded slash stays literal in the host' do
      expect(RepoMatcher.host('https://evil.domain%2Fapk.cgr.dev/x'))
        .to eq('evil.domain%2fapk.cgr.dev')
      expect(RepoMatcher.host('https://apk.cgr.dev%2Fevil.domain/x'))
        .to eq('apk.cgr.dev%2fevil.domain')
    end
  end

  describe '.allowed_domains' do
    it 'reduces bare-domain and full-URL entries to their hosts' do
      expect(RepoMatcher.allowed_domains(['apk.cgr.dev', 'https://packages.wolfi.dev/os']))
        .to eq(['apk.cgr.dev', 'packages.wolfi.dev'])
    end

    it 'is empty for an empty list' do
      expect(RepoMatcher.allowed_domains([])).to eq([])
    end

    it 'drops blank entries (so a blank-only list denies all)' do
      expect(RepoMatcher.allowed_domains([''])).to eq([])
    end
  end

  describe '.allowed?' do
    let(:domains) { ['apk.cgr.dev', 'virtualapk.cgr.dev', 'packages.wolfi.dev'] }

    it 'allows a host equal to an allowed domain' do
      expect(RepoMatcher.allowed?('https://apk.cgr.dev/chainguard', domains)).to be true
    end

    it 'allows a subdomain of an allowed domain' do
      expect(RepoMatcher.allowed?('https://customer.apk.cgr.dev/some-uuid/', domains)).to be true
    end

    it 'allows a subdomain of the virtualapk domain' do
      expect(RepoMatcher.allowed?('https://example.virtualapk.cgr.dev/foo', domains)).to be true
    end

    it 'allows after stripping credentials' do
      expect(RepoMatcher.allowed?('https://token:s3cr3t@apk.cgr.dev/x', domains)).to be true
    end

    it 'is case-insensitive on the host' do
      expect(RepoMatcher.allowed?('https://APK.CGR.DEV/x', domains)).to be true
    end

    it 'denies a host unrelated to any allowed domain' do
      expect(RepoMatcher.allowed?('https://evil.example.com/packages', domains)).to be false
    end

    it 'denies when the allowed domain only appears in the path' do
      expect(RepoMatcher.allowed?('https://evil.example.com/mirror/apk.cgr.dev/chainguard', domains))
        .to be false
    end

    it 'denies a suffix attack (allowed domain is a suffix of a larger host)' do
      expect(RepoMatcher.allowed?('https://apk.cgr.dev.evil.com/chainguard', domains)).to be false
    end

    it 'denies a lookalike host with no dot boundary' do
      expect(RepoMatcher.allowed?('https://evilapk.cgr.dev/foo', domains)).to be false
    end

    it 'fails closed on a percent-encoded slash before the allowed domain' do
      expect(RepoMatcher.allowed?('https://evil.domain%2Fapk.cgr.dev/x', domains)).to be false
    end

    it 'fails closed on a percent-encoded slash after the allowed domain' do
      expect(RepoMatcher.allowed?('https://apk.cgr.dev%2Fevil.domain/x', domains)).to be false
    end

    it 'denies a userinfo spoof whose real host is hostile' do
      expect(RepoMatcher.allowed?('https://apk.cgr.dev@evil.com/x', domains)).to be false
    end

    it 'denies everything when the allowed-domain list is empty' do
      expect(RepoMatcher.allowed?('https://apk.cgr.dev/chainguard', [])).to be false
    end
  end
end
