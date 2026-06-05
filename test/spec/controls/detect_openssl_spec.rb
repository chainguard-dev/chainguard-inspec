require 'spec_helper'
require 'tmpdir'
require 'fileutils'

# NOTE: DetectOpenSslTest.rb uses command("find <ssl_dir> ...") which runs on the
# audit host (direct mode) or inside the cinc-auditor container (Docker mode).
# In both cases the fixture path resolves correctly because either:
#   - Direct: the fixture is on the host at the path passed as rootfs
#   - Docker: the fixture is bind-mounted at /fixture inside the container

RSpec.describe 'oval:org.OpenSsl:def:1' do
  let(:rootfs) { Dir.mktmpdir }
  let(:ssl_dir) { File.join(rootfs, 'etc/ssl') }
  let(:apk_db_dir) { File.join(rootfs, 'usr/lib/apk/db') }

  after { FileUtils.rm_rf(rootfs) }

  # Minimal valid fipsmodule.cnf content
  let(:fipsmodule_content) do
    <<~CNF
      [fips_sect]
      activate = 1
      install-mac = ABC123DEF456
    CNF
  end

  # Valid openssl.cnf with all required FIPS stanzas.
  # Must contain:
  #   - a line matching /^\s*\.include\s+fipsmodule\.cnf\s*$/
  #   - [provider_sect] with fips = fips_sect
  #   - [algorithm_sect] with default_properties = fips=yes
  let(:openssl_cnf_valid) do
    <<~CNF
      openssl_conf = openssl_init

      .include fipsmodule.cnf

      [openssl_init]
      providers = provider_sect
      alg_section = algorithm_sect

      [provider_sect]
      fips = fips_sect
      default = default_sect

      [default_sect]
      activate = 1

      [algorithm_sect]
      default_properties = fips=yes
    CNF
  end

  # openssl.cnf missing all FIPS-required stanzas
  let(:openssl_cnf_broken) do
    <<~CNF
      openssl_conf = openssl_init

      [openssl_init]
      providers = provider_sect
    CNF
  end

  # Minimal APK db with both required FIPS packages
  let(:apk_db_with_fips_packages) do
    <<~APK_DB
      C:Q1aaaabbbbcccc==
      P:openssl-config-fipshardened
      V:3.1.4-r0
      A:x86_64

      C:Q1ddddeeeeffffgg==
      P:openssl-provider-fips
      V:3.1.4-r0
      A:x86_64

    APK_DB
  end

  # APK db where the FIPS provider is shipped as a version stream: its P: name
  # carries a digit-led suffix (openssl-provider-fips -> openssl-provider-fips-3.1).
  # The required-package check must still recognize it as satisfied.
  let(:apk_db_with_fips_version_stream) do
    <<~APK_DB
      C:Q1aaaabbbbcccc==
      P:openssl-config-fipshardened
      V:3.1.4-r0
      A:x86_64

      C:Q1ddddeeeeffffgg==
      P:openssl-provider-fips-3.1
      V:3.1.4-r0
      A:x86_64

    APK_DB
  end

  # APK db where the bare required provider package is ABSENT and only a
  # separate, word-suffix subpackage (openssl-provider-fips-doc) is present.
  # config-fipshardened is present, so the only thing determining the result is
  # whether the subpackage wrongly satisfies the openssl-provider-fips
  # requirement — it must not.
  let(:apk_db_with_fips_subpackage_only) do
    <<~APK_DB
      C:Q1aaaabbbbcccc==
      P:openssl-config-fipshardened
      V:3.1.4-r0
      A:x86_64

      C:Q1ddddeeeeffffgg==
      P:openssl-provider-fips-doc
      V:3.1.4-r0
      A:x86_64

    APK_DB
  end

  # APK db with unrelated packages but not the FIPS ones
  let(:apk_db_without_fips_packages) do
    <<~APK_DB
      C:Q1hhhhiiiijjjj==
      P:musl
      V:1.2.5-r0
      A:x86_64

    APK_DB
  end

  def setup_valid_ssl_dir
    FileUtils.mkdir_p(ssl_dir)
    File.write(File.join(ssl_dir, 'fipsmodule.cnf'), fipsmodule_content)
    File.write(File.join(ssl_dir, 'openssl.cnf'), openssl_cnf_valid)
  end

  def setup_apk_db(content)
    FileUtils.mkdir_p(apk_db_dir)
    File.write(File.join(apk_db_dir, 'installed'), content)
  end

  context 'when skip_fips_checks is true' do
    it 'is skipped' do
      result = run_control('oval:org.OpenSsl:def:1', rootfs: rootfs,
                           skip_fips_checks: 'true')
      expect(result).to be_skipped
    end
  end

  context 'when all FIPS requirements are met' do
    before do
      setup_valid_ssl_dir
      setup_apk_db(apk_db_with_fips_packages)
    end

    it 'passes' do
      expect(run_control('oval:org.OpenSsl:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when fipsmodule.cnf is missing from /etc/ssl' do
    before do
      # ssl_dir exists but contains only openssl.cnf — no fipsmodule.cnf
      FileUtils.mkdir_p(ssl_dir)
      File.write(File.join(ssl_dir, 'openssl.cnf'), openssl_cnf_valid)
      setup_apk_db(apk_db_with_fips_packages)
    end

    it 'fails' do
      expect(run_control('oval:org.OpenSsl:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when openssl.cnf is missing required FIPS stanzas' do
    before do
      FileUtils.mkdir_p(ssl_dir)
      File.write(File.join(ssl_dir, 'fipsmodule.cnf'), fipsmodule_content)
      File.write(File.join(ssl_dir, 'openssl.cnf'), openssl_cnf_broken)
      setup_apk_db(apk_db_with_fips_packages)
    end

    it 'fails' do
      expect(run_control('oval:org.OpenSsl:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when required FIPS packages are absent from the APK database' do
    before do
      setup_valid_ssl_dir
      setup_apk_db(apk_db_without_fips_packages)
    end

    it 'fails' do
      expect(run_control('oval:org.OpenSsl:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when the FIPS provider is present as a version stream (P:openssl-provider-fips-3.1)' do
    before do
      setup_valid_ssl_dir
      setup_apk_db(apk_db_with_fips_version_stream)
    end

    it 'passes' do
      expect(run_control('oval:org.OpenSsl:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when only a word-suffix subpackage of the FIPS provider is present (P:openssl-provider-fips-doc)' do
    before do
      setup_valid_ssl_dir
      setup_apk_db(apk_db_with_fips_subpackage_only)
    end

    it 'fails' do
      expect(run_control('oval:org.OpenSsl:def:1', rootfs: rootfs)).to be_failing
    end
  end
end
