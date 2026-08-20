require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe 'oval:org.RemoteAccessServices:def:1' do
  let(:rootfs) { Dir.mktmpdir }
  let(:apk_db_dir) { File.join(rootfs, 'usr/lib/apk/db') }
  let(:apk_db_path) { File.join(apk_db_dir, 'installed') }

  before { FileUtils.mkdir_p(apk_db_dir) }
  after { FileUtils.rm_rf(rootfs) }

  context 'when no banned packages are present in the APK database' do
    before do
      # Unrelated packages only — no remote access packages
      File.write(apk_db_path, <<~APK_DB)
        C:Q1aaaabbbbcccc==
        P:musl
        V:1.2.5-r0
        A:x86_64

        C:Q1ddddeeeefffff==
        P:libssl3
        V:3.1.4-r0
        A:x86_64

      APK_DB
    end

    it 'passes' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when openssh is present in the APK database' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1gggghhhhiiii==
        P:openssh
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'fails' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when a package installs a file whose name matches a banned package pattern (e.g. telnetlib.py)' do
    before do
      # python-3.12 installs telnetlib.py; no actual telnet package is present.
      # The control must not treat a file-path entry (R: line) as a package match.
      File.write(apk_db_path, <<~APK_DB)
        C:Q1aaaabbbbcccc==
        P:python-3.12
        V:3.12.0-r0
        A:x86_64
        F:usr/lib/python3.12
        R:telnetlib.py
        Z:Q1ddddeeeefffff==

      APK_DB
    end

    it 'passes' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when cockpit-ws is present in the APK database' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1jjjjkkkkllll==
        P:cockpit-ws
        V:320-r0
        A:x86_64

      APK_DB
    end

    it 'fails' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # A banned package shipped as a version stream carries a digit-led suffix in
  # its P: name (openssh -> openssh-9.7). It must still be flagged.
  context 'when a banned package is present as a version stream (P:openssh-9.7)' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1mmmmnnnnoooo==
        P:openssh-9.7
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'fails' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # A separate subpackage carries a word-led suffix (openssh-keygen). Banning
  # `openssh` must NOT implicitly ban `openssh-keygen`, which is not itself in
  # the banned list.
  context 'when only a word-suffix subpackage of a banned package is present (P:openssh-keygen)' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1ppppqqqqrrrr==
        P:openssh-keygen
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'passes' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # Contrast with openssh-keygen above: openssh-server and openssh-sftp-server
  # ARE word-suffix subpackages, but they are listed in banned_remote_packages
  # in their own right, so they must still be flagged via their own exact entry
  # (not via the `openssh` entry, which does not match word-led suffixes).
  context 'when explicitly-listed openssh subpackages are present (openssh-server, openssh-sftp-server)' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1ssssttttuuuu==
        P:openssh-server
        V:9.7_p1-r0
        A:x86_64

        C:Q1vvvvwwwwxxxx==
        P:openssh-sftp-server
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'fails' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # A listed subpackage shipped as a version stream (openssh-server-9.7) must
  # also be flagged: the digit-led suffix matches its own exact entry.
  context 'when a listed openssh subpackage is present as a version stream (P:openssh-server-9.7)' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1yyyyzzzz0000==
        P:openssh-server-9.7
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'fails' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # --- banned_remote_packages input override (B6) ---
  #
  # The banned set is driven entirely by the banned_remote_packages input. These
  # contexts prove the input — not just the inspec.yml default — decides the
  # outcome, in both directions.

  # A package absent from the default banned list must be flagged once added to
  # the override. (myforbiddenpkg is not in the inspec.yml default list, so the
  # default run would pass it.)
  context 'when a custom override bans a package the default list ignores' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1aaaabbbbcccc==
        P:myforbiddenpkg
        V:1.0.0-r0
        A:x86_64

      APK_DB
    end

    it 'passes under the default banned list' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_passing
    end

    it 'fails when the override bans it' do
      result = run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs,
                           banned_remote_packages: '[myforbiddenpkg]')
      expect(result).to be_failing
    end
  end

  # The inverse: a package that IS in the default banned list (openssh) must pass
  # when an override list omits it — confirming the default list is replaced, not
  # merged.
  context 'when an override omits a package that the default list bans' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1ddddeeeeffff==
        P:openssh
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'passes when the override list does not include openssh' do
      result = run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs,
                           banned_remote_packages: '[vsftpd]')
      expect(result).to be_passing
    end
  end

  # Upstream stigs commit 2e346ee removed openssh-client from
  # oval:org.RemoteAccessServices:obj:6: the SSH *client* is permitted, and FIPS
  # ssh_config policy (checked by DetectOpenSslTest) governs it instead of a
  # package ban. Banning it here would report a finding oscap does not.
  context 'when openssh-client is present in the APK database' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1client000001==
        P:openssh-client
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'passes, because openssh-client is not a banned package' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # openssh-client as a version stream must also pass. ApkDb matches digit-led
  # suffixes, so if openssh-client were still banned this would be flagged too —
  # this guards the un-ban across the version-stream matcher, not just the exact
  # name.
  context 'when openssh-client is present as a version stream (P:openssh-client-9.7)' do
    before do
      File.write(apk_db_path, <<~APK_DB)
        C:Q1client000002==
        P:openssh-client-9.7
        V:9.7_p1-r0
        A:x86_64

      APK_DB
    end

    it 'passes, because openssh-client is not a banned package' do
      expect(run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # These eight names are banned by oval:org.RemoteAccessServices:obj:6 but were
  # missing from the profile's banned_remote_packages default, so the profile
  # passed images oscap fails. One named row per package: the subtest name tells
  # you which package regressed, and the failure message prints the APK db entry
  # that was scanned.
  describe 'packages banned by the OVAL that must be flagged' do
    [
      { name: 'cockpit-bridge', version: '320-r0' },
      { name: 'nfs-utils',      version: '2.6.4-r0' },
      { name: 'samba',          version: '4.19.4-r0' },
      { name: 'samba-server',   version: '4.19.4-r0' },
      { name: 'samba-client',   version: '4.19.4-r0' },
      { name: 'samba-common',   version: '4.19.4-r0' },
      { name: 'rsh',            version: '0.17-r0' },
      { name: 'telnet',         version: '0.17-r0' }
    ].each_with_index do |pkg, idx|
      context "when #{pkg[:name]} is present in the APK database" do
        let(:apk_db_entry) do
          # Synthetic, distinct-per-row checksum (derived from the row index) —
          # ApkDb matches only P: lines, never C: lines, but a distinct value
          # per fixture avoids implying the rows are otherwise identical.
          <<~APK_DB
            C:Q1#{format('%012d', idx)}==
            P:#{pkg[:name]}
            V:#{pkg[:version]}
            A:x86_64

          APK_DB
        end

        before { File.write(apk_db_path, apk_db_entry) }

        it "fails, because #{pkg[:name]} is a banned remote-access package" do
          result = run_control('oval:org.RemoteAccessServices:def:1', rootfs: rootfs)
          expect(result).to be_failing,
            "expected #{pkg[:name]} to be flagged as a banned package, but the " \
            "control passed. APK db content scanned:\n#{apk_db_entry}"
        end
      end
    end
  end
end
