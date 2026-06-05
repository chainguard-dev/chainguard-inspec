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
end
