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
end
