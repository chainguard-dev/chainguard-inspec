require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'json'

RSpec.describe 'oval:org.NoUsers:def:1' do
  let(:rootfs) { Dir.mktmpdir }
  let(:etc_dir) { File.join(rootfs, 'etc') }

  after { FileUtils.rm_rf(rootfs) }

  before { FileUtils.mkdir_p(etc_dir) }

  # Write a minimal /etc/shadow (required to exist by the control)
  def write_shadow(*usernames)
    content = usernames.map { |u| "#{u}:!:19000:0:99999:7:::" }.join("\n") + "\n"
    File.write(File.join(etc_dir, 'shadow'), content)
  end

  context 'when passwd has only root and system accounts (nologin shells) before/at nobody' do
    before do
      File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
        root:x:0:0:root:/root:/sbin/nologin
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        nobody:x:65534:65534:nobody:/:/sbin/nologin
      PASSWD
      write_shadow('root', 'daemon', 'nobody')
    end

    it 'passes' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when a user from the default allowed_extra_users list appears after nobody' do
    # 'nonroot' is in the default allowed_extra_users input in inspec.yml
    before do
      File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
        root:x:0:0:root:/root:/sbin/nologin
        nobody:x:65534:65534:nobody:/:/sbin/nologin
        nonroot:x:65532:65532:nonroot:/home/nonroot:/bin/bash
      PASSWD
      write_shadow('root', 'nobody', 'nonroot')
    end

    it 'passes' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_passing
    end
  end

  context 'when an unexpected interactive user appears after nobody' do
    before do
      File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
        root:x:0:0:root:/root:/sbin/nologin
        nobody:x:65534:65534:nobody:/:/sbin/nologin
        hacker:x:1337:1337:Unauthorized User:/home/hacker:/bin/bash
      PASSWD
      write_shadow('root', 'nobody', 'hacker')
    end

    it 'fails' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_failing
    end
  end

  context 'when a user after nobody is declared in /etc/apko.json accounts.users' do
    before do
      File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
        root:x:0:0:root:/root:/sbin/nologin
        nobody:x:65534:65534:nobody:/:/sbin/nologin
        builduser:x:1001:1001:Build User:/home/builduser:/bin/bash
      PASSWD
      write_shadow('root', 'nobody', 'builduser')
      # apko.json declares builduser with matching UID — control accepts it
      File.write(File.join(etc_dir, 'apko.json'), JSON.generate(
        'accounts' => {
          'users' => [{ 'username' => 'builduser', 'uid' => 1001 }]
        }
      ))
    end

    it 'passes' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_passing
    end
  end
end
