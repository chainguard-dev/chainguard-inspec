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

  # When apko.json is present, an account after nobody is accepted only if its
  # uid matches the apko-declared uid OR it uses an allowed (nologin) shell.
  # Here builduser is declared in apko.json but with a DIFFERENT uid than the
  # passwd entry, and its shell is /bin/bash (not an allowed shell), so neither
  # acceptance clause applies and the account must be flagged. /bin/bash is
  # deliberate: an allowed shell would be accepted regardless of the uid, masking
  # the uid-mismatch branch under test.
  context 'when an apko-declared user appears with a UID that does not match apko.json' do
    before do
      File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
        root:x:0:0:root:/root:/sbin/nologin
        nobody:x:65534:65534:nobody:/:/sbin/nologin
        builduser:x:9999:9999:Build User:/home/builduser:/bin/bash
      PASSWD
      write_shadow('root', 'nobody', 'builduser')
      File.write(File.join(etc_dir, 'apko.json'), JSON.generate(
        'accounts' => { 'users' => [{ 'username' => 'builduser', 'uid' => 1001 }] }
      ))
    end

    it 'fails' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # A structurally malformed /etc/passwd entry (wrong field count) must be a
  # failing finding, not silently dropped: a truncated line such as
  # "evil:x:0:0" has < 7 fields, so the previous `next unless parts.length >= 7`
  # discarded it — letting a crafted UID-0 entry evade evaluation entirely.
  context 'when /etc/passwd has a structurally malformed (truncated) entry after nobody' do
    before do
      File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
        root:x:0:0:root:/root:/sbin/nologin
        nobody:x:65534:65534:nobody:/:/sbin/nologin
        evil:x:0:0
      PASSWD
      write_shadow('root', 'nobody', 'evil')
    end

    it 'fails (cannot evaluate account correctness against a malformed entry)' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_failing
    end
  end

  # A valid entry whose trailing field is legitimately empty (empty shell) still
  # has 7 colon-separated fields and must NOT be flagged as malformed. This
  # guards the field-count check against naive String#split, which drops trailing
  # empty fields ("svc:x:1:1:svc:/home/svc:".split(':') => 6 elements). Placed
  # before nobody so it is not also subject to the post-nobody account check.
  context 'when a system passwd entry has an empty trailing field but the right field count' do
    before do
      File.write(File.join(etc_dir, 'passwd'), <<~PASSWD)
        root:x:0:0:root:/root:/sbin/nologin
        svc:x:1:1:svc:/home/svc:
        nobody:x:65534:65534:nobody:/:/sbin/nologin
      PASSWD
      write_shadow('root', 'svc', 'nobody')
    end

    it 'passes' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_passing
    end
  end

  # /etc/passwd absent: the control asserts the passwd file `should exist`, so an
  # absent file must be a finding (be_failing). Shadow is written so that passwd
  # is the only thing missing, isolating this to the passwd-existence path.
  context 'when /etc/passwd is absent' do
    before { write_shadow('root', 'nobody') }

    it 'fails' do
      expect(run_control('oval:org.NoUsers:def:1', rootfs: rootfs)).to be_failing
    end
  end
end
