require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe 'oval:org.example:def:3' do
  let(:rootfs) { Dir.mktmpdir }
  let(:shadow_dir) { File.join(rootfs, 'etc') }
  let(:shadow_path) { File.join(shadow_dir, 'shadow') }

  before { FileUtils.mkdir_p(shadow_dir) }
  after { FileUtils.rm_rf(rootfs) }

  context 'when all shadow entries have locked passwords (! or *)' do
    before do
      File.write(shadow_path, <<~SHADOW)
        root:!:19000:0:99999:7:::
        daemon:*:18000:0:99999:7:::
        nobody:!:18000:0:99999:7:::
      SHADOW
    end

    it 'passes' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_passing
    end
  end

  context 'when an account has a real password hash' do
    before do
      # $6$ prefix indicates SHA-512 crypt — a real password hash
      File.write(shadow_path, <<~SHADOW)
        root:$6$salt$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:19000:0:99999:7:::
        daemon:*:18000:0:99999:7:::
        nobody:!:18000:0:99999:7:::
      SHADOW
    end

    it 'fails' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_failing
    end
  end

  # A structurally malformed /etc/shadow entry (wrong field count) must be a
  # failing finding. The InSpec `shadow` resource does its own parsing and may
  # silently skip such lines, so a malformed entry could otherwise evade the
  # password-hash check entirely — we cannot assert password correctness against
  # an unparseable file. Standard shadow = 9 colon-separated fields.
  context 'when /etc/shadow has a structurally malformed (truncated) entry' do
    before do
      # All passwords locked, but one line is truncated to 3 fields.
      File.write(shadow_path, <<~SHADOW)
        root:!:19000:0:99999:7:::
        truncated:!:19000
        nobody:!:18000:0:99999:7:::
      SHADOW
    end

    it 'fails (cannot assert password correctness against a malformed entry)' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_failing
    end
  end

  # A valid entry whose trailing fields are legitimately empty still has 9
  # colon-separated fields and must NOT be flagged as malformed (guards against
  # naive String#split dropping trailing empty fields).
  context 'when a shadow entry has empty trailing fields but the right field count' do
    before do
      File.write(shadow_path, <<~SHADOW)
        root:!:19000:0:99999:7:::
        nobody:*:::::::
      SHADOW
    end

    it 'passes' do
      expect(run_control('oval:org.example:def:3', rootfs: rootfs)).to be_passing
    end
  end
end
