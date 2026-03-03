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
end
