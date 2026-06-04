require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe 'aslr-runtime-check' do
  let(:rootfs) { Dir.mktmpdir }
  after { FileUtils.rm_rf(rootfs) }

  context 'when /proc/sys/kernel/randomize_va_space contains 2' do
    before do
      FileUtils.mkdir_p(File.join(rootfs, 'proc/sys/kernel'))
      File.write(File.join(rootfs, 'proc/sys/kernel/randomize_va_space'), "2\n")
    end

    it 'passes' do
      expect(run_control('aslr-runtime-check', rootfs: rootfs)).to be_passing
    end
  end

  context 'when /proc/sys/kernel/randomize_va_space contains 0' do
    before do
      FileUtils.mkdir_p(File.join(rootfs, 'proc/sys/kernel'))
      File.write(File.join(rootfs, 'proc/sys/kernel/randomize_va_space'), "0\n")
    end

    it 'fails' do
      expect(run_control('aslr-runtime-check', rootfs: rootfs)).to be_failing
    end
  end

  context 'when .runtime_capture/aslr_setting contains 2 (no /proc file)' do
    before do
      FileUtils.mkdir_p(File.join(rootfs, '.runtime_capture'))
      File.write(File.join(rootfs, '.runtime_capture/aslr_setting'), "2\n")
    end

    it 'passes' do
      expect(run_control('aslr-runtime-check', rootfs: rootfs)).to be_passing
    end
  end

  context 'when .runtime_capture/aslr_setting contains 1 (no /proc file)' do
    before do
      FileUtils.mkdir_p(File.join(rootfs, '.runtime_capture'))
      File.write(File.join(rootfs, '.runtime_capture/aslr_setting'), "1\n")
    end

    it 'fails' do
      expect(run_control('aslr-runtime-check', rootfs: rootfs)).to be_failing
    end
  end

  context 'when neither /proc/sys/kernel/randomize_va_space nor .runtime_capture/aslr_setting exists' do
    it 'is skipped' do
      expect(run_control('aslr-runtime-check', rootfs: rootfs)).to be_skipped
    end
  end
end
