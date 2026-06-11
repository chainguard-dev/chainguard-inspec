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

  # Gating (deterministic): no sysctl path and no runtime-capture file, with
  # allow_host_aslr_fallback at its default (false), so the only_if guard trips
  # and the control is skipped. This is the clean, environment-independent
  # assertion that the default input value disables the host fallback.
  context 'when neither /proc/sys/kernel/randomize_va_space nor .runtime_capture/aslr_setting exists' do
    it 'is skipped' do
      expect(run_control('aslr-runtime-check', rootfs: rootfs)).to be_skipped
    end
  end

  # Source precedence (deterministic): when BOTH the rootfs-relative sysctl path
  # and the runtime-capture file are present, the control must read the sysctl
  # path first (AslrCheck.rb ~:48-51). Here sysctl=0 (non-compliant) and
  # capture=2 (compliant); a result of be_failing proves /proc won. If precedence
  # were reversed it would read 2 and pass, so this assertion bites.
  context 'when both the sysctl path and the runtime capture file are present' do
    before do
      FileUtils.mkdir_p(File.join(rootfs, 'proc/sys/kernel'))
      File.write(File.join(rootfs, 'proc/sys/kernel/randomize_va_space'), "0\n")
      FileUtils.mkdir_p(File.join(rootfs, '.runtime_capture'))
      File.write(File.join(rootfs, '.runtime_capture/aslr_setting'), "2\n")
    end

    it 'reads the sysctl value (0), not the capture value (2)' do
      expect(run_control('aslr-runtime-check', rootfs: rootfs)).to be_failing
    end
  end

  # Host fallback (NON-deterministic — do not pin pass/fail). With
  # allow_host_aslr_fallback enabled and no fixture sources, the control reads
  # the host/container's absolute /proc/sys/kernel/randomize_va_space (an
  # absolute path that is NOT remapped to the rootfs — see memory
  # docker-mode-rootfs-fixture-remap), so the compliance result depends on the
  # runner kernel. We assert only that the fallback flips the only_if guard: the
  # control is no longer skipped because the host path exists.
  context 'when allow_host_aslr_fallback is enabled with no fixture sources' do
    it 'is not skipped (host /proc path satisfies the only_if guard)' do
      result = run_control('aslr-runtime-check', rootfs: rootfs,
                           allow_host_aslr_fallback: 'true')
      expect(result).not_to be_skipped
    end
  end
end
