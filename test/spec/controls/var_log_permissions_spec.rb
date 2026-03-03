require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'shellwords'

RSpec.describe 'oval:org.varlog:def:2' do
  let(:rootfs) { Dir.mktmpdir }
  let(:var_log_path) { File.join(rootfs, 'var/log') }

  before { FileUtils.mkdir_p(var_log_path) }

  after { cleanup_with_root_files(rootfs) }

  context 'when /var/log is owned root:root with mode 0755' do
    it 'passes' do
      skip 'requires root or passwordless sudo' unless chown_root(var_log_path)
      FileUtils.chmod(0o755, var_log_path)
      expect(run_control('oval:org.varlog:def:2', rootfs: rootfs)).to be_passing
    end
  end

  context 'when /var/log is owned by the current non-root user' do
    it 'fails' do
      skip 'only meaningful when not running as root' if Process.uid == 0
      # After mkdir_p the directory is already owned by the current (non-root) user
      FileUtils.chmod(0o755, var_log_path)
      expect(run_control('oval:org.varlog:def:2', rootfs: rootfs)).to be_failing
    end
  end

  context 'when /var/log is owned root:root but has mode 0777' do
    it 'fails' do
      skip 'requires root or passwordless sudo' unless chown_root(var_log_path)
      FileUtils.chmod(0o777, var_log_path)
      expect(run_control('oval:org.varlog:def:2', rootfs: rootfs)).to be_failing
    end
  end
end
