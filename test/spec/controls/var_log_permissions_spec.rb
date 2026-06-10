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
      FileUtils.chmod(0o755, var_log_path)
      skip 'requires root or passwordless sudo' unless chown_root(var_log_path)
      expect(run_control('oval:org.varlog:def:2', rootfs: rootfs)).to be_passing
    end
  end

  context 'when /var/log is owned by a non-root user' do
    it 'fails' do
      FileUtils.chmod(0o755, var_log_path)
      make_non_root_owned(var_log_path)
      expect(run_control('oval:org.varlog:def:2', rootfs: rootfs)).to be_failing
    end
  end

  context 'when /var/log is owned root:root but has mode 0777' do
    it 'fails' do
      FileUtils.chmod(0o777, var_log_path)
      skip 'requires root or passwordless sudo' unless chown_root(var_log_path)
      expect(run_control('oval:org.varlog:def:2', rootfs: rootfs)).to be_failing
    end
  end

  # /var/log absent: the control asserts the directory `should exist`, so an
  # absent path must be a finding. The top-level before mkdir_p's it, so this
  # context removes it. No root/sudo needed — the existence assertion fails
  # before any owner/group/mode check.
  context 'when /var/log is absent' do
    before { FileUtils.rm_rf(var_log_path) }

    it 'fails' do
      expect(run_control('oval:org.varlog:def:2', rootfs: rootfs)).to be_failing
    end
  end
end
