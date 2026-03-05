require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'shellwords'

# NOTE: LibraryPermissionsTest.rb uses command("find <lib_path> -type f -print0") which
# runs on the audit host (direct mode) or inside the cinc-auditor container (Docker mode).
# Fixtures are regular files on the host filesystem; file ownership is what the control checks.

RSpec.describe 'oval:org.LibraryPermissions:def:2' do
  let(:rootfs) { Dir.mktmpdir }
  let(:usr_lib_path) { File.join(rootfs, 'usr/lib') }
  let(:libfoo_path) { File.join(usr_lib_path, 'libfoo.so') }
  let(:libbar_path) { File.join(usr_lib_path, 'libbar.so') }
  let(:libbad_path) { File.join(usr_lib_path, 'libbad.so') }

  before { FileUtils.mkdir_p(usr_lib_path) }
  after { cleanup_with_root_files(rootfs) }

  context 'when all files in /usr/lib are owned root:root' do
    before do
      File.write(libfoo_path, "ELF stub\n")
      File.write(libbar_path, "ELF stub\n")
    end

    it 'passes' do
      skip 'requires root or passwordless sudo' unless chown_root(libfoo_path) && chown_root(libbar_path)
      expect(run_control('oval:org.LibraryPermissions:def:2', rootfs: rootfs)).to be_passing
    end
  end

  context 'when a library in /usr/lib is owned by a non-root user' do
    before { File.write(libfoo_path, "ELF stub\n") }

    it 'fails' do
      skip 'only meaningful when not running as root' if Process.uid == 0
      # File created by non-root user is already non-root-owned — no chown needed
      expect(run_control('oval:org.LibraryPermissions:def:2', rootfs: rootfs)).to be_failing
    end
  end

  context 'when most libraries are root-owned but one is not' do
    before do
      File.write(libfoo_path, "ELF stub\n")
      File.write(libbar_path, "ELF stub\n")
      File.write(libbad_path, "ELF stub\n")
    end

    it 'fails' do
      # chown two files to root; leave or set libbad to non-root ownership
      skip 'requires root or passwordless sudo' unless chown_root(libfoo_path) && chown_root(libbar_path)
      make_non_root_owned(libbad_path)
      expect(run_control('oval:org.LibraryPermissions:def:2', rootfs: rootfs)).to be_failing
    end
  end
end
