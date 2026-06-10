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

  # Regression test for shell-escaping of the find(1) path argument.
  # A real scan may point rootfs at an image extracted to a directory whose
  # name contains a space. The control builds command("find <lib_path> ...")
  # with lib_path = File.join(rootfs, 'usr/lib'). Without shell-escaping the
  # interpolated path, the shell word-splits it, find scans a nonexistent
  # directory and returns nothing, and the control passes vacuously — silently
  # auditing ZERO libraries. With escaping it scans the real directory and
  # flags the non-root-owned file. We assert failure to prove the scan happened.
  context 'when the rootfs path contains a space' do
    let(:prefix) { 'has space' }
    let(:usr_lib_path) { File.join(rootfs, prefix, 'usr/lib') }
    let(:libbad_path) { File.join(usr_lib_path, 'libbad.so') }

    before { File.write(libbad_path, "ELF stub\n") }

    it 'still scans libraries (path shell-escaped) and flags the non-root file' do
      skip 'only meaningful when not running as root' if Process.uid == 0
      # File created by non-root user is already non-root-owned — no chown needed.
      result = run_control('oval:org.LibraryPermissions:def:2', rootfs: rootfs, rootfs_prefix: prefix)
      expect(result).to be_failing
    end
  end

  # /usr/lib absent: the control asserts the directory `should exist`, so an
  # absent path must be a finding. The file enumeration is guarded by
  # `if lib_dir.exist?`, so it stays clean (no find against a missing dir). The
  # top-level before mkdir_p's the dir, so this context removes it. No root/sudo
  # needed — the existence assertion fails before any ownership check.
  context 'when /usr/lib is absent' do
    before { FileUtils.rm_rf(usr_lib_path) }

    it 'fails' do
      expect(run_control('oval:org.LibraryPermissions:def:2', rootfs: rootfs)).to be_failing
    end
  end

  # /usr/lib present but empty: find returns no entries, so the only assertion is
  # the evidence "scanned 0 file(s)" (entries.length >= 0) and the control passes
  # vacuously — there are no files to check ownership of. This is locked in
  # deliberately: it documents the legitimate empty-dir pass so a future
  # regression where find silently returns nothing (and thus skips all ownership
  # checks) is distinguishable from this intended behavior, rather than reading
  # as an accidental all-clear. No root/sudo needed. The top-level before already
  # mkdir_p's an empty usr/lib; this context just adds no lib files.
  context 'when /usr/lib exists but is empty' do
    it 'passes' do
      expect(run_control('oval:org.LibraryPermissions:def:2', rootfs: rootfs)).to be_passing
    end
  end
end
