module FixtureHelpers
  # Chown path to a non-root user (nobody/65534) if running as root,
  # otherwise a file/dir created by the current user is already non-root-owned.
  def make_non_root_owned(path)
    File.chown(65534, 65534, path) if Process.uid == 0
  end

  # Attempt to chown path to root:root.
  # Returns true if successful, false if neither direct nor sudo chown worked.
  def chown_root(path)
    if Process.uid == 0
      File.chown(0, 0, path)
      true
    else
      system("sudo -n chown root:root #{Shellwords.shellescape(path)} 2>/dev/null") == true
    end
  end

  # Cleanup a tmpdir that may contain root-owned files (e.g., after chown_root).
  # Tries to reset ownership first so that FileUtils.rm_rf can remove everything.
  def cleanup_with_root_files(path)
    return unless File.exist?(path)

    if Process.uid != 0
      system("sudo -n chown -R #{Process.uid}:#{Process.gid} #{Shellwords.shellescape(path)} 2>/dev/null")
    end
    FileUtils.rm_rf(path)
  end
end
