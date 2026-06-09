require 'spec_helper'
require_relative '../../../libraries/find_helper'

# Pure-Ruby unit tests for the FindHelper module. FindHelper resolves how to
# invoke find(1) against a target that may lack `find` or ship busybox. Every
# probe is duck-typed against a `context` that responds to
# `context.file(path).exist?` and `context.command(str).{stdout,stderr,exit_status}`,
# so these tests use plain RSpec doubles — no cinc-auditor / Docker.
#
# These tests pin the *current* behavior of working code (added as coverage,
# not to drive a change).
#
# Why this matters: the busybox tiers are the load-bearing path for the
# docker:// transport scan (tools/cinc-chainguard-docker-transport.sh), where
# file()/command() resolve INSIDE a distroless target that has no `find` and a
# static busybox bind-mounted at /bin/sh — i.e. Tier 3. These tests cover the
# tier-selection and predicate logic; they do NOT prove the busybox invocation
# strings work against a real busybox (the exact-string assertions just mirror
# the source). That end-to-end check is a follow-up integration test driving the
# docker-transport flow against a real distroless image — see CLAUDE.local.md.
RSpec.describe FindHelper do
  # Build a context double.
  #   files:    maps a path to whether file(path).exist? is true; any path not
  #             listed is treated as absent.
  #   commands: maps an exact command string to a result with the given
  #             {stdout:, stderr:, exit_status:} (each defaulted).
  def context_double(files: {}, commands: {})
    ctx = double('context')
    allow(ctx).to receive(:file) do |path|
      double("file:#{path}", exist?: files.fetch(path, false))
    end
    allow(ctx).to receive(:command) do |cmd|
      attrs = commands.fetch(cmd, {})
      double("command:#{cmd}",
             stdout: attrs.fetch(:stdout, ''),
             stderr: attrs.fetch(:stderr, ''),
             exit_status: attrs.fetch(:exit_status, 1))
    end
    ctx
  end

  # Command strings FindHelper builds for a given shell path.
  def help_command(shell)
    "#{shell} --help"
  end

  def list_command(shell)
    %(#{shell} -c 'exec -a busybox "$0" --list' #{shell})
  end

  def find_invocation(shell)
    %(#{shell} -c 'exec -a find "$0" "$@"' #{shell})
  end

  # Representative command output fixtures.
  let(:busybox_help) do
    "BusyBox v1.36.1 (2024-01-15 12:00:00 UTC) multi-call binary.\n" \
      "Usage: busybox [function [arguments]...]\n"
  end
  let(:non_busybox_help) do
    "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\n" \
      "Usage:\tbash [option] ...\n"
  end
  let(:applet_list_with_find)    { "[\nash\ncat\nfind\ngrep\nls\nsh\n" }
  let(:applet_list_without_find) { "[\nash\ncat\ngrep\nls\nsh\n" }

  describe '.find_command' do
    context 'Tier 1: a real find binary is present' do
      it 'returns /usr/bin/find when it exists' do
        ctx = context_double(files: { '/usr/bin/find' => true })
        expect(FindHelper.find_command(ctx)).to eq('/usr/bin/find')
      end

      it 'returns /bin/find when only it exists' do
        ctx = context_double(files: { '/bin/find' => true })
        expect(FindHelper.find_command(ctx)).to eq('/bin/find')
      end

      it 'prefers /usr/bin/find over /bin/find (FIND_PATHS order)' do
        ctx = context_double(files: { '/usr/bin/find' => true, '/bin/find' => true })
        expect(FindHelper.find_command(ctx)).to eq('/usr/bin/find')
      end

      it 'wins over a present busybox binary (Tier 1 precedence)' do
        ctx = context_double(files: { '/usr/bin/find' => true, '/usr/bin/busybox' => true })
        expect(FindHelper.find_command(ctx)).to eq('/usr/bin/find')
      end
    end

    context 'Tier 2: no real find, a busybox binary is present' do
      it 'returns "<busybox> find" for /usr/bin/busybox' do
        ctx = context_double(files: { '/usr/bin/busybox' => true })
        expect(FindHelper.find_command(ctx)).to eq('/usr/bin/busybox find')
      end

      it 'returns "<busybox> find" for /bin/busybox when only it exists' do
        ctx = context_double(files: { '/bin/busybox' => true })
        expect(FindHelper.find_command(ctx)).to eq('/bin/busybox find')
      end

      it 'prefers /usr/bin/busybox over /bin/busybox (BUSYBOX_PATHS order)' do
        ctx = context_double(files: { '/usr/bin/busybox' => true, '/bin/busybox' => true })
        expect(FindHelper.find_command(ctx)).to eq('/usr/bin/busybox find')
      end

      it 'short-circuits at Tier 2 without probing any shell (Tier 2 beats Tier 3)' do
        # A busybox binary AND a /bin/sh are both present; Tier 2 must win and
        # return before any shell-detection command() is ever issued.
        ctx = context_double(files: { '/usr/bin/busybox' => true, '/bin/sh' => true })
        expect(ctx).not_to receive(:command)
        expect(FindHelper.find_command(ctx)).to eq('/usr/bin/busybox find')
      end
    end

    context 'Tier 3: no real find, no busybox binary, a hidden busybox shell' do
      it 'returns the exec-a find invocation for a busybox /bin/sh that has the find applet' do
        ctx = context_double(
          files: { '/bin/sh' => true },
          commands: {
            help_command('/bin/sh') => { stdout: busybox_help },
            list_command('/bin/sh') => { stdout: applet_list_with_find, exit_status: 0 }
          }
        )
        expect(FindHelper.find_command(ctx)).to eq(find_invocation('/bin/sh'))
      end
    end

    context 'Tier 3 negatives' do
      it 'returns nil when the shell exists but --help is not busybox' do
        ctx = context_double(
          files: { '/bin/sh' => true, '/usr/bin/sh' => true },
          commands: {
            help_command('/bin/sh')     => { stdout: non_busybox_help },
            help_command('/usr/bin/sh') => { stdout: non_busybox_help }
          }
        )
        expect(FindHelper.find_command(ctx)).to be_nil
      end

      it 'returns nil when the shell is busybox but the find applet is absent' do
        ctx = context_double(
          files: { '/bin/sh' => true },
          commands: {
            help_command('/bin/sh') => { stdout: busybox_help },
            list_command('/bin/sh') => { stdout: applet_list_without_find, exit_status: 0 }
          }
        )
        expect(FindHelper.find_command(ctx)).to be_nil
      end

      it 'returns nil when the busybox shell does not support exec -a (non-zero exit)' do
        ctx = context_double(
          files: { '/bin/sh' => true },
          commands: {
            help_command('/bin/sh') => { stdout: busybox_help },
            # Old busybox: exec -a usage error -> non-zero exit, even though
            # garbage stdout might mention find.
            list_command('/bin/sh') => { stdout: 'find', stderr: 'exec: invalid option', exit_status: 1 }
          }
        )
        expect(FindHelper.find_command(ctx)).to be_nil
      end
    end

    context 'nothing usable is present' do
      it 'returns nil' do
        expect(FindHelper.find_command(context_double)).to be_nil
      end
    end

    context 'Tier 4: no find at FIND_PATHS, no busybox, but find is on PATH' do
      it 'returns the absolute path reported by `command -v find`' do
        ctx = context_double(
          commands: { 'command -v find' => { stdout: "/usr/local/bin/find\n", exit_status: 0 } }
        )
        expect(FindHelper.find_command(ctx)).to eq('/usr/local/bin/find')
      end

      it 'returns nil when `command -v find` fails (busybox without the find applet: exit 127)' do
        ctx = context_double(
          commands: { 'command -v find' => { stdout: '', exit_status: 127 } }
        )
        expect(FindHelper.find_command(ctx)).to be_nil
      end
    end

    context 'earlier tiers short-circuit before the PATH probe' do
      it 'runs no command at all when Tier 1 resolves' do
        ctx = context_double(files: { '/usr/bin/find' => true })
        expect(ctx).not_to receive(:command)
        expect(FindHelper.find_command(ctx)).to eq('/usr/bin/find')
      end

      it 'never probes `command -v find` once Tier 3 resolves' do
        ctx = context_double(
          files: { '/bin/sh' => true },
          commands: {
            help_command('/bin/sh') => { stdout: busybox_help },
            list_command('/bin/sh') => { stdout: applet_list_with_find, exit_status: 0 }
          }
        )
        expect(ctx).not_to receive(:command).with('command -v find')
        expect(FindHelper.find_command(ctx)).to eq(find_invocation('/bin/sh'))
      end
    end
  end

  describe '.detect_busybox_shell' do
    it 'returns the first SHELL_PATHS entry that exists and is busybox' do
      ctx = context_double(
        files: { '/bin/sh' => true },
        commands: { help_command('/bin/sh') => { stdout: busybox_help } }
      )
      expect(FindHelper.detect_busybox_shell(ctx)).to eq('/bin/sh')
    end

    it 'skips an existing non-busybox shell and finds a later busybox one' do
      ctx = context_double(
        files: { '/bin/sh' => true, '/usr/bin/sh' => true },
        commands: {
          help_command('/bin/sh')     => { stdout: non_busybox_help },
          help_command('/usr/bin/sh') => { stdout: busybox_help }
        }
      )
      expect(FindHelper.detect_busybox_shell(ctx)).to eq('/usr/bin/sh')
    end

    it 'prefers /bin/sh over /usr/bin/sh when both are busybox (SHELL_PATHS order)' do
      ctx = context_double(
        files: { '/bin/sh' => true, '/usr/bin/sh' => true },
        commands: {
          help_command('/bin/sh')     => { stdout: busybox_help },
          help_command('/usr/bin/sh') => { stdout: busybox_help }
        }
      )
      expect(FindHelper.detect_busybox_shell(ctx)).to eq('/bin/sh')
    end

    it 'returns nil when no shell path exists' do
      expect(FindHelper.detect_busybox_shell(context_double)).to be_nil
    end

    it 'returns nil when a shell exists but is not busybox' do
      ctx = context_double(
        files: { '/bin/sh' => true },
        commands: { help_command('/bin/sh') => { stdout: non_busybox_help } }
      )
      expect(FindHelper.detect_busybox_shell(ctx)).to be_nil
    end
  end

  describe '.shell_is_busybox?' do
    it 'is true when the banner is on stdout' do
      ctx = context_double(commands: { help_command('/bin/sh') => { stdout: busybox_help } })
      expect(FindHelper.shell_is_busybox?(ctx, '/bin/sh')).to be true
    end

    it 'is true when the banner is on stderr (busybox prints --help to stderr)' do
      ctx = context_double(commands: { help_command('/bin/sh') => { stdout: '', stderr: busybox_help } })
      expect(FindHelper.shell_is_busybox?(ctx, '/bin/sh')).to be true
    end

    it 'is false for a non-busybox shell' do
      ctx = context_double(commands: { help_command('/bin/sh') => { stdout: non_busybox_help } })
      expect(FindHelper.shell_is_busybox?(ctx, '/bin/sh')).to be false
    end

    it 'is false when only one of the two banner tokens is present' do
      ctx = context_double(commands: { help_command('/bin/sh') => { stdout: 'BusyBox-like but not the binary' } })
      expect(FindHelper.shell_is_busybox?(ctx, '/bin/sh')).to be false
    end
  end

  describe '.busybox_shell_has_find?' do
    it 'is true when exec -a exits zero and the applet list includes find' do
      ctx = context_double(
        commands: { list_command('/bin/sh') => { stdout: applet_list_with_find, exit_status: 0 } }
      )
      expect(FindHelper.busybox_shell_has_find?(ctx, '/bin/sh')).to be true
    end

    it 'is false when exec -a exits zero but the applet list lacks find' do
      ctx = context_double(
        commands: { list_command('/bin/sh') => { stdout: applet_list_without_find, exit_status: 0 } }
      )
      expect(FindHelper.busybox_shell_has_find?(ctx, '/bin/sh')).to be false
    end

    it 'is false when exec -a is unsupported (non-zero exit), even if stdout mentions find' do
      ctx = context_double(
        commands: { list_command('/bin/sh') => { stdout: 'find', exit_status: 2 } }
      )
      expect(FindHelper.busybox_shell_has_find?(ctx, '/bin/sh')).to be false
    end

    it 'matches the find applet despite surrounding whitespace (lines are stripped)' do
      ctx = context_double(
        commands: { list_command('/bin/sh') => { stdout: "ash\n   find  \nls\n", exit_status: 0 } }
      )
      expect(FindHelper.busybox_shell_has_find?(ctx, '/bin/sh')).to be true
    end

    it 'requires an exact applet line, not a substring (rejects findfs/findmnt decoys)' do
      # Real busybox ships `find` AND separate `findfs`/`findmnt` applets. A
      # substring match would wrongly accept a busybox that has findfs but not
      # find, then build an invocation against the wrong applet. The match must
      # be on the whole (stripped) line.
      ctx = context_double(
        commands: { list_command('/bin/sh') => { stdout: "ash\nfindfs\nfindmnt\nls\nsh\n", exit_status: 0 } }
      )
      expect(FindHelper.busybox_shell_has_find?(ctx, '/bin/sh')).to be false
    end
  end

  describe '.find_on_path' do
    it 'returns the absolute path when `command -v find` succeeds' do
      ctx = context_double(
        commands: { 'command -v find' => { stdout: "/usr/local/bin/find\n", exit_status: 0 } }
      )
      expect(FindHelper.find_on_path(ctx)).to eq('/usr/local/bin/find')
    end

    it 'returns nil when `command -v find` exits non-zero (no find, or no shell)' do
      ctx = context_double(
        commands: { 'command -v find' => { stdout: '', exit_status: 127 } }
      )
      expect(FindHelper.find_on_path(ctx)).to be_nil
    end

    it 'returns nil when the output is not an absolute path (e.g. a builtin/applet name)' do
      # Some shells print a bare name for a non-binary; we require a real path.
      ctx = context_double(
        commands: { 'command -v find' => { stdout: "find\n", exit_status: 0 } }
      )
      expect(FindHelper.find_on_path(ctx)).to be_nil
    end
  end
end
