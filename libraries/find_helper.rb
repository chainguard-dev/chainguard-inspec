# Copyright (c) 2026 Chainguard Inc.
# SPDX-License-Identifier: Apache-2.0
#
# libraries/find_helper.rb
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Helper for locating a usable `find` binary inside container images
# (particularly distroless images) that may or may not ship with GNU
# find or the complete set of busybox commands.
#
# Context:
#   - Many distroless images intentionally omit a shell and standard
#     utilities like `find`, which the Chainguard InSpec profile relies
#     on for certain controls.
#   - To work around this we sometimes inject a statically linked
#     busybox into the image via a docker bind mount, and busybox
#     provides a `find` applet, but the busybox binary is not also
#     injected at `/usr/bin/find` or elsewhere in the $PATH

# Explicit top-level anchor: define the module as a constant on Object
# so it is visible from any InSpec evaluation context (ProfileContext,
# ControlEvalContext, etc.) rather than being scoped to whichever
# anonymous class instance_eval'd this file.
module ::FindHelper

  FIND_PATHS = ['/usr/bin/find', '/bin/find']
  BUSYBOX_PATHS = ['/usr/bin/busybox', '/bin/busybox']

  # Paths where a shell might live that is *secretly* busybox. We only
  # check common shell locations because checking arbitrary binaries
  # would be expensive and error-prone. /bin/sh is the canonical POSIX
  # shell path and the most common injection target.
  SHELL_PATHS    = ['/bin/sh', '/usr/bin/sh']

  # Returns a command string suitable for prefixing a find invocation,
  # e.g. "find" or "/usr/bin/busybox find". Returns nil when no usable
  # find implementation can be located in the target image.
  #
  # The `context` argument is the InSpec control/test context (pass
  # `self` from within a control) so that we can use InSpec resources
  # like `file` and `command` against the target rather than the host
  # running InSpec.
  def self.find_command(context)
    # Tier 1: prefer a real `find` binary when present.
    real_find = FIND_PATHS.find { |p| context.file(p).exist? }
    return real_find if real_find

    # Tier 2: fall back to an invocation of the busybox find applet
    busybox = BUSYBOX_PATHS.find { |p| context.file(p).exist? }
    return "#{busybox} find" if busybox

    # Tier 3: busybox masquerading as /bin/sh (no busybox binary
    # reachable at a conventional path). We use the ash `exec -a`
    # builtin to re-exec the shell binary with argv[0] set to "find",
    # which triggers busybox's applet dispatcher by name.
    hidden_shell = detect_busybox_shell(context)
    if hidden_shell && busybox_shell_has_find?(context, hidden_shell)
      return %(#{hidden_shell} -c 'exec -a find "$0" "$@"' #{hidden_shell})
    end

    # Tier 4: a real `find` resolvable on PATH but not at FIND_PATHS (e.g.
    # /usr/local/bin/find, or a Nix profile). Reached only after the busybox
    # tiers miss, so the shell running the probe is either a real /bin/sh
    # (`command -v find` prints the path) or a busybox without the find applet
    # (`command -v find` exits non-zero -> nil, the correct outcome). It can
    # therefore never perturb the docker:// busybox scan, which Tier 3 owns.
    find_on_path(context)
  end

  # The absolute path of a `find` resolvable on the target's PATH, or nil.
  # Uses the POSIX `command -v` builtin (no external binary required). We only
  # accept an absolute path: a successful probe at the Tier 4 call site implies
  # a real (non-busybox) shell with a genuine find binary, so it returns a path;
  # a bare name (shell builtin/applet) is rejected since a real find applet
  # would already have been claimed by the busybox tiers.
  def self.find_on_path(context)
    result = context.command('command -v find')
    return nil unless result.exit_status.to_i.zero?

    path = result.stdout.to_s.strip
    path.start_with?('/') ? path : nil
  end

  # Determine whether a shell at one of SHELL_PATHS is actually
  # busybox. Returns the shell path, or nil.
  def self.detect_busybox_shell(context)
    SHELL_PATHS.each do |shell_path|
      next unless context.file(shell_path).exist?
      return shell_path if shell_is_busybox?(context, shell_path)
    end
    nil
  end

  # Determine whether the binary at `path` is actually busybox, by
  # invoking it in a way that triggers its self-identification banner.
  #
  # Busybox prints a line like:
  #   BusyBox v1.36.1 (2024-01-15 ...) multi-call binary.
  # to stdout or stderr when invoked with --help, or with no arguments
  # when dispatched as the `busybox` applet. For safety we use --help
  # because it's a no-op for most applets (won't try to read input,
  # spawn a shell, etc.).
  def self.shell_is_busybox?(context, shell_path)
    result = context.command("#{shell_path} --help")
    combined = "#{result.stdout}\n#{result.stderr}"
    combined.include?('BusyBox') && combined.include?('multi-call')
  end

  # Verify that a busybox-backed shell supports both:
  #   (a) the `find` applet being compiled in, and
  #   (b) the `exec -a` builtin we rely on for argv[0] rewriting.
  #
  # We probe both in a single shell invocation to minimize round
  # trips. If `exec -a` is unsupported (very old busybox, pre ~1.30),
  # ash reports a usage error and we bail out.
  def self.busybox_shell_has_find?(context, shell_path)
    # Use `exec -a` to ask busybox to list its applets. If exec -a
    # works AND find is in the applet list, stdout contains "find"
    # on its own line.
    probe = %(exec -a busybox "$0" --list)
    result = context.command(%(#{shell_path} -c '#{probe}' #{shell_path}))
    return false unless result.exit_status.to_i.zero?

    result.stdout.split("\n").map(&:strip).include?('find')
  end
end
