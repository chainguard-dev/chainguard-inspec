require 'spec_helper'

# Static guard that control paths stay relative to the `rootfs` input.
#
# Controls resolve the scan target through
# `rootfs = ENV['ROOTFS_DIR'] || input('rootfs')` and then build paths with
# `File.join(rootfs, 'etc/ssl/certs')` and similar. A control that instead
# hardcodes an absolute path literal reads the machine running the scanner,
# not the image under test. The failure is quiet and asymmetric: CI runs
# these specs in docker mode, where the auditor image usually lacks the
# path, so the check passes; a developer running direct mode (host-installed
# auditor) against a host that *has* the file either gets a spurious
# failure, or worse, a spurious pass that silently misses a real finding.
#
# This spec reads control sources directly (no cinc-auditor / Docker
# needed), following test/spec/metadata_consistency_spec.rb's pattern.
#
# Detection rule (static, regex-based -- this is not a Ruby parser):
#
#   A line is examined unless it is a full-line comment (`line.strip`
#   starts with '#'). Any trailing `# ...` comment on an examined line is
#   stripped first, using a small quote-parity scan (see
#   strip_trailing_comment) so that a '#' opening string interpolation
#   (`"...#{...}..."`) is not mistaken for a comment.
#
#   What remains is scanned for a single- or double-quoted string literal
#   whose *entire* content is a pure absolute path: a leading '/' followed
#   only by path-safe characters (word characters, '.', '-', '/') up to the
#   closing quote of the same kind.
#
#   This deliberately DOES catch a hardcoded absolute path literal used in
#   expression position, e.g.:
#     host_sysctl_path = '/proc/sys/kernel/randomize_va_space'
#
#   This deliberately does NOT catch:
#     - path fragments joined to rootfs, e.g. `File.join(rootfs, 'etc/ssl')`
#       -- no leading '/', so the literal never matches.
#     - comments, full-line or trailing, including ones that legitimately
#       mention an absolute path for the reader's benefit (see
#       controls/CaBundleHashTest.rb's Java truststore comment, which spells
#       out /etc/ssl/certs/java/cacerts in prose).
#     - message/describe strings that happen to start with a path but
#       continue with prose, punctuation, interpolation, or a space, e.g.
#       `describe "/etc/apk/repositories file contents (#{...} lines)"` --
#       the space and '(' break the path-safe character class, so the
#       quoted content is not a *pure* path and does not match.
#
#   This does NOT catch an absolute path assembled at runtime from more than
#   one literal or from interpolation (e.g. `'/' + 'etc/ssl'`, or
#   `"/etc/#{name}"` where the '/etc/' part is itself hardcoded) -- those
#   aren't a single self-contained quoted literal. No control does this
#   today (verified by inspection during Step 1); if one ever does, this
#   spec needs to be extended rather than trusted to catch it silently.
RSpec.describe 'control paths stay relative to the rootfs input' do
  controls_dir = File.expand_path('../../controls', __dir__)
  control_files = Dir.glob(File.join(controls_dir, '*.rb')).sort

  # Absolute path literals allowed to bypass the rootfs input, keyed by
  # control filename and the exact literal string. This is the review
  # checkpoint: a new deliberate host read cannot be added to a control
  # without also adding an entry here, so it shows up in the diff.
  allowlist = {
    'AslrCheck.rb' => [
      # Deliberate host /proc read, used only as an explicit fallback when
      # neither rootfs-relative ASLR path (the rootfs-mounted /proc, or the
      # runtime-capture file) is available -- e.g. an overlay scan where
      # /proc isn't mounted. Gated behind the `allow_host_aslr_fallback`
      # input, which defaults to `false`, so a normal scan never reads the
      # host's own kernel setting.
      '/proc/sys/kernel/randomize_va_space'
    ]
  }.freeze

  # Matches a quoted string literal whose entire content is a pure absolute
  # path: leading '/', then only path-safe characters, then the same quote
  # that opened it. Group 2 is the path (without the surrounding quotes).
  absolute_path_literal = %r{(['"])(/[\w./-]+)\1}

  it 'finds control files to check' do
    expect(control_files).not_to be_empty
  end

  # Strip a trailing `# ...` comment from a line of Ruby source, tracking
  # quote state so a '#' inside a string (in particular, the '#' that opens
  # "#{...}" interpolation) is not mistaken for the start of a comment.
  def strip_trailing_comment(line)
    in_squote = false
    in_dquote = false
    line.each_char.with_index do |char, index|
      case char
      when "'"
        in_squote = !in_squote unless in_dquote
      when '"'
        in_dquote = !in_dquote unless in_squote
      when '#'
        return line[0...index] unless in_squote || in_dquote
      end
    end
    line
  end

  # Returns [line_number, literal] pairs for every non-allowlisted absolute
  # path literal found in expression position in the file at `path`.
  def find_violations(path, allowed_literals, absolute_path_literal)
    violations = []
    File.readlines(path).each_with_index do |line, index|
      next if line.strip.start_with?('#')

      code = strip_trailing_comment(line)
      code.scan(absolute_path_literal) do |_quote, literal|
        violations << [index + 1, literal] unless allowed_literals.include?(literal)
      end
    end
    violations
  end

  control_files.each do |path|
    name = File.basename(path)

    context "controls/#{name}" do
      it 'uses no absolute path literals that are not derived from rootfs' do
        allowed_literals = allowlist.fetch(name, [])
        violations = find_violations(path, allowed_literals, absolute_path_literal)

        messages = violations.map do |line, literal|
          "controls/#{name}:#{line}: absolute path literal #{literal.inspect} -- " \
            'an absolute path literal audits the machine running the scanner ' \
            'instead of the image under test. This passes in docker mode (the ' \
            'auditor image usually lacks the path) and fails, or worse silently ' \
            'passes on the wrong file, in direct mode. Derive the path from the ' \
            'rootfs input (File.join(rootfs, ...)) instead, or if this is a ' \
            'deliberate, input-gated host read, add it to the allowlist in ' \
            'test/spec/rootfs_relativity_spec.rb.'
        end

        expect(violations).to be_empty, messages.join("\n")
      end
    end
  end
end
