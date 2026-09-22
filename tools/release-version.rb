#!/usr/bin/env ruby
#
# Copyright (c) 2026 Chainguard
# SPDX-License-Identifier: Apache-2.0

# Release version helper for the chainguard-inspec profile.
#
# `inspec.yml`'s `version:` is the profile version a scan report carries, and it
# is expected to equal the `vX.Y.Z` git tag of the release it was cut from. That
# invariant used to be maintained by hand and drifted: the profile sat at
# `0.0.4` while releases had reached `v1.0.4`, so a report's `version:` field
# could not be used to tell two materially different profiles apart (see
# docs/testing.md). The release workflows now maintain it mechanically, and this
# tool is the single implementation of the three operations they need:
#
#   get          - print the version recorded in inspec.yml
#   set          - rewrite that version (idempotent)
#   next         - derive the next version from conventional commits since the last tag
#   validate     - echo a version back, normalised, or fail
#   assert-newer - fail unless a version comes after the newest release tag
#
# It lives here rather than as shell embedded in the workflow YAML so the
# parsing, the bump arithmetic and the file rewrite are unit-testable; see
# test/spec/tools/release_version_spec.rb. The pure logic is deliberately
# separated from git and filesystem access: every method below that decides
# anything takes strings and returns values, and the CLI at the bottom is the
# only part that touches the outside world.

require 'optparse'

module ReleaseVersion
  # What `next` concluded, and the evidence for it. `reason` is kept to a single
  # line so it can be passed through $GITHUB_OUTPUT without heredoc delimiters.
  Decision = Struct.new(:version, :bump, :reason, keyword_init: true)

  # A commit as `next` considers it: the full message, because a breaking change
  # may be declared either in the subject (`feat!:`) or in a body footer.
  Commit = Struct.new(:sha, :message, keyword_init: true) do
    def subject
      message.to_s.lines.first.to_s.strip
    end

    def short_sha
      sha.to_s[0, 8]
    end
  end

  SEMVER = /\A(\d+)\.(\d+)\.(\d+)\z/

  # Conventional Commits: an optional scope, then `!` to mark a breaking change.
  BREAKING_SUBJECT = /\A[a-zA-Z]+(?:\([^)]*\))?!:/
  # The footer form. Both the hyphenated and spaced spellings are seen in the
  # wild; the spec allows `BREAKING CHANGE` and `BREAKING-CHANGE`.
  BREAKING_FOOTER = /^BREAKING[ -]CHANGE:/
  # A feature. `feat!:` is breaking and is matched above first, so this pattern
  # deliberately excludes `!`.
  FEATURE_SUBJECT = /\Afeat(?:\([^)]*\))?:/

  # The `version:` key at column 0 in inspec.yml. Anchored so it cannot match a
  # nested mapping key — the `inputs:` block below it is indented.
  METADATA_VERSION = /^version:[ \t]*(\S+)[ \t]*$/

  class Error < StandardError; end

  module_function

  # "1.2.3" -> [1, 2, 3]. A leading `v` is accepted so a tag name can be passed
  # directly; everything else is rejected rather than coerced, because silently
  # accepting "1.2" or "1.2.3-rc1" here would produce a wrong tag downstream.
  def parse(str)
    candidate = str.to_s.strip.sub(/\Av/, '')
    m = SEMVER.match(candidate)
    raise Error, "not a X.Y.Z version: #{str.inspect}" unless m

    [m[1].to_i, m[2].to_i, m[3].to_i]
  end

  def format_version(triple)
    triple.join('.')
  end

  # :major, :minor or :patch for a single commit.
  def classify(commit)
    return :major if BREAKING_SUBJECT.match?(commit.subject)
    return :major if BREAKING_FOOTER.match?(commit.message.to_s)
    return :minor if FEATURE_SUBJECT.match?(commit.subject)

    :patch
  end

  # Semver ordering. Compares component-by-component as integers, so 1.0.10
  # sorts after 1.0.9 — which string comparison gets backwards.
  def compare(a, b)
    parse(a) <=> parse(b)
  end

  # True when `candidate` is a strictly later release than `baseline`. Equality
  # is not "newer": re-releasing a version that already shipped is the mistake
  # this is here to catch, not an edge case to wave through.
  def newer?(candidate, baseline)
    compare(candidate, baseline).positive?
  end

  def bump(triple, level)
    x, y, z = triple
    case level
    when :major then [x + 1, 0, 0]
    when :minor then [x, y + 1, 0]
    when :patch then [x, y, z + 1]
    else raise Error, "unknown bump level: #{level.inspect}"
    end
  end

  # The next version implied by `commits` on top of `current_version`.
  #
  # The highest bump any single commit implies wins, and the reason names that
  # commit — so a derived version can be checked against history by a reviewer
  # rather than taken on trust.
  def derive(current_version:, commits:)
    raise Error, 'no commits since the last release, nothing to release' if commits.empty?

    trigger = commits.find { |c| classify(c) == :major } ||
              commits.find { |c| classify(c) == :minor }
    level = trigger ? classify(trigger) : :patch

    reason =
      if trigger
        "#{level} bump: #{trigger.short_sha} #{trigger.subject}"
      else
        "patch bump: #{commits.length} commit(s) since the last release, " \
        'none a feature or a breaking change'
      end

    Decision.new(
      version: format_version(bump(parse(current_version), level)),
      bump: level,
      reason: reason
    )
  end

  # The version recorded in an inspec.yml's text.
  def read_metadata_version(content)
    m = METADATA_VERSION.match(content)
    raise Error, 'no `version:` key found in profile metadata' unless m

    m[1]
  end

  # inspec.yml's text with `version:` set to `version`. Raises unless exactly one
  # `version:` key is present, so an unexpected file shape is a failure rather
  # than a partial rewrite.
  def write_metadata_version(content, version)
    parse(version) # reject a malformed version before touching the content
    matches = content.scan(METADATA_VERSION).length
    raise Error, 'no `version:` key found in profile metadata' if matches.zero?
    raise Error, "expected one `version:` key, found #{matches}" if matches > 1

    content.sub(METADATA_VERSION, "version: #{version}")
  end
end

# --- CLI -------------------------------------------------------------------
#
# Everything below is the only part that reads git, reads files or writes files.

module ReleaseVersion
  module CLI
    DEFAULT_METADATA = 'inspec.yml'

    # git log record separators: \x1f between fields, \x1e between records, so a
    # commit message containing blank lines survives round-tripping.
    LOG_FORMAT = '%H%x1f%B%x1e'

    module_function

    def git(*args)
      out = IO.popen(['git', *args], err: File::NULL, &:read)
      raise Error, "git #{args.join(' ')} failed" unless $?.success?

      out
    end

    # The newest `vX.Y.Z` tag, or nil if the repo has none.
    def last_tag
      tags = git('tag', '--list', 'v[0-9]*', '--sort=-v:refname').lines.map(&:strip).reject(&:empty?)
      tags.find { |t| t.match?(/\Av\d+\.\d+\.\d+\z/) }
    end

    def commits_since(tag)
      range = tag ? "#{tag}..HEAD" : 'HEAD'
      git('log', "--format=#{LOG_FORMAT}", range)
        .split("\x1e")
        .map { |record| record.sub(/\A\n/, '') }
        .reject { |record| record.strip.empty? }
        .map do |record|
          sha, message = record.split("\x1f", 2)
          Commit.new(sha: sha.to_s.strip, message: message.to_s)
        end
    end

    # Echo `version` back in bare X.Y.Z form, or fail. Exists so the workflows
    # share one definition of a well-formed version instead of each carrying
    # its own copy of the regex, and so a `v` typed into the dispatch form is
    # normalised rather than rejected or carried through into a `vv1.1.0` tag.
    def cmd_validate(version)
      puts ReleaseVersion.format_version(ReleaseVersion.parse(version))
      0
    end

    # Fail unless `version` comes after the newest release tag.
    #
    # A release should only ever move forward, and nothing else enforces that:
    # an abandoned prerelease PR keeps its `release` label, so reopening and
    # merging it would cut a release out of order, and the profile-version
    # assertion would pass because that branch's inspec.yml matches its own
    # branch name. This is the check that does not depend on anyone having
    # deleted the branch.
    #
    # Consequence worth knowing: this rules out cutting a patch on an older
    # line (1.0.5 once 1.1.0 exists). That suits a repo that releases only
    # from main, and is the thing to revisit if backport releases ever start.
    def cmd_assert_newer(version)
      candidate = ReleaseVersion.format_version(ReleaseVersion.parse(version))
      tag = last_tag

      if tag.nil?
        warn "no release tag yet, #{candidate} accepted as the first"
        return 0
      end

      unless ReleaseVersion.newer?(candidate, tag)
        raise Error, "#{candidate} does not come after the newest release #{tag}"
      end

      warn "#{candidate} comes after #{tag}"
      0
    end

    def cmd_get(metadata)
      puts ReleaseVersion.read_metadata_version(File.read(metadata))
      0
    end

    def cmd_set(metadata, version)
      original = File.read(metadata)
      updated = ReleaseVersion.write_metadata_version(original, version)
      File.write(metadata, updated) unless updated == original

      # Read back rather than trusting the write: this is the step the release
      # invariant rests on, and a silent no-op here would ship a mislabelled
      # profile.
      actual = ReleaseVersion.read_metadata_version(File.read(metadata))
      raise Error, "set #{version} but metadata reads #{actual}" unless actual == version

      warn(original == updated ? "#{metadata} already at #{version}" : "#{metadata} set to #{version}")
      0
    end

    def cmd_next(current_version, github_output)
      tag = last_tag
      base = current_version || (tag ? tag.sub(/\Av/, '') : '0.0.0')
      decision = ReleaseVersion.derive(current_version: base, commits: commits_since(tag))

      base_note = tag ? "last tag #{tag}" : 'no release tag yet, starting from 0.0.0'
      if github_output
        puts "version=#{decision.version}"
        puts "bump=#{decision.bump}"
        puts "reason=#{decision.reason} (#{base_note})"
      else
        puts decision.version
        warn "#{decision.reason} (#{base_note})"
      end
      0
    end

    def usage
      <<~USAGE
        Usage: release-version.rb <command> [options]

        Commands:
          get                 print the version recorded in the profile metadata
          set <X.Y.Z>         set that version (idempotent)
          next                derive the next version from commits since the last tag
          validate <X.Y.Z>    print the version in bare X.Y.Z form, or fail
          assert-newer <X.Y.Z>
                              fail unless the version comes after the newest tag

        Options:
          --metadata PATH     profile metadata file (default: #{DEFAULT_METADATA})
          --current-version V base `next` on V instead of the last git tag
          --github-output     `next` prints version=/bump=/reason= for $GITHUB_OUTPUT
      USAGE
    end

    def run(argv)
      metadata = DEFAULT_METADATA
      current_version = nil
      github_output = false

      parser = OptionParser.new do |o|
        o.on('--metadata PATH') { |v| metadata = v }
        o.on('--current-version V') { |v| current_version = v }
        o.on('--github-output') { github_output = true }
        o.on('-h', '--help') do
          puts usage
          return 0
        end
      end
      args = parser.parse(argv)

      case args.shift
      when 'get' then cmd_get(metadata)
      when 'set' then cmd_set(metadata, args.fetch(0) { raise Error, 'set requires a X.Y.Z version' })
      when 'next' then cmd_next(current_version, github_output)
      when 'validate'
        cmd_validate(args.fetch(0) { raise Error, 'validate requires a X.Y.Z version' })
      when 'assert-newer'
        cmd_assert_newer(args.fetch(0) { raise Error, 'assert-newer requires a X.Y.Z version' })
      else
        warn usage
        2
      end
    rescue Error, OptionParser::ParseError, Errno::ENOENT => e
      warn "error: #{e.message}"
      1
    end
  end
end

exit ReleaseVersion::CLI.run(ARGV) if __FILE__ == $PROGRAM_NAME
