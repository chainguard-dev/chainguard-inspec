require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'rbconfig'
require 'open3'
require_relative '../../../tools/release-version'

# Unit tests for tools/release-version.rb, the single implementation of the
# three version operations the release workflows perform.
#
# Two things here are deliberate rather than incidental:
#
#   * The metadata read/write cases run against the repo's **real** inspec.yml,
#     not a hand-written stand-in. A synthetic fixture would be written from the
#     same mental model as the regex it is testing, so a wrong assumption about
#     the file's shape would reproduce in the fixture and the test would pass.
#   * The `next` cases build a **real git repository** and let `git log` produce
#     the records the parser consumes. The record framing (\x1f between fields,
#     \x1e between commits, multi-line bodies) is precisely what a synthetic
#     fixture would get wrong in the same direction as the code.
RSpec.describe ReleaseVersion do
  let(:repo_root) { File.expand_path('../../..', __dir__) }
  let(:tool_path) { File.join(repo_root, 'tools', 'release-version.rb') }
  let(:metadata_path) { File.join(repo_root, 'inspec.yml') }

  def commit(message, sha: 'abcdef1234567890')
    ReleaseVersion::Commit.new(sha: sha, message: message)
  end

  describe '.parse' do
    [
      ['a plain X.Y.Z version',            '1.2.3',        [1, 2, 3]],
      ['a v-prefixed tag name',            'v1.2.3',       [1, 2, 3]],
      ['surrounding whitespace',           "  1.2.3\n",    [1, 2, 3]],
      ['multi-digit components',           '10.20.30',     [10, 20, 30]],
      ['a zero version',                   '0.0.0',        [0, 0, 0]],
      ['rejects a two-component version',  '1.2',          :error],
      ['rejects a prerelease suffix',      '1.2.3-rc1',    :error],
      ['rejects a build suffix',           '1.2.3+build4', :error],
      ['rejects a four-component version', '1.2.3.4',      :error],
      ['rejects non-numeric input',        'latest',       :error],
      ['rejects an empty string',          '',             :error],
      ['rejects nil',                      nil,            :error]
    ].each do |name, input, want|
      it name do
        if want == :error
          expect { described_class.parse(input) }
            .to raise_error(ReleaseVersion::Error, /not a X\.Y\.Z version/)
        else
          expect(described_class.parse(input)).to eq(want),
            "parse(#{input.inspect}): want #{want.inspect}"
        end
      end
    end
  end

  describe '.classify' do
    [
      ['a bare feature is a minor bump',            "feat: add the java truststore arm",        :minor],
      ['a scoped feature is a minor bump',          "feat(controls): add the arm",              :minor],
      ['a bang feature is a major bump',            "feat!: drop the pinned hash input",        :major],
      ['a scoped bang feature is a major bump',     "feat(controls)!: drop the input",          :major],
      ['a bang fix is a major bump',                "fix!: rename the rootfs input",            :major],
      ['a bang on any type is a major bump',        "chore!: drop ruby 3.1 support",            :major],
      ['a BREAKING CHANGE footer is a major bump',  "fix: tighten\n\nBREAKING CHANGE: input renamed", :major],
      ['a BREAKING-CHANGE footer is a major bump',  "fix: tighten\n\nBREAKING-CHANGE: input renamed", :major],
      ['a bare fix is a patch bump',                "fix: correct the sidecar basename",        :patch],
      ['a scoped chore is a patch bump',            "chore(deps): bump zizmor-action",          :patch],
      ['a docs commit is a patch bump',             "docs: describe the sidecar",               :patch],
      ['a merge commit is a patch bump',            "Merge pull request #90 from chainguard-dev/x", :patch],
      ['a non-conventional subject is a patch bump', "tidy up the makefile",                    :patch],
      # Negative cases for the two patterns most likely to over-match.
      ['prose mentioning a breaking change is a patch bump',
       "fix: note that this would be a BREAKING CHANGE: if applied", :patch],
      ['a footer-like line mid-sentence is a patch bump',
       "fix: tighten\n\nthis is not a BREAKING CHANGE: footer", :patch],
      ['a type merely starting with feat is a patch bump',
       "feature: not a conventional type",                        :patch]
    ].each do |name, message, want|
      it name do
        got = described_class.classify(commit(message))
        expect(got).to eq(want),
          "classify(#{message.inspect}): want #{want.inspect}, got #{got.inspect}"
      end
    end
  end

  describe '.bump' do
    [
      ['major zeroes minor and patch', [1, 2, 3], :major, [2, 0, 0]],
      ['minor zeroes patch',           [1, 2, 3], :minor, [1, 3, 0]],
      ['patch increments patch',       [1, 2, 3], :patch, [1, 2, 4]],
      ['major from a zero version',    [0, 0, 0], :major, [1, 0, 0]]
    ].each do |name, triple, level, want|
      it name do
        expect(described_class.bump(triple, level)).to eq(want),
          "bump(#{triple.inspect}, #{level.inspect}): want #{want.inspect}"
      end
    end

    it 'rejects an unknown level' do
      expect { described_class.bump([1, 2, 3], :nope) }
        .to raise_error(ReleaseVersion::Error, /unknown bump level/)
    end
  end

  describe '.newer?' do
    [
      ['a patch increment is newer',            '1.0.5',  '1.0.4', true],
      ['a minor increment is newer',            '1.1.0',  '1.0.4', true],
      ['a major increment is newer',            '2.0.0',  '1.9.9', true],
      ['an equal version is not newer',         '1.0.4',  '1.0.4', false],
      ['a lower patch is not newer',            '1.0.3',  '1.0.4', false],
      ['a lower minor is not newer',            '1.0.9',  '1.1.0', false],
      ['a lower major is not newer',            '0.9.9',  '1.0.0', false],
      # The cases string comparison gets backwards.
      ['10 is newer than 9 in the patch field', '1.0.10', '1.0.9', true],
      ['9 is not newer than 10 in the patch field', '1.0.9', '1.0.10', false],
      ['10 is newer than 9 in the minor field', '1.10.0', '1.9.0', true],
      # A tag name is accepted directly, since that is what the caller has.
      ['a v-prefixed baseline is handled',      '1.1.0',  'v1.0.4', true],
      ['a v-prefixed candidate is handled',     'v1.1.0', '1.0.4',  true]
    ].each do |name, candidate, baseline, want|
      it name do
        got = described_class.newer?(candidate, baseline)
        expect(got).to eq(want),
          "newer?(#{candidate.inspect}, #{baseline.inspect}): want #{want}, got #{got}"
      end
    end
  end

  describe '.derive' do
    [
      ['patch when no commit is a feature or breaking',
       '1.0.4', ['fix: a', 'docs: b', 'chore: c'], '1.0.5', :patch],
      ['minor when any commit is a feature',
       '1.0.4', ['fix: a', 'feat: b', 'docs: c'], '1.1.0', :minor],
      ['minor when the only feature is the last commit',
       '1.0.4', ['fix: a', 'docs: b', 'feat: c'], '1.1.0', :minor],
      ['major when any commit is breaking, even among features',
       '1.0.4', ['feat: a', 'fix!: b', 'feat: c'], '2.0.0', :major],
      ['major when the breaking commit is last',
       '1.0.4', ['fix: a', 'feat: b', 'feat!: c'], '2.0.0', :major],
      ['a single feature commit',
       '0.0.4', ['feat: a'], '0.1.0', :minor]
    ].each do |name, current, messages, want_version, want_bump|
      it name do
        decision = described_class.derive(
          current_version: current,
          commits: messages.map { |m| commit(m) }
        )
        expect([decision.version, decision.bump]).to eq([want_version, want_bump]),
          "derive(#{current.inspect}, #{messages.inspect}): " \
          "want #{want_version}/#{want_bump}, got #{decision.version}/#{decision.bump} " \
          "(reason: #{decision.reason})"
      end
    end

    it 'names the triggering commit in the reason so a reviewer can check it' do
      decision = described_class.derive(
        current_version: '1.0.4',
        commits: [
          commit('fix: unrelated', sha: '1111111111'),
          commit('feat: the interesting one', sha: 'deadbeefcafe')
        ]
      )
      expect(decision.reason).to include('deadbeef', 'feat: the interesting one'),
        "reason did not name the triggering commit: #{decision.reason.inspect}"
    end

    it 'reports the commit count when nothing implies more than a patch' do
      decision = described_class.derive(
        current_version: '1.0.4',
        commits: [commit('fix: a'), commit('docs: b')]
      )
      expect(decision.reason).to include('2 commit(s)')
    end

    it 'keeps the reason to a single line for $GITHUB_OUTPUT' do
      decision = described_class.derive(
        current_version: '1.0.4',
        commits: [commit("feat: multi\n\nwith a body\nspanning lines")]
      )
      expect(decision.reason.lines.length).to eq(1),
        "reason spans #{decision.reason.lines.length} lines: #{decision.reason.inspect}"
    end

    it 'refuses to derive a version when there is nothing to release' do
      expect { described_class.derive(current_version: '1.0.4', commits: []) }
        .to raise_error(ReleaseVersion::Error, /nothing to release/)
    end

    it 'rejects a malformed current version rather than guessing' do
      expect { described_class.derive(current_version: 'latest', commits: [commit('fix: a')]) }
        .to raise_error(ReleaseVersion::Error, /not a X\.Y\.Z version/)
    end
  end

  describe '.read_metadata_version' do
    it "reads the repo's real inspec.yml" do
      version = described_class.read_metadata_version(File.read(metadata_path))
      expect(version).to match(/\A\d+\.\d+\.\d+\z/),
        "inspec.yml version #{version.inspect} is not a bare X.Y.Z value"
    end

    it 'ignores an indented version: key, such as one inside inputs:' do
      content = "name: p\ninputs:\n  - name: x\n    version: 9.9.9\nversion: 1.2.3\n"
      expect(described_class.read_metadata_version(content)).to eq('1.2.3')
    end

    it 'raises when no version: key is present' do
      expect { described_class.read_metadata_version("name: p\n") }
        .to raise_error(ReleaseVersion::Error, /no `version:` key/)
    end
  end

  describe '.write_metadata_version' do
    it "round-trips through the repo's real inspec.yml" do
      original = File.read(metadata_path)
      updated = described_class.write_metadata_version(original, '9.8.7')

      expect(described_class.read_metadata_version(updated)).to eq('9.8.7')
      expect(updated.lines.length).to eq(original.lines.length),
        'rewriting version: changed the line count of inspec.yml'
      expect(updated).to include('name: chainguard_stig_v3r2'),
        'rewriting version: disturbed other metadata keys'
    end

    it 'leaves the real inspec.yml byte-identical when already at that version' do
      original = File.read(metadata_path)
      current = described_class.read_metadata_version(original)
      expect(described_class.write_metadata_version(original, current)).to eq(original)
    end

    it 'does not rewrite an indented version: key' do
      content = "inputs:\n  - name: x\n    version: 9.9.9\nversion: 1.2.3\n"
      updated = described_class.write_metadata_version(content, '2.0.0')
      expect(updated).to include('    version: 9.9.9')
      expect(updated).to include("\nversion: 2.0.0")
    end

    it 'rejects a malformed version before touching the content' do
      expect { described_class.write_metadata_version("version: 1.2.3\n", 'v1.2') }
        .to raise_error(ReleaseVersion::Error, /not a X\.Y\.Z version/)
    end

    it 'raises rather than partially rewriting a file with two version: keys' do
      expect { described_class.write_metadata_version("version: 1.2.3\nversion: 4.5.6\n", '2.0.0') }
        .to raise_error(ReleaseVersion::Error, /expected one `version:` key, found 2/)
    end

    it 'raises when there is no version: key to rewrite' do
      expect { described_class.write_metadata_version("name: p\n", '2.0.0') }
        .to raise_error(ReleaseVersion::Error, /no `version:` key/)
    end
  end

  # --- CLI -----------------------------------------------------------------
  #
  # These drive the script the workflows actually invoke, so the option parsing,
  # the exit statuses and the $GITHUB_OUTPUT formatting are covered rather than
  # only the pure logic underneath them.
  describe 'the command line interface' do
    def run_tool(*args, chdir:)
      out, err, status = Open3.capture3(RbConfig.ruby, tool_path, *args, chdir: chdir)
      [out, err, status.exitstatus]
    end

    context 'get and set against a copy of the real inspec.yml' do
      around do |example|
        Dir.mktmpdir('release-version') do |dir|
          FileUtils.cp(metadata_path, File.join(dir, 'inspec.yml'))
          @dir = dir
          example.run
        end
      end

      it 'get prints the recorded version and exits 0' do
        out, _err, code = run_tool('get', chdir: @dir)
        expect([out.strip, code]).to eq([ReleaseVersion.read_metadata_version(File.read(metadata_path)), 0])
      end

      it 'set rewrites the version, and get reads back what set wrote' do
        _out, err, code = run_tool('set', '2.5.9', chdir: @dir)
        expect(code).to eq(0), "set failed: #{err}"

        out, _err, get_code = run_tool('get', chdir: @dir)
        expect([out.strip, get_code]).to eq(['2.5.9', 0])
      end

      it 'set is idempotent and says so' do
        run_tool('set', '2.5.9', chdir: @dir)
        _out, err, code = run_tool('set', '2.5.9', chdir: @dir)
        expect(code).to eq(0)
        expect(err).to include('already at 2.5.9')
      end

      it 'set rejects a malformed version and leaves the file untouched' do
        before_content = File.read(File.join(@dir, 'inspec.yml'))
        _out, err, code = run_tool('set', '1.2', chdir: @dir)

        expect(code).to eq(1), "expected a failing exit status, got #{code}"
        expect(err).to include('not a X.Y.Z version')
        expect(File.read(File.join(@dir, 'inspec.yml'))).to eq(before_content)
      end

      it 'set without a version argument fails' do
        _out, err, code = run_tool('set', chdir: @dir)
        expect(code).to eq(1)
        expect(err).to include('set requires a X.Y.Z version')
      end

      # Both workflows validate a version through this subcommand rather than
      # each embedding its own regex, so these rows are the only definition of
      # what the release pipeline will accept.
      [
        ['accepts a bare X.Y.Z',              '1.1.0',    '1.1.0', 0],
        ['normalises a v-prefixed version',   'v1.1.0',   '1.1.0', 0],
        ['rejects a two-component version',   '1.1',      nil,     1],
        ['rejects a prerelease suffix',       '1.1.0-rc1', nil,    1],
        ['rejects a version with a space',    '1.1.0 x',  nil,     1],
        ['rejects an empty version',          '',         nil,     1],
        ['rejects a shell metacharacter',     '1.1.0;id', nil,     1]
      ].each do |name, input, want_out, want_code|
        it "validate #{name}" do
          out, err, code = run_tool('validate', input, chdir: @dir)
          expect(code).to eq(want_code),
            "validate #{input.inspect}: want exit #{want_code}, got #{code} (out=#{out.inspect} err=#{err.inspect})"
          expect(out.strip).to eq(want_out) if want_out
        end
      end

      it 'validate without an argument fails' do
        _out, err, code = run_tool('validate', chdir: @dir)
        expect(code).to eq(1)
        expect(err).to include('validate requires a X.Y.Z version')
      end

      it 'an unknown subcommand exits 2 with usage' do
        _out, err, code = run_tool('frobnicate', chdir: @dir)
        expect(code).to eq(2)
        expect(err).to include('Usage: release-version.rb')
      end

      it 'a missing metadata file is a clean error, not a backtrace' do
        _out, err, code = run_tool('get', '--metadata', 'nope.yml', chdir: @dir)
        expect(code).to eq(1)
        expect(err).to start_with('error:')
      end
    end

    context 'next, against commits a real git produced' do
      # Builds a throwaway repo so `git log`'s own output drives the parser.
      def git!(dir, *args)
        out, err, status = Open3.capture3(
          'git',
          '-c', 'user.email=test@example.com',
          '-c', 'user.name=Test',
          '-c', 'commit.gpgsign=false',
          '-c', 'tag.gpgsign=false',
          *args,
          chdir: dir
        )
        raise "git #{args.join(' ')} failed: #{err}#{out}" unless status.success?

        out
      end

      def commit!(dir, message)
        File.write(File.join(dir, 'file.txt'), message)
        git!(dir, 'add', 'file.txt')
        git!(dir, 'commit', '-m', message)
      end

      around do |example|
        Dir.mktmpdir('release-version-git') do |dir|
          git!(dir, 'init', '--initial-branch=main', '.')
          FileUtils.cp(metadata_path, File.join(dir, 'inspec.yml'))
          git!(dir, 'add', 'inspec.yml')
          git!(dir, 'commit', '-m', 'chore: initial')
          @dir = dir
          example.run
        end
      end

      it 'derives a patch bump from fixes since the last tag' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, 'fix: correct the sidecar basename')
        commit!(@dir, 'docs: explain it')

        out, err, code = run_tool('next', chdir: @dir)
        expect(code).to eq(0), "next failed: #{err}"
        expect(out.strip).to eq('1.0.5')
        expect(err).to include('last tag v1.0.4')
      end

      it 'derives a minor bump from a feature since the last tag' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, 'fix: a')
        commit!(@dir, 'feat: verify the java truststore')

        out, _err, code = run_tool('next', chdir: @dir)
        expect([out.strip, code]).to eq(['1.1.0', 0])
      end

      # The framing test: a multi-line body must not be mistaken for extra
      # commits, and a BREAKING CHANGE footer in a body must still be seen.
      it 'reads a BREAKING CHANGE footer out of a multi-paragraph commit body' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, "fix: tighten the check\n\nA body paragraph.\n\nBREAKING CHANGE: the rootfs input was renamed.\n")

        out, err, code = run_tool('next', chdir: @dir)
        expect([out.strip, code]).to eq(['2.0.0', 0]),
          "want 2.0.0 from the footer, got #{out.strip.inspect} (#{err})"
      end

      it 'counts a multi-paragraph commit once' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, "fix: one\n\nparagraph two\n\nparagraph three\n")

        _out, err, code = run_tool('next', chdir: @dir)
        expect(code).to eq(0)
        expect(err).to include('1 commit(s)'),
          "multi-paragraph body was split into several commits: #{err}"
      end

      it 'ignores commits from before the last tag' do
        commit!(@dir, 'feat!: ancient breaking change')
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, 'fix: only this one counts')

        out, _err, code = run_tool('next', chdir: @dir)
        expect([out.strip, code]).to eq(['1.0.5', 0]),
          'a pre-tag breaking change leaked into the derivation'
      end

      it 'picks the newest tag, not the most recently created one' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, 'fix: a')
        git!(@dir, 'tag', 'v1.0.10')
        commit!(@dir, 'fix: b')
        git!(@dir, 'tag', 'v1.0.9')
        commit!(@dir, 'fix: c')

        out, err, code = run_tool('next', chdir: @dir)
        expect(code).to eq(0), err
        expect(err).to include('last tag v1.0.10'),
          "version sort picked the wrong tag: #{err}"
      end

      it 'ignores tags that are not bare vX.Y.Z' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, 'fix: a')
        git!(@dir, 'tag', 'v2.0.0-rc1')

        _out, err, code = run_tool('next', chdir: @dir)
        expect(code).to eq(0), err
        expect(err).to include('last tag v1.0.4'),
          "a prerelease tag was treated as the last release: #{err}"
      end

      it 'starts from 0.0.0 in a repo with no release tag' do
        commit!(@dir, 'feat: the first feature')

        out, err, code = run_tool('next', chdir: @dir)
        expect(code).to eq(0), err
        expect(out.strip).to eq('0.1.0')
        expect(err).to include('no release tag yet')
      end

      it 'fails when there is nothing to release' do
        git!(@dir, 'tag', 'v1.0.4')

        _out, err, code = run_tool('next', chdir: @dir)
        expect(code).to eq(1)
        expect(err).to include('nothing to release')
      end

      it '--current-version overrides the tag as the base' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, 'fix: a')

        out, _err, code = run_tool('next', '--current-version', '3.2.16', chdir: @dir)
        expect([out.strip, code]).to eq(['3.2.17', 0])
      end

      # The backstop against an abandoned prerelease PR being reopened and
      # merged out of order. It has to hold against the tags git actually
      # reports, not against a list a fixture made up.
      context 'assert-newer' do
        [
          ['accepts the next patch',        '1.0.5',  0],
          ['accepts a minor bump',          '1.1.0',  0],
          ['accepts a major bump',          '2.0.0',  0],
          ['rejects the current version',   '1.0.4',  1],
          ['rejects an earlier version',    '1.0.3',  1],
          ['rejects a malformed version',   '1.0',    1]
        ].each do |name, version, want_code|
          it name do
            git!(@dir, 'tag', 'v1.0.4')
            _out, err, code = run_tool('assert-newer', version, chdir: @dir)
            expect(code).to eq(want_code),
              "assert-newer #{version} against v1.0.4: want exit #{want_code}, got #{code} (#{err})"
            expect(err).to include('does not come after') if want_code == 1 && version != '1.0'
          end
        end

        it 'compares numerically against the newest tag, not lexically' do
          git!(@dir, 'tag', 'v1.0.9')
          commit!(@dir, 'fix: a')
          git!(@dir, 'tag', 'v1.0.10')

          _out, err, code = run_tool('assert-newer', '1.0.9', chdir: @dir)
          expect(code).to eq(1),
            "1.0.9 was accepted over v1.0.10 — string ordering leaked in (#{err})"
          expect(err).to include('v1.0.10')
        end

        it 'accepts any version in a repo with no release tag' do
          _out, err, code = run_tool('assert-newer', '0.0.1', chdir: @dir)
          expect(code).to eq(0), err
          expect(err).to include('no release tag yet')
        end

        it 'requires a version argument' do
          _out, err, code = run_tool('assert-newer', chdir: @dir)
          expect(code).to eq(1)
          expect(err).to include('assert-newer requires a X.Y.Z version')
        end
      end

      it '--github-output emits parseable key=value lines on stdout' do
        git!(@dir, 'tag', 'v1.0.4')
        commit!(@dir, 'feat: verify the java truststore')

        out, err, code = run_tool('next', '--github-output', chdir: @dir)
        expect(code).to eq(0), err

        parsed = out.lines.map(&:chomp).reject(&:empty?).to_h { |l| l.split('=', 2) }
        expect(parsed['version']).to eq('1.1.0')
        expect(parsed['bump']).to eq('minor')
        expect(parsed['reason']).to include('feat: verify the java truststore')
        expect(out.lines.length).to eq(3),
          "expected exactly version/bump/reason on stdout, got: #{out.inspect}"
      end
    end
  end
end
