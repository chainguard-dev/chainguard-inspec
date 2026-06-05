require 'open3'
require 'tmpdir'
require 'json'
require 'fileutils'

# InspecRunner executes cinc-auditor (or inspec) against the chainguard-inspec profile
# and returns an InspecResult parsed from the JSON reporter output.
#
# Execution mode is chosen automatically in this priority order:
#   1. CINC_AUDITOR_BIN env var set → use that binary directly
#   2. cinc-auditor found in PATH → use directly
#   3. inspec found in PATH → use directly
#   4. docker in PATH + CINC_AUDITOR_IMAGE env var set → Docker mode
#   5. Otherwise → raise with a helpful error message
#
# All controls use ENV['ROOTFS_DIR'] || input('rootfs'). Tests always pass
# rootfs via --input (not ROOTFS_DIR) so the input mechanism is exercised.
class InspecRunner
  # Repository root (3 levels up from support/). The InSpec profile lives at the
  # repo root, but the root also holds non-profile content. In particular,
  # bundler vendors gems into test/vendor/bundle (e.g. CI's setup-ruby
  # bundler-cache), and cinc-auditor / InSpec 7.x discovers ZERO controls when
  # handed a profile path whose tree contains such vendored gem dirs (it loads
  # the profile metadata but no controls, exiting 0). To stay robust we evaluate
  # a staged copy that contains only the profile files — which also mirrors what
  # a consumer receives from a clean git checkout. See docs/testing.md.
  REPO_ROOT = File.expand_path('../../..', __dir__).freeze

  # The files/directories that make up the InSpec profile proper.
  PROFILE_ENTRIES = %w[inspec.yml controls libraries].freeze

  # Lazily assemble (once per process) a clean profile directory containing only
  # the profile files, and return its path. Cleaned up at process exit.
  def self.profile_path
    @profile_path ||= begin
      dir = Dir.mktmpdir('chainguard-inspec-profile')
      at_exit { FileUtils.rm_rf(dir) }
      PROFILE_ENTRIES.each do |entry|
        src = File.join(REPO_ROOT, entry)
        FileUtils.cp_r(src, dir) if File.exist?(src)
      end
      dir
    end
  end

  # rootfs_prefix lets a spec point the control's `rootfs` *input* at a subpath
  # beneath the mounted fixture, rather than at the fixture root. This mirrors a
  # real-world scan where an image is extracted to a local directory and rootfs
  # is set to that extracted path — which, unlike the fixed /fixture mount, may
  # contain spaces or other shell metacharacters. The fixture is still mounted
  # at /fixture (docker) / used in place (direct); only the rootfs input value
  # gains the prefix, so a spec can create fixtures under e.g. "has space/" and
  # exercise paths the control must shell-escape. Default nil = rootfs at root.
  def self.run(control_id, rootfs:, extra_inputs: {}, rootfs_prefix: nil)
    case detect_mode
    when :direct
      run_direct(control_id, rootfs: rootfs, extra_inputs: extra_inputs, rootfs_prefix: rootfs_prefix)
    when :docker
      run_docker(control_id, rootfs: rootfs, extra_inputs: extra_inputs, rootfs_prefix: rootfs_prefix)
    end
  end

  def self.detect_mode
    if ENV['CINC_AUDITOR_BIN']
      :direct
    elsif which('cinc-auditor')
      :direct
    elsif which('inspec')
      :direct
    elsif ENV['CINC_AUDITOR_IMAGE'] && which(docker_cmd.first)
      :docker
    else
      raise <<~MSG
        No cinc-auditor/inspec binary found and no Docker image configured.

        Options:
          1. Install cinc-auditor or inspec and ensure it is in PATH
          2. Set CINC_AUDITOR_BIN to the full path of the binary
          3. Set CINC_AUDITOR_IMAGE to a cinc-auditor Docker image name
             (docker must also be in PATH)
      MSG
    end
  end

  def self.auditor_bin
    if ENV['CINC_AUDITOR_BIN']
      ENV['CINC_AUDITOR_BIN']
    elsif which('cinc-auditor')
      'cinc-auditor'
    elsif which('inspec')
      'inspec'
    end
  end

  def self.which(cmd)
    ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? do |dir|
      f = File.join(dir, cmd)
      File.executable?(f) && !File.directory?(f)
    end
  end

  # Returns the docker command words as an array (supports DOCKER_CMD env var).
  # DOCKER_CMD can be set to e.g. "sudo docker" if the user needs privilege escalation
  # to reach the Docker socket. Defaults to "docker".
  def self.docker_cmd
    ENV.fetch('DOCKER_CMD', 'docker').split
  end

  def self.run_direct(control_id, rootfs:, extra_inputs:, rootfs_prefix: nil)
    tmpdir = Dir.mktmpdir
    begin
      json_path = File.join(tmpdir, 'result.json')
      cmd = build_direct_cmd(control_id, rootfs: rootfs, extra_inputs: extra_inputs,
                             rootfs_prefix: rootfs_prefix, json_path: json_path)
      stdout, stderr, process_status = Open3.capture3(*cmd)
      json_content = File.exist?(json_path) ? File.read(json_path) : nil
      result = InspecResult.new(control_id, json_content, stdout, stderr,
                                exit_status: process_status.exitstatus, cmd: cmd)
      debug_dump(result) if ENV['INSPEC_DEBUG']
      result
    ensure
      FileUtils.rm_rf(tmpdir)
    end
  end

  def self.run_docker(control_id, rootfs:, extra_inputs:, rootfs_prefix: nil)
    results_dir = Dir.mktmpdir
    begin
      FileUtils.chmod(0o777, results_dir)
      cmd = build_docker_cmd(control_id, rootfs: rootfs, extra_inputs: extra_inputs,
                             rootfs_prefix: rootfs_prefix, results_dir: results_dir)
      stdout, stderr, process_status = Open3.capture3(*cmd)
      json_path = File.join(results_dir, 'output.json')
      json_content = File.exist?(json_path) ? File.read(json_path) : nil
      result = InspecResult.new(control_id, json_content, stdout, stderr,
                                exit_status: process_status.exitstatus, cmd: cmd)
      debug_dump(result) if ENV['INSPEC_DEBUG']
      result
    ensure
      FileUtils.rm_rf(results_dir)
    end
  end

  def self.debug_dump(result)
    $stderr.puts "=== INSPEC_DEBUG: #{result.control_id} ==="
    $stderr.puts "CMD: #{result.cmd.join(' ')}"
    $stderr.puts "EXIT: #{result.exit_status}"
    $stderr.puts "STDOUT: #{result.stdout.empty? ? '(empty)' : result.stdout}"
    $stderr.puts "STDERR: #{result.stderr.empty? ? '(empty)' : result.stderr}"
    $stderr.puts "JSON: #{result.raw_json ? result.raw_json[0, 2000] : '(none)'}"
    $stderr.puts "=== status: #{result.status} ==="
  end

  def self.build_direct_cmd(control_id, rootfs:, extra_inputs:, json_path:, rootfs_prefix: nil)
    rootfs_value = rootfs_prefix ? File.join(rootfs, rootfs_prefix) : rootfs
    inputs = ["rootfs=#{rootfs_value}"] + extra_inputs.map { |k, v| "#{k}=#{v}" }
    cmd = [auditor_bin, 'exec', profile_path,
           '--controls', control_id,
           '--reporter', "json:#{json_path}",
           '--no-create-lockfile',
           '--input', *inputs]
    cmd
  end

  def self.build_docker_cmd(control_id, rootfs:, extra_inputs:, results_dir:, rootfs_prefix: nil)
    image = ENV['CINC_AUDITOR_IMAGE']
    # The fixture is bind-mounted at /fixture; the rootfs input points there, or
    # at a subpath beneath it when rootfs_prefix is set (see .run).
    rootfs_value = rootfs_prefix ? File.join('/fixture', rootfs_prefix) : '/fixture'
    inputs = ["rootfs=#{rootfs_value}"] + extra_inputs.map { |k, v| "#{k}=#{v}" }
    cmd = docker_cmd + ['run', '--rm',
           '--platform', 'linux/amd64',
           '--user', '0:0',
           '-v', "#{profile_path}:/profile:ro",
           '-v', "#{rootfs}:/fixture:ro",
           '-v', "#{results_dir}:/results",
           image,
           'exec', '/profile',
           '--controls', control_id,
           '--reporter', 'json:/results/output.json',
           '--no-create-lockfile',
           '--input', *inputs]
    cmd
  end
end

# InspecResult wraps the JSON output from cinc-auditor and provides #status.
class InspecResult
  attr_reader :stdout, :stderr, :raw_json, :control_id, :exit_status, :cmd

  def initialize(control_id, json_content, stdout, stderr, exit_status: nil, cmd: nil)
    @control_id = control_id
    @raw_json = json_content
    @stdout = stdout
    @stderr = stderr
    @exit_status = exit_status
    @cmd = cmd
    @data = json_content ? JSON.parse(json_content) : nil
  rescue JSON::ParserError
    @data = nil
  end

  # Returns :passed, :failed, or :skipped based on the control's results.
  def status
    return :error unless @data

    controls = @data.dig('profiles', 0, 'controls') || []
    control = controls.find { |c| c['id'] == @control_id }
    return :error unless control

    results = control['results'] || []

    if results.empty? || results.all? { |r| r['status'] == 'skipped' }
      :skipped
    elsif results.any? { |r| r['status'] == 'failed' || r['status'] == 'error' }
      :failed
    else
      :passed
    end
  end

  def to_s
    "InspecResult(#{@control_id}: #{status})"
  end

  def diagnostic
    lines = ["control: #{@control_id}", "status: #{status}"]
    lines << "exit_status: #{@exit_status}" unless @exit_status.nil?
    lines << "cmd: #{@cmd.join(' ')}" if @cmd
    lines << "stdout: #{@stdout.empty? ? '(empty)' : @stdout}"
    lines << "stderr: #{@stderr.empty? ? '(empty)' : @stderr}"
    lines << "cinc-auditor JSON: #{reporter_json_for_diagnostic}"
    lines.join("\n")
  end

  # The reporter JSON cinc-auditor produced, pretty-printed when parseable, so a
  # failure shows exactly what the runner saw — e.g. an empty `controls` array
  # (profile loaded but no controls discovered) vs. an empty/absent file. This
  # is the evidence that distinguishes a real test failure from a profile/runner
  # problem, so always include it.
  def reporter_json_for_diagnostic
    return '(no reporter file produced)' if @raw_json.nil?
    return '(empty reporter file)' if @raw_json.strip.empty?

    text = @data ? JSON.pretty_generate(@data) : "(unparseable) #{@raw_json}"
    text.length > 6000 ? "#{text[0, 6000]}\n... (truncated)" : "\n#{text}"
  end
end

# RSpec custom matchers for InspecResult
RSpec::Matchers.define :be_passing do
  match { |result| result.status == :passed }
  failure_message { |result| "expected control to pass\n#{result.diagnostic}" }
end

RSpec::Matchers.define :be_failing do
  match { |result| result.status == :failed }
  failure_message { |result| "expected control to fail\n#{result.diagnostic}" }
end

RSpec::Matchers.define :be_skipped do
  match { |result| result.status == :skipped }
  failure_message { |result| "expected control to be skipped\n#{result.diagnostic}" }
end

# Helper methods available in all spec files
module InspecHelpers
  def run_control(control_id, rootfs:, rootfs_prefix: nil, **extra_inputs)
    InspecRunner.run(control_id, rootfs: rootfs, extra_inputs: extra_inputs, rootfs_prefix: rootfs_prefix)
  end
end
