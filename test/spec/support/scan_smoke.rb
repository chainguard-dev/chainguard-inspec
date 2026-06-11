require 'json'
require 'open3'

# Shared helpers for the end-to-end scan-mode integration smokes
# (test/spec/integration/*_smoke_spec.rb). These drive the real tools/ scan
# scripts and assert on the JSON reporter / HTML deliverable, reusing the
# harness's InspecResult + be_passing/be_failing matchers rather than
# re-implementing JSON evaluation.
#
# The smokes are heavy (pull images, start containers) and depend on floating
# :latest images, so they are gated behind RUN_SCAN_SMOKE=1 (see the
# `:scan_smoke`-tagged before hook wired up in spec_helper.rb) and run on a
# schedule via .github/workflows/scan-smoke.yml. Run locally with
# `make scan-smoke`.
module ScanSmokeHelpers
  # Run a tools/ scan script and return [combined_output, Process::Status].
  #
  # The scripts' --use-local-profile HTML step shells out to plain host `ruby`,
  # so run OUTSIDE this process's bundler context so it behaves like a real user
  # invocation (global gems) rather than inheriting bundle exec's
  # RUBYOPT/BUNDLE_GEMFILE and being restricted to the test Gemfile (which lacks
  # the report generator's deps, e.g. rexml on Ruby 3.4+).
  def run_scan_script(script, *args, env: {})
    cmd = ['bash', script, *args]
    if defined?(Bundler)
      Bundler.with_unbundled_env { Open3.capture2e(env, *cmd) }
    else
      Open3.capture2e(env, *cmd)
    end
  end

  # Absolute path to a tools/ scan script (callers pass e.g. 'cinc-chainguard.sh').
  def scan_script(name)
    File.expand_path("../../../tools/#{name}", __dir__)
  end

  # The first file matching *.<ext> written into results_dir, or nil.
  def scan_report(results_dir, ext)
    Dir.glob(File.join(results_dir, "*.#{ext}")).first
  end

  # The controls array from a full-profile JSON reporter string ([] if absent).
  def parsed_controls(json)
    JSON.parse(json).dig('profiles', 0, 'controls') || []
  end

  # The *resolved* value of a profile input from the JSON reporter's
  # profiles[0].attributes (nil if absent). cinc-auditor echoes the effective
  # input value there after applying --input/--input-file, so this is a
  # transport-independent way to prove an override actually reached the scan.
  def resolved_input(name, json)
    attr = (JSON.parse(json).dig('profiles', 0, 'attributes') || []).find { |a| a['name'] == name }
    attr&.dig('options', 'value')
  end

  # Evaluate one control's aggregate status from the full-profile JSON, reusing
  # the harness's InspecResult + be_passing/be_failing matchers.
  def control_result(id, json)
    InspecResult.new(id, json, '', '')
  end

  # The code_desc strings of a control's results ([] if the control is absent).
  def control_descs(id, json)
    ctrl = parsed_controls(json).find { |c| c['id'] == id }
    (ctrl&.fetch('results', []) || []).map { |r| r['code_desc'] }.compact
  end

  # The integer N from a "scanned N file(s)..." evidence line, or nil. Used to
  # prove a find-based control actually enumerated files (vs. vacuously passing
  # because find returned nothing).
  def scanned_count(id, json)
    desc = control_descs(id, json).find { |d| d =~ /scanned \d+/ }
    desc && desc[/scanned (\d+)/, 1].to_i
  end

  # True if `id` has a failed result mentioning the FIPS material the OpenSsl
  # control looks for — i.e. a non-FIPS target correctly failed the FIPS check
  # (and, by implication, find scanned /etc/ssl).
  def fips_failure_evidence?(id, json)
    ctrl = parsed_controls(json).find { |c| c['id'] == id }
    (ctrl&.fetch('results', []) || []).any? do |r|
      r['status'] == 'failed' && r['code_desc'].to_s =~ /FIPS module|openssl-provider-fips/i
    end
  end
end
