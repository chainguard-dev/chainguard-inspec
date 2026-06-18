require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'open3'

# End-to-end proof that the scan scripts' --input-file flag actually applies an
# input-overrides file — across ALL FOUR scan scripts — and, by dogfooding the
# shipped examples/inputs.yml, that that example file is valid and usable.
#
# Every script is tested separately on purpose: each has its own --input-file
# arg parser (a per-script while/case calling cinc_set_input_file), and an input
# file can't ride on a generic passthrough — the auditor runs in a container, so
# the YAML must be bind-mounted in and referenced by its in-container path (the
# host path is invisible there). Three scripts share cinc_run_auditor for that
# bind mount; docker-transport does it in its own runner. A per-script omission
# (flag not wired, or not bind-mounted) only shows up by exercising each one.
#
# Parametrized by script so CI can fan the four out across a matrix (one job
# each, see scan-smoke.yml): set SCAN_SMOKE_OVERRIDE_SCRIPT to a single script to
# test just that one. Unset (e.g. local `make scan-smoke`) tests all four.
#
# Proof is the transport-independent attribute readback: cinc-auditor echoes the
# *resolved* input values under profiles[0].attributes, so we copy
# examples/inputs.yml, set a sentinel expected_cacert_hash the scan scripts do
# NOT override inline (so the file's value wins), scan with --input-file, and
# assert the sentinel comes back resolved. Verified that this readback reflects
# the override (not the inspec.yml default), so no behavioral-delta fallback is
# needed.
#
# nginx is used for every script: it satisfies all of their constraints (in
# particular it keeps its server in the foreground, so the live scan's target
# stays up). The sentinel readback does not depend on the target's contents.
#
# Heavy (pulls an image, runs a scan per script) and dependent on a floating
# :latest image, so gated behind RUN_SCAN_SMOKE=1; scan-smoke.yml runs it on a
# schedule. Run locally with `make scan-smoke`.
RSpec.describe 'input-file override applies across the scan scripts (examples/inputs.yml)', :scan_smoke do
  # Per-script config: mode-specific extra flags, and any prerequisite gate.
  SCRIPT_CONFIG = {
    'cinc-chainguard.sh'                  => { flags: ['--no-tmpfs'] },
    'cinc-chainguard-docker-transport.sh' => { flags: [] },
    'cinc-chainguard-overlay.sh'          => { flags: [], requires: :overlay },
    'cinc-chainguard-live.sh'             => { flags: [] },
  }.freeze

  let(:target)        { ENV['SCAN_SMOKE_IMAGE'] || 'cgr.dev/chainguard/nginx:latest' }
  let(:auditor_image) { ENV['CINC_AUDITOR_IMAGE'] || 'cgr.dev/chainguard/cinc-auditor:latest' }
  let(:example_inputs) { File.expand_path('../../../examples/inputs.yml', __dir__) }
  # A non-default sentinel for a scalar input the scan scripts do NOT set inline
  # via --input (so the --input-file value wins). 64 hex chars = a valid-looking
  # sha256, so the control parses it without choking.
  let(:sentinel_hash) { 'deadbeef' * 8 }

  before do
    skip 'set RUN_SCAN_SMOKE=1 to run the input-file override smoke (heavy)' unless ENV['RUN_SCAN_SMOKE'] == '1'
    skip 'docker not available' unless system('docker', '--version', out: File::NULL, err: File::NULL)
  end

  # One script (CI matrix sets SCAN_SMOKE_OVERRIDE_SCRIPT) or all four (local).
  # Treat an empty value as unset: the shared scan-smoke matrix sets this env for
  # every job, so it arrives as "" on the mode-smoke jobs (which run a different
  # spec and ignore it).
  only = ENV['SCAN_SMOKE_OVERRIDE_SCRIPT']
  only = nil if only.nil? || only.empty?
  selected = only ? { only => SCRIPT_CONFIG.fetch(only) } : SCRIPT_CONFIG

  selected.each do |script_name, cfg|
    it "applies the --input-file override over #{script_name}" do
      require_overlay_prereqs! if cfg[:requires] == :overlay
      expect_override_applies(script_name, *cfg[:flags])
    end
  end

  # --- helpers ---------------------------------------------------------------

  # Run `script` (with any mode-specific flags) with --use-local-profile and a
  # --input-file built from the shipped example + a sentinel, then assert the
  # sentinel comes back as the resolved expected_cacert_hash.
  def expect_override_applies(script_name, *extra_flags)
    Dir.mktmpdir do |work|
      inputs  = sentinel_inputs_file(work)
      results = File.join(work, 'results')
      FileUtils.mkdir_p(results)

      out, status = run_scan_script(
        scan_script(script_name), *extra_flags, '--use-local-profile',
        '--input-file', inputs, target, 'dev', results,
        env: { 'CINC_AUDITOR_IMAGE' => auditor_image }
      )
      expect(status.exitstatus).to eq(0), "scan script hard-errored (exit #{status.exitstatus}):\n#{out}"

      json_path = scan_report(results, 'json')
      expect(json_path).not_to be_nil, 'scan produced no JSON reporter'
      json = File.read(json_path)

      expect(parsed_controls(json).length).to be > 0
      expect(resolved_input('expected_cacert_hash', json)).to eq(sentinel_hash)
    end
  end

  # A temp copy of the shipped examples/inputs.yml with a sentinel
  # expected_cacert_hash appended (the example leaves that key commented out).
  # Copying the real file dogfoods it — a malformed example would fail the scan.
  def sentinel_inputs_file(dir)
    path = File.join(dir, 'inputs.yml')
    FileUtils.cp(example_inputs, path)
    File.write(path, %(\nexpected_cacert_hash: "#{sentinel_hash}"\n), mode: 'a')
    path
  end

  # The overlay script requires a Linux host with the overlay2 storage driver
  # (e.g. Docker Desktop keeps overlay2 in a VM); skip with a clear message
  # otherwise rather than failing.
  def require_overlay_prereqs!
    skip 'overlay scan requires a Linux host' unless RUBY_PLATFORM.include?('linux')
    driver, st = Open3.capture2e('docker', 'info', '--format', '{{.Driver}}')
    skip "overlay scan requires the overlay2 storage driver (got: #{driver.strip})" \
      unless st.success? && driver.strip == 'overlay2'
  end
end
