require 'spec_helper'
require 'tmpdir'

# End-to-end integration smoke for the live-container scan
# (tools/cinc-chainguard-live.sh) — starts the target's real workload and runs
# cinc-auditor with --pid=host against /proc/<PID>/root, so the auditor reads
# the *running* container's filesystem in place.
#
# Unlike the filesystem-reconstruction smoke, this reads the live container fs
# directly, which preserves the image's real (root) ownership without a
# privileged host-side extraction. So here we DO assert the ownership controls
# pass — that faithful-ownership-without-root-extraction is exactly the point of
# live mode. It drives the real script and asserts on the scan RESULTS via
# ScanSmokeHelpers.
#
# The target must stay running for the whole scan (its fs is read live through
# /proc/<PID>/root); a workload that exits makes the path vanish. nginx runs its
# server in the foreground so it stays up on its own (it is also the README's
# example image). The #52 liveness helper aborts the scan with a clear error if
# the target exits early, so a flaky target surfaces as a hard error here rather
# than a vacuous pass.
#
# Heavy (pulls an image, starts a container) and dependent on a floating :latest
# image, so gated behind RUN_SCAN_SMOKE=1; scan-smoke.yml runs it on a schedule.
# Run locally with `make scan-smoke`.
RSpec.describe 'live container scan (cinc-chainguard-live.sh)', :scan_smoke do
  # A public image whose workload stays in the foreground (so it remains running
  # through the scan) and is non-FIPS (so the FIPS-crypto control fails).
  let(:target)        { ENV['SCAN_SMOKE_LIVE_IMAGE'] || 'cgr.dev/chainguard/nginx:latest' }
  let(:auditor_image) { ENV['CINC_AUDITOR_IMAGE'] || 'cincproject/auditor:latest' }
  let(:script) { scan_script('cinc-chainguard-live.sh') }

  before do
    skip 'set RUN_SCAN_SMOKE=1 to run the live scan smoke (heavy)' unless ENV['RUN_SCAN_SMOKE'] == '1'
    skip 'docker not available' unless system('docker', '--version', out: File::NULL, err: File::NULL)
  end

  it 'scans the running container and produces correct verdicts', :aggregate_failures do
    Dir.mktmpdir do |results_dir|
      # --use-local-profile mounts the repo profile (the public auditor image has
      # none embedded). The script exits 0 on a completed scan even when controls
      # fail; a non-zero exit is a hard error — including the #52 liveness guard
      # firing because the target exited mid-scan — which we surface with the log.
      out, status = run_scan_script(script, '--use-local-profile', target, 'dev', results_dir,
                                    env: { 'CINC_AUDITOR_IMAGE' => auditor_image })
      expect(status.exitstatus).to eq(0), "scan script hard-errored (exit #{status.exitstatus}):\n#{out}"

      json_path = scan_report(results_dir, 'json')
      expect(json_path).not_to be_nil, 'scan produced no JSON reporter'
      json = File.read(json_path)

      # Controls were discovered (profile resolution — the inspec#7934 guard).
      expect(parsed_controls(json).length).to be > 0

      # Live mode reads the running container fs through /proc/<PID>/root, so the
      # real root ownership is preserved (no privileged extraction needed) and
      # the ownership controls pass — the distinguishing value of this mode. find
      # also enumerated /usr/lib.
      lib = 'oval:org.LibraryPermissions:def:2'
      expect(control_result(lib, json)).to be_passing
      expect(scanned_count(lib, json)).to be > 0
      expect(control_result('oval:org.varlog:def:2', json)).to be_passing

      # The APK installed DB was read (no banned remote-access packages).
      expect(control_result('oval:org.RemoteAccessServices:def:1', json)).to be_passing

      # Verdict correctness: a non-FIPS image must FAIL the FIPS-crypto control.
      ssl = 'oval:org.OpenSsl:def:1'
      expect(control_result(ssl, json)).to be_failing
      expect(fips_failure_evidence?(ssl, json)).to be(true)

      # The scan deliverable: a non-trivial HTML report.
      html_path = scan_report(results_dir, 'html')
      expect(html_path).not_to be_nil, 'scan produced no HTML report'
      expect(File.size(html_path)).to be > 1000
    end
  end
end
