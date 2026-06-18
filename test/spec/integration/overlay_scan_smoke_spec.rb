require 'spec_helper'
require 'tmpdir'
require 'open3'

# End-to-end integration smoke for the overlay merged-dir scan
# (tools/cinc-chainguard-overlay.sh) — reads the container's overlay2 merged
# directory (docker inspect GraphDriver.Data.MergedDir) directly, with no
# filesystem extraction and without needing the workload to stay running (the
# overlay stays mounted until `docker rm`).
#
# Like live mode and unlike the filesystem-reconstruction smoke, this reads the
# real container fs in place, preserving the image's root ownership without a
# privileged host-side extraction — so we assert the ownership controls pass.
# The merged dir under /var/lib/docker/overlay2 is root-owned, but the scan
# works for a non-root docker-group user because the Docker daemon performs the
# bind mount into the (privileged) auditor container; the invoker never reads
# the path itself.
#
# Requires a Linux host with the overlay2 storage driver (the script errors out
# otherwise — e.g. Docker Desktop on macOS/Windows keeps overlay2 inside a VM).
# We pre-check those prerequisites and skip with a clear message when absent,
# rather than failing.
#
# Heavy (pulls an image, starts a container) and dependent on a floating :latest
# image, so gated behind RUN_SCAN_SMOKE=1; scan-smoke.yml runs it on a schedule.
# Run locally with `make scan-smoke`.
RSpec.describe 'overlay merged-dir scan (cinc-chainguard-overlay.sh)', :scan_smoke do
  let(:target)        { ENV['SCAN_SMOKE_OVERLAY_IMAGE'] || 'cgr.dev/chainguard/nginx:latest' }
  let(:auditor_image) { ENV['CINC_AUDITOR_IMAGE'] || 'cgr.dev/chainguard/cinc-auditor:latest' }
  let(:script) { scan_script('cinc-chainguard-overlay.sh') }

  before do
    skip 'set RUN_SCAN_SMOKE=1 to run the overlay scan smoke (heavy)' unless ENV['RUN_SCAN_SMOKE'] == '1'
    skip 'docker not available' unless system('docker', '--version', out: File::NULL, err: File::NULL)
    skip 'overlay scan requires a Linux host' unless RUBY_PLATFORM.include?('linux')
    driver, st = Open3.capture2e('docker', 'info', '--format', '{{.Driver}}')
    skip "overlay scan requires the overlay2 storage driver (got: #{driver.strip})" \
      unless st.success? && driver.strip == 'overlay2'
  end

  it 'scans the overlay merged dir and produces correct verdicts', :aggregate_failures do
    Dir.mktmpdir do |results_dir|
      # --use-local-profile mounts the repo profile (the public auditor image has
      # none embedded). The script exits 0 on a completed scan even when controls
      # fail; a non-zero exit is a hard error (overlay not mounted / profile /
      # container failure), which we surface with the log.
      out, status = run_scan_script(script, '--use-local-profile', target, 'dev', results_dir,
                                    env: { 'CINC_AUDITOR_IMAGE' => auditor_image })
      expect(status.exitstatus).to eq(0), "scan script hard-errored (exit #{status.exitstatus}):\n#{out}"

      json_path = scan_report(results_dir, 'json')
      expect(json_path).not_to be_nil, 'scan produced no JSON reporter'
      json = File.read(json_path)

      # Controls were discovered (profile resolution — the inspec#7934 guard).
      expect(parsed_controls(json).length).to be > 0

      # Reading the merged dir in place preserves real root ownership (no
      # privileged extraction), so the ownership controls pass; find enumerated
      # /usr/lib.
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
