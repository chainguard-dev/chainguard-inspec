require 'spec_helper'
require 'tmpdir'

# End-to-end integration smoke for the filesystem-reconstruction scan
# (tools/cinc-chainguard.sh) — the portable default mode that rebuilds the
# target rootfs on the host with `docker export | tar` and points cinc-auditor
# at it via a read-only bind mount (local transport, FindHelper Tier 1).
#
# This exercises the pipeline the fast control-tests job cannot: real image
# export/extraction -> auditor over the reconstructed rootfs -> JSON + HTML
# report. It drives the real script and asserts on the scan RESULTS, reusing
# InspecResult + the be_passing/be_failing matchers (ScanSmokeHelpers).
#
# Verdicts asserted here are deliberately ownership-INDEPENDENT. Faithful file
# ownership requires a privileged (root) extraction — `docker export | tar`
# restores the image's archived uid/gid only when run as root — so the
# ownership controls (LibraryPermissions, VarLogPermissions) pass only under a
# root extraction and would flap between a non-root local run and a privileged
# CI run. Those controls' correctness is covered by the control-tests suite and
# the docker-transport smoke; here we assert what holds regardless of who ran
# the extraction:
#   1. Controls were discovered (> 0) — the inspec#7934 profile-resolution guard.
#   2. find ran over the reconstructed /usr/lib (LibraryPermissions scanned > 0)
#      — a regressed find / empty reconstruction would scan zero.
#   3. An APK-content control read the installed DB and produced a real verdict
#      (RemoteAccessServices passes — the base image has no banned remote-access
#      packages).
#   4. Verdict correctness: the base image ships no OpenSSL FIPS configuration,
#      so it FAILS the FIPS-crypto control with the expected evidence.
#   5. The scan deliverable: a non-trivial HTML report.
#
# Heavy (pulls an image, exports its filesystem) and dependent on a floating
# :latest image, so gated behind RUN_SCAN_SMOKE=1; scan-smoke.yml runs it on a
# schedule. Run locally with `make scan-smoke`.
RSpec.describe 'filesystem reconstruction scan (cinc-chainguard.sh)', :scan_smoke do
  # A public target with `apk` so the APK-based controls run. wolfi-base is
  # non-FIPS, so the FIPS-crypto control fails (a stable, ownership-independent
  # verdict). It also ships /usr/lib libraries for find to enumerate.
  let(:target)        { ENV['SCAN_SMOKE_FS_IMAGE'] || 'cgr.dev/chainguard/wolfi-base:latest' }
  let(:auditor_image) { ENV['CINC_AUDITOR_IMAGE'] || 'cgr.dev/chainguard/cinc-auditor:latest' }
  let(:script) { scan_script('cinc-chainguard.sh') }

  before do
    skip 'set RUN_SCAN_SMOKE=1 to run the filesystem scan smoke (heavy)' unless ENV['RUN_SCAN_SMOKE'] == '1'
    skip 'docker not available' unless system('docker', '--version', out: File::NULL, err: File::NULL)
  end

  it 'reconstructs the rootfs, runs controls, and produces correct verdicts', :aggregate_failures do
    Dir.mktmpdir do |results_dir|
      # --no-tmpfs: don't require a writable /dev/shm (some CI runners lack one).
      # --use-local-profile mounts the repo profile (the public auditor image has
      # none embedded). The script exits 0 on a completed scan even when controls
      # fail (it masks cinc-auditor's exit 100); a non-zero exit is a hard error
      # (export/extraction/profile failure), which we surface with the log.
      out, status = run_scan_script(script, '--no-tmpfs', '--use-local-profile', target, 'dev', results_dir,
                                    env: { 'CINC_AUDITOR_IMAGE' => auditor_image })
      expect(status.exitstatus).to eq(0), "scan script hard-errored (exit #{status.exitstatus}):\n#{out}"

      json_path = scan_report(results_dir, 'json')
      expect(json_path).not_to be_nil, 'scan produced no JSON reporter'
      json = File.read(json_path)

      # Controls were discovered (profile resolution — the inspec#7934 guard).
      expect(parsed_controls(json).length).to be > 0

      # find ran over the reconstructed /usr/lib (ownership-independent).
      lib = 'oval:org.LibraryPermissions:def:2'
      expect(scanned_count(lib, json)).to be > 0

      # The APK installed DB was read and produced a real verdict: the base
      # image carries no banned remote-access packages, so this passes.
      expect(control_result('oval:org.RemoteAccessServices:def:1', json)).to be_passing

      # Verdict correctness: a non-FIPS image must FAIL the FIPS-crypto control,
      # with the expected "no FIPS material" evidence.
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
