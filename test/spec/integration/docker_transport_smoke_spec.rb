require 'spec_helper'
require 'json'
require 'open3'
require 'tmpdir'

# End-to-end integration smoke for the docker:// transport scan.
#
# This is the only mode that exercises FindHelper's busybox tiers: the docker://
# transport resolves file()/command() INSIDE the target, so against a distroless
# image with no `find` and a static busybox bind-mounted at /bin/sh, FindHelper
# must reach Tier 3 (re-exec the shell with argv[0]="find"). The control specs
# use local transport (the auditor image's own find) and so only ever hit Tier 1.
#
# It drives the real tools/cinc-chainguard-docker-transport.sh and asserts on the
# scan RESULTS, reusing InspecResult + the be_passing/be_failing matchers rather
# than re-implementing JSON evaluation. Two things are checked:
#   1. Tier 3 actually discovered files (LibraryPermissions scanned > 0) — a
#      regressed find_command returning nil would scan zero and vacuously pass.
#   2. Verdicts are real: the non-FIPS target FAILS the FIPS-crypto control with
#      evidence that find scanned /etc/ssl and found nothing. (The script exits 0
#      even when controls fail — it masks cinc-auditor's exit 100 — so the verdict
#      must be read from the JSON, not the exit code.)
#
# Heavy (pulls images, starts containers) and dependent on floating :latest
# images, so it is gated behind RUN_SCAN_SMOKE=1 and skipped in the default
# suite; scan-smoke.yml runs it on a schedule. Run locally with `make scan-smoke`.
RSpec.describe 'docker:// transport scan (FindHelper Tier 3)', :scan_smoke do
  # A distroless target: no find / no busybox binary on PATH (only the static
  # busybox the script bind-mounts at /bin/sh) so FindHelper must reach Tier 3;
  # with /usr/lib libraries to discover; and NON-FIPS so the FIPS control fails.
  let(:target)        { ENV['SCAN_SMOKE_IMAGE'] || 'cgr.dev/chainguard/glibc-dynamic:latest' }
  let(:auditor_image) { ENV['CINC_AUDITOR_IMAGE'] || 'cgr.dev/chainguard/cinc-auditor:latest' }
  let(:script) { scan_script('cinc-chainguard-docker-transport.sh') }

  before do
    skip 'set RUN_SCAN_SMOKE=1 to run the docker:// scan smoke (heavy)' unless ENV['RUN_SCAN_SMOKE'] == '1'
    skip 'docker not available' unless system('docker', '--version', out: File::NULL, err: File::NULL)
  end

  it 'reaches Tier 3, discovers files, and produces correct verdicts', :aggregate_failures do
    require_tier3_target!(target)

    Dir.mktmpdir do |results_dir|
      # --use-local-profile mounts the repo profile (the public auditor image has
      # none embedded). The script exits 0 on a completed scan even when controls
      # fail; a non-zero exit is a hard error (profile/container failure).
      out, status = run_scan_script(script, '--use-local-profile', target, 'dev', results_dir,
                                    env: { 'CINC_AUDITOR_IMAGE' => auditor_image })
      expect(status.exitstatus).to eq(0), "scan script hard-errored (exit #{status.exitstatus}):\n#{out}"

      json_path = scan_report(results_dir, 'json')
      expect(json_path).not_to be_nil, 'scan produced no JSON reporter'
      json = File.read(json_path)

      # Controls were discovered (profile resolution — the inspec#7934 guard).
      expect(parsed_controls(json).length).to be > 0

      # Tier 3 positive: LibraryPermissions resolved find and enumerated /usr/lib.
      lib = 'oval:org.LibraryPermissions:def:2'
      expect(control_result(lib, json)).to be_passing
      expect(scanned_count(lib, json)).to be > 0

      # Verdict correctness (also a Tier 3 check: find scanned /etc/ssl, found no
      # FIPS material): the non-FIPS target must FAIL the FIPS-crypto control.
      ssl = 'oval:org.OpenSsl:def:1'
      expect(control_result(ssl, json)).to be_failing
      expect(fips_failure_evidence?(ssl, json)).to be(true)

      # The scan deliverable: a non-trivial HTML report.
      html_path = scan_report(results_dir, 'html')
      expect(html_path).not_to be_nil, 'scan produced no HTML report'
      expect(File.size(html_path)).to be > 1000
    end
  end

  # --- helpers (Tier-3-specific; shared helpers live in support/scan_smoke.rb) -

  # Skip (don't fail) unless `image` genuinely forces Tier 3: it must have no
  # `find`/busybox binary at a FindHelper FIND_PATHS/BUSYBOX_PATHS location, else
  # the scan would resolve Tier 1/2 and this would silently NOT test Tier 3
  # (e.g. wolfi-base ships /usr/bin/find). Lists the image's files via
  # `docker export | tar -t` (no shell needed in the image itself).
  def require_tier3_target!(image)
    # Inert placeholder command so `docker create` succeeds on a distroless image
    # with no default CMD (create only configures; the command is never run).
    created, st = Open3.capture2e('docker', 'create', '--platform', 'linux/amd64', image, '/smoke-noop')
    skip "cannot create container from #{image} (pull/auth?): #{created.strip}" unless st.success?

    cid = created.lines.last.strip
    begin
      listing, _err, lst = Open3.capture3('bash', '-c', "set -o pipefail; docker export #{cid} | tar -tf -")
      paths = lst.success? ? listing.split("\n") : []
    ensure
      system('docker', 'rm', cid, out: File::NULL, err: File::NULL)
    end

    found = %w[usr/bin/find bin/find usr/bin/busybox bin/busybox] & paths
    return if found.empty?

    skip "#{image} has #{found.join(', ')}; would resolve FindHelper Tier 1/2, not Tier 3"
  end
end
