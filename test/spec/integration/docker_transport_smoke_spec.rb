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
  let(:auditor_image) { ENV['CINC_AUDITOR_IMAGE'] || 'cincproject/auditor:latest' }
  let(:script) { File.expand_path('../../../tools/cinc-chainguard-docker-transport.sh', __dir__) }

  before do
    skip 'set RUN_SCAN_SMOKE=1 to run the docker:// scan smoke (heavy)' unless ENV['RUN_SCAN_SMOKE'] == '1'
    skip 'docker not available' unless system('docker', '--version', out: File::NULL, err: File::NULL)
  end

  it 'reaches Tier 3, discovers files, and produces correct verdicts', :aggregate_failures do
    require_tier3_target!(target)

    Dir.mktmpdir do |results_dir|
      run_docker_transport_scan(target, results_dir)

      json_path = Dir.glob(File.join(results_dir, '*.json')).first
      expect(json_path).not_to be_nil, 'scan produced no JSON reporter'
      json = File.read(json_path)

      # Controls were discovered (profile resolution — the inspec#7934 guard).
      controls = JSON.parse(json).dig('profiles', 0, 'controls') || []
      expect(controls.length).to be > 0

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
      html_path = Dir.glob(File.join(results_dir, '*.html')).first
      expect(html_path).not_to be_nil, 'scan produced no HTML report'
      expect(File.size(html_path)).to be > 1000
    end
  end

  # --- helpers ---------------------------------------------------------------

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

  # Run the docker-transport scan into results_dir. --use-local-profile mounts
  # the repo profile (the public auditor image has none embedded). The script
  # exits 0 on a completed scan even when controls fail; a non-zero exit is a
  # hard error (profile/container failure), which we surface with the log.
  def run_docker_transport_scan(image, results_dir)
    env = { 'CINC_AUDITOR_IMAGE' => auditor_image }
    cmd = ['bash', script, '--use-local-profile', image, 'dev', results_dir]
    # The script's HTML step runs plain host `ruby`. Run it OUTSIDE this
    # process's bundler context so it behaves like a real user invocation
    # (global gems) instead of inheriting bundle exec's RUBYOPT/BUNDLE_GEMFILE
    # and being restricted to the test Gemfile (which lacks the report
    # generator's deps, e.g. rexml on Ruby 3.4+).
    out, status =
      if defined?(Bundler)
        Bundler.with_unbundled_env { Open3.capture2e(env, *cmd) }
      else
        Open3.capture2e(env, *cmd)
      end
    expect(status.exitstatus).to eq(0), "scan script hard-errored (exit #{status.exitstatus}):\n#{out}"
  end

  # Evaluate one control's aggregate status from the full-profile JSON, reusing
  # the harness's InspecResult + be_passing/be_failing matchers.
  def control_result(id, json)
    InspecResult.new(id, json, '', '')
  end

  # The integer N from LibraryPermissions' "scanned N file(s)..." evidence, or nil.
  def scanned_count(id, json)
    desc = control_descs(id, json).find { |d| d =~ /scanned \d+/ }
    desc && desc[/scanned (\d+)/, 1].to_i
  end

  # True if `id` has a failed result mentioning the FIPS material find looks for.
  def fips_failure_evidence?(id, json)
    ctrl = JSON.parse(json).dig('profiles', 0, 'controls')&.find { |c| c['id'] == id }
    (ctrl&.fetch('results', []) || []).any? do |r|
      r['status'] == 'failed' && r['code_desc'].to_s =~ /FIPS module|openssl-provider-fips/i
    end
  end

  def control_descs(id, json)
    ctrl = JSON.parse(json).dig('profiles', 0, 'controls')&.find { |c| c['id'] == id }
    (ctrl&.fetch('results', []) || []).map { |r| r['code_desc'] }.compact
  end
end
