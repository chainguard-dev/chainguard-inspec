# Testing

Two suites live under `test/`, with different harnesses:

- **`test/spec/`** — the rspec control suite. Most of this document.
- **`test/tools/*_test.sh`** — shell tests for the `tools/` scan helpers. See
  [Testing the `tools/` shell helpers](#testing-the-tools-shell-helpers).

Both run from `make test`; `make controls` and `make tools-test` run them
individually.

## The rspec control suite

This profile ships a behavioural unit-test suite under `test/`. Each control has
a spec in `test/spec/controls/` that builds a small synthetic root filesystem in
a tmpdir, runs the control against it with cinc-auditor, and asserts the control
passes / fails / is skipped via the `be_passing`, `be_failing`, and `be_skipped`
matchers.

This is distinct from the end-to-end scan scripts in `tools/` (which evaluate
real container images) and from `cinc-auditor check .` (which only validates
profile structure). The unit suite exercises control *logic* against fixtures
without needing a real image.

## Permission tests require root or passwordless sudo

> **Read this before running the suite.** Several controls check filesystem
> ownership (e.g. that a library or `/var/log` is owned by `root:root`). The
> corresponding specs build fixtures that must actually be root-owned, via
> `chown_root` in `test/spec/support/fixture_helpers.rb`, which does a direct
> `File.chown` when running as root or falls back to `sudo -n chown root:root`.

Implications:

- The rspec process needs to be **root** or have **passwordless sudo**
  (`sudo -n`, or sudo with cached credentials — run any `sudo` command first to
  prime the timestamp).
- If neither is available, those examples don't fail — they
  `skip 'requires root or passwordless sudo'`. The suite stays green but
  **silently loses coverage**. Watch the rspec summary for skipped examples.
- **Docker mode does not remove this requirement.** The fixture files are
  created and chowned *on the host*, inside the rspec process, before the
  container is launched. The container running as `--user 0:0` only *reads*
  them; the host-side ownership has to be established first.
- Conversely, a few examples are only meaningful as non-root and self-skip when
  `Process.uid == 0` (`skip 'only meaningful when not running as root'`), since
  root can't create a file it doesn't already own as non-root in the usual way.

So no single uid runs 100% of the suite trivially: root covers the
root-ownership cases, and the few "must be non-root" cases skip. Passwordless
sudo as a normal user covers both (root-owned via `sudo`, non-root via the
current user).

## How a control gets executed: mode auto-detection

`test/spec/support/inspec_runner.rb` picks how to invoke cinc-auditor, in this
priority order (see `InspecRunner.detect_mode`):

1. `CINC_AUDITOR_BIN` set → run that binary directly
2. `cinc-auditor` found in `PATH` → run directly
3. `inspec` found in `PATH` → run directly
4. `CINC_AUDITOR_IMAGE` set **and** `docker` in `PATH` → **Docker mode**
5. otherwise → raises with setup instructions

So if no `cinc-auditor`/`inspec` binary is installed, setting
`CINC_AUDITOR_IMAGE` is enough to route every control through a container.

All controls read `ENV['ROOTFS_DIR'] || input('rootfs')`; the harness always
passes the fixture path via `--input rootfs=...` (never `ROOTFS_DIR`) so the
input mechanism itself is exercised.

## The profile is evaluated from a staged clean copy (not the repo root)

The harness does **not** point cinc-auditor at the repository root. It stages a
clean directory containing only `inspec.yml` + `controls/` + `libraries/` (see
`InspecRunner.profile_path` in `inspec_runner.rb`) and evaluates that. This is
deliberate, and the reason is a sharp-edged behaviour change in cinc-auditor /
InSpec **7.x**:

> **Gotcha — a stray `*.gemspec` anywhere under the profile path makes 7.x find
> zero controls.** InSpec 7.0 added a "gem" source reader
> (`source_readers/gem.rb`) whose `resolve` claims a profile when *any* file in
> the tree path-matches `/gemspec/`, and it outranks the normal `inspec.yml`
> reader. A gem-read profile is treated as a resource pack and exposes **no
> controls** (`@tests = {}`). Our profile lives at the repo root, and
> `bundle install` (or CI's `setup-ruby` `bundler-cache`) vendors gems into
> `test/vendor/bundle/.../specifications/*.gemspec`. So evaluating the repo root
> directly while `test/vendor` exists makes 7.x silently discover **0 controls**
> — every control reports `status: error`, and `cinc-auditor check` prints
> `No controls or tests were defined`. cinc-auditor 5.x/6.x are unaffected (no
> gem source reader); the regression is at the 6.x→7.0 boundary.

Implications:

- The unit-test harness sidesteps it by staging the clean profile copy above.
- When you run cinc-auditor against the profile **yourself**, point it at a
  clean checkout or a git URL (vendored gems are gitignored, so a fresh clone is
  unaffected) — not a working tree that has had `bundle install` run under
  `test/`. The `tools/` scan scripts mount the local tree for
  `--use-local-profile`; on a bundled checkout they will hit this until they
  adopt the same staged-copy approach (tracked follow-up).
- A single `.gemspec` reproduces it: a clean profile dir plus one dummy
  `*.gemspec` file yields `controls:[]` on 7.x.

Upstream issue: [inspec/inspec#7934](https://github.com/inspec/inspec/issues/7934).

## Scan scripts default to the profile baked into the auditor image

The `tools/` scan scripts do **not** evaluate your working tree by default.
`cinc_setup_profile_paths` (`tools/lib/cinc-common.sh`) points `PROFILE_PATH` at
`/usr/share/chainguard-inspec/` — the copy the `chainguard-inspec` apk installs
*inside the auditor image*. Pass `--use-local-profile` to bind-mount and
evaluate the checkout instead.

The scan header reports which one is in play, and its version:

```
Profile:     embedded (1.1.0)          # the auditor image's copy
Profile:     local bind mount (1.1.0)  # --use-local-profile
```

> **Gotcha — running a scan from a branch worktree does not mean you scanned
> that branch's profile.** The results land in that worktree's `results/`
> either way, so a local change can look like it had no effect, or an
> already-merged change can look broken. The header distinguishes them; the
> saved JSON does not.

A **stale auditor image** is the sharper version of the same trap, because
nothing about it looks wrong. `cinc_warn_if_profile_stale` therefore compares
the image's embedded profile version against this checkout's and says so:

```
WARNING: the auditor image's embedded profile does not match this checkout.
         embedded (scanning with): 0.0.4
         this checkout:            1.1.0
```

It reports the difference without claiming which is newer — `sort -V` is
GNU-only and these scripts run on macOS hosts too, so an ordering claim would
be wrong on some platforms. Both values are printed, which is what the reader
needs either way. The check is silent when the versions agree, when either is
unreadable, and in `--use-local-profile` mode (where the checkout *is* the
profile, so there is nothing to compare).

This is worth having because the failure is a plausible-looking finding rather
than an error. A three-month-old auditor image embedding profile `0.0.4` still
carried the CA-bundle digest pinned before the sidecar work, so it reported
`CaBundleHashTest` **failing** on a compliant `python:latest-dev` —
`expected: "61efbd6d…"` against a current bundle. Nothing in the output said
the profile was old.

Worked example (2026-09-09). Scanning a private `jre-fips` image from a worktree
carrying the sidecar-digest work reported `CaBundleHashTest` failing:

```
expected: #<Encoding:UTF-8>    "61efbd6d…"
got:      #<Encoding:US-ASCII> "b8d83784…"
```

`61efbd6d…` was not a stale sidecar — it is the bundle digest in the `jre`-family
lineage (`jre:latest-dev` verifies clean against its own sidecar), and it was the
value `inspec.yml` **pinned** between 2026-04-21 and 2026-08-31. The embedded
profile predated the switch to reading the sidecar, so it compared a pin from one
image lineage against a bundle from another. Re-running with
`--use-local-profile` passed 7/7. The differing encodings were a useful tell: a
pinned value is parsed from YAML (UTF-8), a `sha256sum` result is not
(US-ASCII).

Since the saved report has no field naming the profile source, use one of these
to identify an existing JSON after the fact:

- **resolved inputs** (`profiles[0].attributes`): a populated
  `expected_cacert_hash` means the older pinned profile; `""` means the
  sidecar-reading one.
- **the control's result list**: the sidecar-reading profile emits an
  `Expected CA bundle digest origin` evidence line naming where the digest came
  from. Its absence means the embedded profile ran.

`version:` did **not** distinguish them at the time — the profile version was
not bumped across that change, so a report from either one says `0.0.4`. Any
archived JSON reporting `0.0.4` therefore still needs one of the two tells
above. Reports from `1.0.4` onwards do carry a usable version: `inspec.yml`'s
`version:` is now bumped in the commit the release tag points at, so it tracks
the released tag rather than drifting behind it — see
[Releasing](releasing.md).

So: **verifying a local control change requires `--use-local-profile`**, and a
scan result quoted as evidence for a change should be accompanied by one of the
two tells above. Recording the profile source in the report JSON is a tracked
follow-up.

## FilterTable resources can't assert file existence with `should exist`

When a control needs to require that a file is present, assert it through the
`file` resource, **not** through a FilterTable-based resource such as `shadow`,
`passwd`, `csv`, or `json`:

```ruby
# WRONG — passes even when /etc/shadow is absent (see below)
describe shadow(shadow_path) do
  it { should exist }
end

# RIGHT — file().exist? is a real boolean
describe file(shadow_path) do
  it { should exist }
end
```

> **Gotcha — `describe shadow(path) { should exist }` cannot fail on a missing
> file.** FilterTable resources have no `exist?` of their own; FilterTable
> synthesizes one as `!table.raw_data.empty?` and installs it wrapped in
> `rescue ResourceFailed, ResourceSkipped => e; FilterTable::ExceptionCatcher.new(...)`
> (`inspec/utils/filter.rb`). Computing `raw_data` reads the file via
> `FileReader#read_file_content`, which raises `ResourceSkipped` ("Can't find
> file") for an absent path. That skip is caught, so `shadow(path).exist?`
> returns a **truthy `FilterTable::ExceptionCatcher` object**, not `false` — and
> RSpec's `exist` matcher only checks the truthiness of `.exist?`. So the
> assertion **passes** on a missing file (and, perversely, *fails* on a
> present-but-empty one, where `raw_data` is genuinely empty). `file(path).exist?`
> returns a real boolean and behaves correctly. Verified against cinc-auditor /
> inspec-core 7.1.7.

This bit `UserPasswordConfiguredTest`, which had a `describe shadow(path) {
should exist }` that silently never fired. The resolution split the two
concerns the way the upstream SCAP content does:

- **Existence** is owned by `NoUsersCheck`, which requires `/etc/shadow` and
  `/etc/passwd` via the `file()` resource (real boolean `exist?`). A missing
  file is a finding there.
- **Password content** is a pure check in `UserPasswordConfiguredTest` with **no
  existence assertion at all**. The upstream rules (Chainguard SSG
  `oval:org.example:def:3`, ComplianceAsCode `no_empty_passwords_etc_shadow`) use
  OVAL `check_existence="none_exist"`, so an absent `/etc/shadow` scores
  compliant — verified with `oscap` (`OSCAP_PROBE_ROOT=<rootfs> oscap oval eval
  --id <def> <component>.xml`). We match that: absent `/etc/shadow` passes the
  content control vacuously.

Rule of thumb: if a control genuinely needs to assert a file exists, use
`file(path)`, never a FilterTable resource. But first consider whether existence
is that control's responsibility at all — for content checks, upstream's
`none_exist` convention is "absent file ⇒ compliant," with existence enforced by
a separate rule.

## Running locally with system rspec + the Chainguard cinc-auditor image

Common developer setup: system-installed `rspec`, Docker present, and no
`cinc-auditor` binary. Use the public Chainguard cinc-auditor image (it
incorporates the train fix described in the README's "Using binary
distributions" caveat); it is public, so no registry authentication is required.

```bash
# 1. Prime sudo so the permission-ownership fixtures don't skip (see above)
sudo -v

# 2. Run the suite from the test/ directory. With no cinc-auditor/inspec binary
#    on PATH the harness falls through to Docker mode (see mode auto-detection
#    above), which reads CINC_AUDITOR_IMAGE and has no built-in default, so set
#    it. (A binary on PATH, or CINC_AUDITOR_BIN, would be used directly instead.)
cd test
CINC_AUDITOR_IMAGE=cgr.dev/chainguard/cinc-auditor:latest rspec
```

- Bare `rspec` uses the **system** gem and skips bundler. `require 'spec_helper'`
  still resolves because rspec adds `spec/` to the load path. The system rspec
  must satisfy the Gemfile pin (`rspec ~> 3.13`). To pin to the locked versions
  instead: `bundle install && CINC_AUDITOR_IMAGE=... bundle exec rspec`
  (bundler installs into `test/vendor/bundle`, which is gitignored).
- If you need `sudo` for the Docker socket as well, set `DOCKER_CMD="sudo docker"`.
- Single file / single example:

  ```bash
  CINC_AUDITOR_IMAGE=cgr.dev/chainguard/cinc-auditor:latest \
    rspec spec/controls/aslr_check_spec.rb -e 'passes'
  ```

### Docker-mode mechanics

In Docker mode (`InspecRunner.build_docker_cmd`) each control runs as:

```
docker run --rm --platform linux/amd64 --user 0:0 \
  -v <profile>:/profile:ro \
  -v <fixture-tmpdir>:/fixture:ro \
  -v <results-tmpdir>:/results \
  $CINC_AUDITOR_IMAGE exec /profile \
  --controls <id> --reporter json:/results/output.json \
  --no-create-lockfile --input rootfs=/fixture
```

The fixture rootfs is bind-mounted read-only at `/fixture`, and the `rootfs`
input is forced to `/fixture` inside the container regardless of the host
tmpdir path.

## Useful environment variables

| Variable             | Effect                                                              |
| -------------------- | ------------------------------------------------------------------- |
| `CINC_AUDITOR_IMAGE` | Image used in Docker mode (no binary installed).                    |
| `CINC_AUDITOR_BIN`   | Force direct mode against a specific binary path.                   |
| `DOCKER_CMD`         | Override the docker invocation, e.g. `sudo docker`, for socket access. |
| `INSPEC_DEBUG`       | Dump cmd / exit status / stdout / stderr / JSON for each control.   |

## How CI runs it

`.github/workflows/control-tests.yml` runs on pushes to `main` and on PRs that
touch `controls/**`, `test/**`, or `inspec.yml`. It runs on a non-root runner
with **passwordless sudo** and Docker (deliberately *not* a `container:` job, so
Docker-in-Docker works for Docker mode, and so the root-ownership fixtures can
`sudo chown`), sets up Ruby 3.4 with `bundler-cache`, and runs
`bundle exec rspec` in `test/`.

CI uses the public `cgr.dev/chainguard/cinc-auditor:latest` image
(`CINC_AUDITOR_IMAGE` in the workflow env), so the suite runs without registry
credentials. Override `CINC_AUDITOR_IMAGE` to validate against an alternate
auditor image (e.g. the upstream `cincproject/auditor:latest`).

## Writing a new control spec

Mirror an existing spec (e.g. `test/spec/controls/aslr_check_spec.rb`):

- `let(:rootfs) { Dir.mktmpdir }` and clean it up in an `after` block.
- Build only the files/dirs the control inspects under `rootfs` in a `before`.
- Assert with `expect(run_control('<control-id>', rootfs: rootfs)).to be_passing`
  (or `be_failing` / `be_skipped`).
- `run_control` accepts extra inputs as keyword args, forwarded as
  `--input key=value`.
- For permission-sensitive controls, use the ownership helpers in
  `test/spec/support/fixture_helpers.rb` — `chown_root` (root-owned, gated
  behind `skip 'requires root or passwordless sudo'`), `make_non_root_owned`,
  and `cleanup_with_root_files` (resets ownership before `rm_rf` so a non-root
  process can clean up root-owned fixtures).

## Testing the `tools/` shell helpers

`test/tools/*_test.sh` covers the shell in `tools/`, mostly the helpers in
`tools/lib/cinc-common.sh`. They are plain bash scripts, each self-contained
and runnable directly; `make tools-test` globs the directory, so a new file is
picked up without editing anything. CI runs `make tools-test` from
`control-tests.yml` — note it is the *glob* that matters: the workflow
previously named each test file, and a test added to the repo went unrun by CI
for as long as nobody remembered to edit the workflow too.

Most are integration tests: they build or run real (tiny) containers rather
than stubbing Docker, because the thing most likely to be wrong is the
assumption about what a container does, and a stub encodes that assumption
rather than testing it.

### Gotcha — run errexit-sensitive cases in the shell mode production uses

Every scan script in `tools/` starts with `set -euo pipefail`. The test harness
**cannot**: it calls helpers and inspects `$?`, which `-e` makes impossible. So
the harnesses use `set -uo pipefail`, and that difference will hide an entire
class of bug from you.

Under `set -e`, an assignment from a failing command substitution aborts the
script **at that line**:

```bash
x="$(some_command_that_fails | sed -n p)"   # with -e: script dies here
                                            # without -e: x='' and we continue
```

This shipped once. A version probe assigned from a pipeline starting with
`docker run`; whenever the auditor image could not be read — an unpullable
image, or `cincproject/auditor:latest`, which has no embedded profile — the
scan died at that line. Because the probe ran *before* the scan header, the
user got **no output at all**, where previously they got a header and a
diagnosable error.

The regression test for it asserted *"a missing embedded profile degrades to
unknown, does not fail"* — exactly the broken behaviour — and **passed**,
because `-e` was off on the test side and on in production. Fixture and code
were consistently wrong, so the suite stayed quiet. Mutation testing did not
help either: the mutation was caught by nothing, because nothing ran in the
mode where it mattered.

So when a helper is called from a script that uses `set -e`, test it in a
subshell that does too:

```bash
run_under_errexit() {
    bash -euo pipefail -c '
        source "$1"
        # ... set up and call the helper ...
        echo "REACHED-END ${RESULT}"
    ' bash "${TEST_DIR}/../../tools/lib/cinc-common.sh" "$@" 2>&1
}
```

Two details that bite:

- Pass the library as a **positional**, not as `$0`. `cinc-common.sh` refuses
  to run as `$0` (it is a library), and `bash -c 'script' /path/to/lib` makes
  the lib `$0`, so the guard fires and the test fails confusingly.
- Assert on a sentinel the subshell prints *after* the call (`REACHED-END`
  above), not just on its exit status. An abort and a clean run can both leave
  you looking at a plausible-seeming `$?`.

Better still, also drive the real script end to end for the failure you care
about — `cinc_profile_staleness_test.sh` runs `tools/cinc-chainguard.sh` with a
deliberately broken `CINC_AUDITOR_IMAGE` and asserts a header still appears.
That case cannot be fooled by harness/production drift, because there is no
harness in it.

### Writing a new shell test

Mirror `test/tools/cinc_require_target_running_test.sh`:

- `set -uo pipefail` (not `-e` — see above), a `fails` counter, and `pass`/
  `fail` helpers; exit non-zero at the end if `fails` is non-zero.
- `source` the library under test via a `TEST_DIR`-relative path, with the
  `# shellcheck source=` directive above it.
- Clean up containers, images and tmpdirs in a `trap … EXIT`.
- Prefer table-driven cases with a descriptive name per row, and print the
  discriminating values on failure — `want`/`got`, not just "assertion failed".
- `shellcheck -s bash -x -P tools <file>` must pass; that is what pre-commit
  runs, and `-x` is required or the sourced library is not followed.
