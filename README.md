# Chainguard GPOS SRG InSpec Profile

## Purpose

This repository provides an InSpec profile to evaluate Chainguard container images against the DISA GPOS v3r2 requirements with controls that mirror the [chainguard-dev/stigs](https://github.com/chainguard-dev/stigs/releases/tag/v3.2.6) benchmark.

## Components

- **Profile:** `controls/` contains the control implementations along with the `inspec.yml` metadata file, and the `stig_mappings.rb` helper.
- **Scan scripts:** `tools/` provides four wrapper scripts that invoke the Chainguard cinc-auditor image to run the profile and generate HTML reports; see [Scan Scripts](#scan-scripts) for details.
- **Report generator:** `tools/generate_stig_html.rb` converts the JSON reporter output into a standalone HTML report.
- **Common library:** `tools/lib/cinc-common.sh` contains shared functions sourced by all scan scripts.

## Requirements

- **Docker** with permission to run the Chainguard cinc-auditor image and to pull target container images.
- **cinc-auditor image** (`cgr.dev/chainguard-private/cinc-auditor:latest`) pulled and accessible; override with the `CINC_AUDITOR_IMAGE` environment variable. This image is hosted in Chainguard's private registry and requires authenticated access to pull.
- **Elevated privileges.** Every scan runs the cinc-auditor container as `root` (uid 0 inside the container) and `--privileged`; `cinc-chainguard.sh` and `cinc-chainguard-overlay.sh` additionally need the script itself run as root. Granting a container `--privileged` or the Docker socket is root-equivalent on the host, so only scan images and hosts you trust. See [Required privileges](#required-privileges) for the per-script breakdown.

## Optional

- **Benchmark data** `ssg-chainguard-gpos-ds.xml` from https://github.com/chainguard-dev/stigs/ supplies rule titles, descriptions, severities, and CCIs referenced in generated HTML reports.
- **Ruby 2.7+** only required when using `--use-local-profile` (developer mode) to generate HTML reports on the host rather than inside the cinc-auditor container.

## Quick Start

Once requirements are in place, scan any Chainguard container image with the default script:

```bash
./tools/cinc-chainguard.sh cgr.dev/chainguard/nginx:latest
```

Results are written to `./results/` as both JSON and a standalone HTML report. Open the HTML report in a browser to view each test result alongside its STIG rule description, severity, and evidence.

`cinc-chainguard.sh` exports and scans the filesystem without running the container's workload, making it a safe default for any image. See [Scan Scripts](#scan-scripts) for other approaches and their tradeoffs.

### Customizing inputs

The profile's behavior is tuned through a handful of inputs, each with a
sensible default in `inspec.yml`; override any of them with an InSpec input
file.

The commented template [`examples/inputs.yml`](examples/inputs.yml) lists every
overridable input with its semantics. Copy it, edit the values for your image,
and pass it to a scan:

```bash
cinc-auditor exec <profile> --input-file my-inputs.yml --input rootfs=<path>
```

Each list-valued input **replaces** its default rather than extending it, so
keep the default entries you still want.

## Controls and Coverage

| Control file                    | Objective                                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `AslrCheck.rb`                  | Validates that `kernel.randomize_va_space` equals `2` when the capture succeeds.                                  |
| `DetectOpenSslTest.rb`          | Confirms presence of FIPS OpenSSL configuration files and required packages, and prints their contents.           |
| `LibraryPermissionsTest.rb`     | Checks `/usr/lib` ownership and mode for compliance with root-only ownership.                                     |
| `NoUsersCheck.rb`               | Enumerates `/etc/passwd` entries to ensure only approved service accounts follow `nobody`.                        |
| `PackageSignatureTest.rb`       | Ensures every repository entry in `/etc/apk/repositories` uses HTTPS and documents file contents.                 |
| `RemoteAccessServicesTest.rb`   | Verifies that banned remote access packages are absent from the APK installed database.                           |
| `UserPasswordConfiguredTest.rb` | Confirms interactive accounts in `/etc/shadow` are disabled or locked.                                            |
| `VarLogPermissionsTest.rb`      | Reports ownership and permissions for `/var/log` and enforces `root:root` with expected mode.                     |
| `CaBundleHashTest.rb`           | Computes the SHA-256 hash of `etc/ssl/certs/ca-certificates.crt` and compares it to the expected reference value. |

STIG rule identifiers, severities, and CCIs are defined through `tag` metadata within each control and are surfaced in the HTML report alongside test evidence.

## Scan Scripts

All scripts accept `<image> [label] [results-dir]` as positional arguments and write JSON and HTML results to the results directory (default: `./results`). Each script sources `tools/lib/cinc-common.sh` for shared functionality. Pass `--use-local-profile` to bind-mount the local profile directory instead of using the embedded profile in the cinc-auditor image (developer mode).

| Script                                | Approach                  | Platform           |
| ------------------------------------- | ------------------------- | ------------------ |
| `cinc-chainguard.sh`                  | Filesystem reconstruction | Linux, macOS       |
| `cinc-chainguard-live.sh`             | Live container via procfs | Linux, macOS       |
| `cinc-chainguard-overlay.sh`          | Live overlay2 filesystem  | Linux only         |
| `cinc-chainguard-docker-transport.sh` | Docker transport backend  | Linux, macOS, Windows |

### Required privileges

Every scan launches a cinc-auditor container that Docker runs `--privileged` and as `root` (uid 0 **inside** the container) so it can read every file in the target regardless of mode or owner. The flags below are in addition to needing Docker itself:

| Script | Run script as | `--privileged` | `--pid=host` | Docker socket | Why |
| ------------------------------------- | --------------------- | :---: | :---: | :---: | --- |
| `cinc-chainguard.sh`                  | **root** (`sudo`)     | yes | – | – | host-side `docker export \| tar` only preserves the image's real file ownership when run as root (a non-root run warns and the ownership controls become unreliable) |
| `cinc-chainguard-live.sh`             | Docker access¹        | yes | yes | – | reads the running container's rootfs via `/proc/<PID>/root` in the host PID namespace; the target **must stay running** for the whole scan |
| `cinc-chainguard-overlay.sh`          | **root** or `docker` group | yes | – | – | reads the root-owned overlay2 merged dir under `/var/lib/docker/overlay2/` (Linux + overlay2 driver only) |
| `cinc-chainguard-docker-transport.sh` | any Docker user       | yes | – | **yes** | reaches the target only over the `docker://` backend; the bind-mounted Docker socket is the (inherent) root-equivalent grant |

¹ Under **rootful** Docker the container's uid 0 is real host root, so `/proc/<PID>/root` is readable even when you invoke the script as a non-root member of the `docker` group. Under **rootless** Docker that uid 0 maps to your unprivileged user, so reading another container's `/proc/<PID>/root` requires running as real root.

> **Trust posture.** These are local developer/scanning tools, not a sandbox. `--privileged` (all Linux capabilities, device access, relaxed seccomp/AppArmor) and a bind-mounted Docker socket each grant the cinc-auditor container root-equivalent control of the host. Only run them against container images and on hosts you trust. The blanket `--privileged` grant is broader than the read-only bind-mount scans strictly need; narrowing it to the specific capabilities each mode requires is a tracked follow-up.

### `cinc-chainguard.sh` — Filesystem reconstruction

Exports the container image filesystem via `docker export`, extracts it to a tmpfs directory (or on-disk with `--no-tmpfs`), captures the host ASLR setting, and runs cinc-auditor against the extracted rootfs. Suitable for all images including distroless and short-lived containers.

```bash
sudo ./tools/cinc-chainguard.sh cgr.dev/chainguard/nginx:latest dev
sudo ./tools/cinc-chainguard.sh --no-tmpfs cgr.dev/chainguard/nginx:latest dev
```

**Privileges:** run as root (e.g. `sudo`, as shown) so the extracted rootfs keeps the image's real file ownership; see [Required privileges](#required-privileges). A non-root run prints a warning and continues, but the ownership controls (`LibraryPermissionsTest`, `VarLogPermissionsTest`) will be unreliable because every extracted file ends up owned by the invoking user.

### `cinc-chainguard-live.sh` — Live container

Starts the container's actual workload, then runs cinc-auditor using `--pid=host` to access the filesystem via `/proc/<PID>/root`. ASLR is read from the target container's mounted `/proc` without any capture or injection step. All filesystem access happens inside the cinc-auditor container, so no host-side overlay2 path is required.

> **Warning:** Do not use with images that have undesirable side-effects when run; use `cinc-chainguard.sh` for those instead.

```bash
./tools/cinc-chainguard-live.sh cgr.dev/chainguard/nginx:latest dev
```

**Privileges:** needs Docker access; the auditor runs `--privileged --pid=host` to reach `/proc/<PID>/root` (requires real root under rootless Docker — see [Required privileges](#required-privileges)).

**The target must stay running for the entire scan.** Its filesystem is read live through `/proc/<PID>/root`, so if the workload exits early — for example a service that needs configuration or a backend to stay up, or an image whose entrypoint completes immediately — that path disappears and the controls report empty results (everything "found nothing") rather than a clear error. For short-lived, distroless, or non-self-sustaining images, use one of the other approaches instead. If a live scan returns nothing, check `docker ps -a` for the target: a `cinc-chainguard-live`-started container in an `Exited` state is the tell.

### `cinc-chainguard-overlay.sh` — Live overlay filesystem

Reads the container's overlay2 merged directory directly via `docker inspect GraphDriver.Data.MergedDir`, avoiding full filesystem extraction. Faster than export/tar for large images. Requires a Linux host with Docker using the overlay2 storage driver and root or equivalent privileges to read paths under `/var/lib/docker/overlay2/`. Does not work with Docker Desktop on macOS or Windows.

```bash
sudo ./tools/cinc-chainguard-overlay.sh cgr.dev/chainguard/nginx:latest dev
```

**Privileges:** run as root or as a member of the `docker` group — the overlay2 merged directory under `/var/lib/docker/overlay2/` is root-owned. See [Required privileges](#required-privileges).

### `cinc-chainguard-docker-transport.sh` — Docker transport

Extracts a statically-linked busybox binary from a helper image (default: `cgr.dev/chainguard/busybox-static:latest`), starts the target container with busybox bind-mounted at the paths cinc-auditor requires, and connects via the `docker://` transport backend. Works on Linux, macOS, and Windows (Docker Desktop). Useful when the target image lacks basic utilities.

```bash
./tools/cinc-chainguard-docker-transport.sh cgr.dev/chainguard/crane:latest dev
```

Override the busybox source via environment variables — for example, to use Docker Hub's `busybox:musl` instead of the default Chainguard image:

```bash
BUSYBOX_SOURCE_IMAGE=busybox:musl BUSYBOX_BINARY_PATH=/bin/busybox \
  ./tools/cinc-chainguard-docker-transport.sh cgr.dev/chainguard/crane:latest dev
```

**Privileges:** can run as any user with Docker access — no extra privileges beyond Docker itself. The auditor mounts the Docker socket, which is root-equivalent on the host, and runs `--privileged`. See [Required privileges](#required-privileges).

## Caveats

### Possible differences between the XCCDF and InSpec profile

This profile is intended to be comparable to the Chainguard XCCDF GPOS profile; however, there are some subtle differences in evaluation that may cause differences in results. In particular:

- `NoUsersCheck.rb` examines both `/etc/passwd` and `/etc/shadow` for unexpected users, whereas the XCCDF profile just looks at `/etc/shadow`. The InSpec profile also will consider users added by apko as part of the image build process as intended added users, while the XCCDF is not currently capable of doing so.
- `DetectOpenSslTest.rb` is able to look for correct openssl.cnf ini configurations, whereas the XCCDF profile does simple pattern matching.

### ASLR capture

The `AslrCheck.rb` control attempts to read the kernel ASLR setting from the filesystem being scanned:

1. `${rootfs}/proc/sys/kernel/randomize_va_space` — available when the container has `/proc` mounted (e.g. live scans via `cinc-chainguard-live.sh`).
2. `${rootfs}/.runtime_capture/aslr_setting` — a file injected at scan time by `cinc-chainguard.sh` after capturing the value from the host kernel.
3. `/proc/sys/kernel/randomize_va_space` directly on the host — available when the `allow_host_aslr_fallback` input is `true` (set automatically by `cinc-chainguard-overlay.sh`).

If none of these sources is available the control skips.

### APK-focused checks

This profile targets Chainguard (Wolfi-based) images and requires the APK package database at `/usr/lib/apk/db/installed`. Non-APK-based images will fail these controls. The same limitation applies to the XCCDF profile this one is derived from.

### Keeping an image alive to be evaluated

Some images to be examined may not have a long-running process or are quite involved to set up. The `cinc-chainguard-docker-transport.sh` script handles this automatically by starting the container with `busybox sleep infinity` as the entrypoint.

For manual `docker://` transport scans without the wrapper script, a tool like [`anchore-keep-alive`](https://github.com/anchore/anchore-keep-alive) can be used; build it locally, and bind mount it into the container as the entrypoint.

## Project Layout

```
chainguard-inspec/
├── controls/
├── inspec.yml
├── examples/
│   └── inputs.yml         # template for overriding profile inputs
├── libraries/
│   ├── find_helper.rb
│   └── stig_mappings.rb
├── tools/
│   ├── cinc-chainguard.sh
│   ├── cinc-chainguard-live.sh
│   ├── cinc-chainguard-overlay.sh
│   ├── cinc-chainguard-docker-transport.sh
│   ├── generate_stig_html.rb
│   └── lib/
│       └── cinc-common.sh
├── test/                  # rspec control test suite (see docs/testing.md)
├── docs/                  # contributor documentation
├── results/
└── README.md
```

## Contributing

Developer documentation — control authoring guidelines, the rspec unit-test
suite, pre-commit hooks, and lint/style workflow — lives under [`docs/`](docs/):

- [`docs/development.md`](docs/development.md) — development guidelines,
  profile validation, and pre-commit hooks.
- [`docs/testing.md`](docs/testing.md) — running the rspec control test suite.

## License

This project is distributed under the Apache License 2.0. See `LICENSE` for the complete text.
