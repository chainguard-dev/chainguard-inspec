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

### `cinc-chainguard.sh` — Filesystem reconstruction

Exports the container image filesystem via `docker export`, extracts it to a tmpfs directory (or on-disk with `--no-tmpfs`), captures the host ASLR setting, and runs cinc-auditor against the extracted rootfs. Suitable for all images including distroless and short-lived containers.

```bash
./tools/cinc-chainguard.sh cgr.dev/chainguard/nginx:latest dev
./tools/cinc-chainguard.sh --no-tmpfs cgr.dev/chainguard/nginx:latest dev
```

### `cinc-chainguard-live.sh` — Live container

Starts the container's actual workload, then runs cinc-auditor using `--pid=host` to access the filesystem via `/proc/<PID>/root`. ASLR is read from the target container's mounted `/proc` without any capture or injection step. All filesystem access happens inside the cinc-auditor container, so no host-side overlay2 path is required.

> **Warning:** Do not use with images that have undesirable side-effects when run; use `cinc-chainguard.sh` for those instead.

```bash
./tools/cinc-chainguard-live.sh cgr.dev/chainguard/nginx:latest dev
```

### `cinc-chainguard-overlay.sh` — Live overlay filesystem

Reads the container's overlay2 merged directory directly via `docker inspect GraphDriver.Data.MergedDir`, avoiding full filesystem extraction. Faster than export/tar for large images. Requires a Linux host with Docker using the overlay2 storage driver and root or equivalent privileges to read paths under `/var/lib/docker/overlay2/`. Does not work with Docker Desktop on macOS or Windows.

```bash
./tools/cinc-chainguard-overlay.sh cgr.dev/chainguard/nginx:latest dev
```

### `cinc-chainguard-docker-transport.sh` — Docker transport

Extracts a statically-linked busybox binary from a helper image (default: `busybox:musl`), starts the target container with busybox bind-mounted at the paths cinc-auditor requires, and connects via the `docker://` transport backend. Works on Linux, macOS, and Windows (Docker Desktop). Useful when the target image lacks basic utilities.

```bash
./tools/cinc-chainguard-docker-transport.sh cgr.dev/chainguard/crane:latest dev
```

Override the busybox source via environment variables:

```bash
BUSYBOX_SOURCE_IMAGE=busybox:musl BUSYBOX_BINARY_PATH=/bin/busybox \
  ./tools/cinc-chainguard-docker-transport.sh cgr.dev/chainguard/crane:latest dev
```

## Caveats

### Possible differences between the XCCDF and InSpec profile

This profile is intended to be comparable to the Chainguard XCCDF GPOS profile; however, there are some subtle differences in evaluation that may cause differences in results. In particular:

- `NoUsersCheck.rb` examines both `/etc/passwd` and `/etc/shadow` for unexpected users, whereas the XCCDF profile just looks at `/etc/shadow`. The InSpec profile also will consider users added by apko as part of the image build process as intended added users, while the XCCDF is not currently capable of doing so.
- `DetectOpenSslTest.rb` is able to look for correct openssl.cnf ini configurations, whereas the XCCDF profile does simple pattern matching.

### Using binary distributions of InSpec / cinc-auditor

**Use the Chainguard cinc-auditor image to avoid this issue.** When performing runtime scanning of containers using a remote backend (e.g. `docker://`, `k8s-container://`), cinc-auditor did not correctly detect Chainguard images, causing filesystem object examinations to fail. This was fixed in the upstream inspec-train ruby gem in https://github.com/inspec/train/pull/812 and released in [v3.14.1](https://rubygems.org/gems/train/versions/3.14.1); however, the most recent binary release of cinc-auditor [7.0.95](http://downloads.cinc.sh/files/stable/cinc-auditor/) has not been rebuilt with the fixed version of the train gem and will break. The Chainguard cinc-auditor image and source-built versions incorporate the necessary fix.

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
