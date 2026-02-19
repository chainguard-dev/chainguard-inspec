# Chainguard GPOS STIG InSpec Profile

## Purpose

This repository provides a proof of concept InSpec profile and cinc-auditor image that evaluates chainguard container images against the DISA GPOS v3r2 requirements with controls that mirror the [chainguard-dev/stigs](https://github.com/chainguard-dev/stigs/releases/tag/v3.2.6) benchmark. The workflow extracts a container filesystem, runs InSpec controls with Cinc Auditor, and produces JSON and HTML outputs for evidence review.

## Components

- **Profile** `chainguard_stig/` contains control implementations, `inspec.yml`, and the `stig_mappings.rb` helper.
- **Dockerfile** builds the Wolfi-based Cinc Auditor image, embedding the STIG profile, benchmarks, HTML report generator, required glibc libraries, the `libcrypt.so.2` compatibility link, a cached Chef UUID, and the `/usr/local/bin/read-aslr` helper.
- **Scan script** `cinc-chainguard.sh` pulls images when they are not cached locally, exports the filesystem, captures host kernel information using the auditor image, invokes the profile inside Cinc Auditor and automatically generates HTML reports using the embedded report generator.
- **Report generator** `tools/generate_stig_html.rb` converts the JSON reporter output into a standalone HTML report that links STIG metadata from `benchmarks/`.
- **Benchmark data** `benchmarks/ssg-chainguard-gpos-ds.xml` supplies rule titles, descriptions, severities, and CCIs referenced in reports.

## Requirements

- **Docker** with permission to build the auditor helper image and to pull target container images.
- **Ruby 2.7+** (only required when running the developer workflow that generates HTML on the host).
- **Linux host** recommended for tmpfs extraction; macOS and Windows are supported using on-disk extraction.

## Building Auditor Images

Build the fully self-contained image (default runtime for the scan script):

```bash
docker build --platform linux/amd64 -t local/chainguard-cinc-auditor:latest .
```

## Usage

```bash
# Extract to disk (required on macOS)
./cinc-chainguard.sh --no-tmpfs <image> [label] [results-dir]

# Extract to tmpfs on Linux
./cinc-chainguard.sh <image>

# Generate HTML after a scan - done by default in the container and launch script
```

- **Options**
  - **`--use-tmpfs`** mounts the extraction workspace in `/dev/shm` when available.
  - **`--no-tmpfs`** forces extraction onto the local filesystem.
  - **`--tmpfs-base DIR`** overrides the tmpfs mount location.
- **Arguments**
  - **`image`** fully qualified image reference, optionally including digest.
  - **`label`** free-form environment marker used in report headers (default `dev`).
  - **`results-dir`** output directory for JSON and HTML artifacts (default `./results`).

Outputs follow the naming pattern `<image>-stig-<timestamp>.json` and `.html` in the chosen results directory.

## Execution Summary

1. `cinc-chainguard.sh` pulls the target image, exports its filesystem into a temporary rootfs, and normalizes sensitive file permissions.
2. The script captures the host ASLR setting by running the selected auditor image with `--entrypoint /usr/local/bin/read-aslr`; failures record `unavailable` in `.runtime_capture/aslr_setting`.
3. Cinc Auditor executes the profile with `--input rootfs=/rootfs`, writing JSON results under the results directory. When `EMBEDDED_PROFILE=true`, the embedded profile at `/opt/chainguard-stig/chainguard_stig` is used; otherwise the local `chainguard_stig/` directory is bind-mounted.
4. HTML generation runs either inside the container (embedded workflow) or on the host with `tools/generate_stig_html.rb`, enriching the JSON with STIG metadata and emitting a standalone dashboard.

## Controls and Coverage

| Control file                    | Objective                                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `AslrCheck.rb`                  | Validates that `kernel.randomize_va_space` equals `2` when the capture succeeds.                                  |
| `DetectOpenSslTest.rb`          | Confirms presence of FIPS OpenSSL configuration files and required packages, and prints their contents.           |
| `LibraryPermissionsTest.rb`     | Checks `/usr/lib` ownership and mode for compliance with root-only access.                                        |
| `NoUsersCheck.rb`               | Enumerates `/etc/passwd` entries to ensure only approved service accounts follow `nobody`.                        |
| `PackageSignatureTest.rb`       | Ensures every repository entry in `/etc/apk/repositories` uses HTTPS and documents file contents.                 |
| `RemoteAccessServicesTest.rb`   | Verifies that banned remote access packages are absent from the APK installed database.                           |
| `UserPasswordConfiguredTest.rb` | Confirms interactive accounts in `/etc/shadow` are disabled or locked.                                            |
| `VarLogPermissionsTest.rb`      | Reports ownership and permissions for `/var/log` and enforces `root:root` with expected mode.                     |
| `CaBundleHashTest.rb`           | Computes the SHA-256 hash of `etc/ssl/certs/ca-certificates.crt` and compares it to the expected reference value. |

STIG rule identifiers, severities, and CCIs are defined through `tag` metadata within each control and are surfaced in the HTML report alongside test evidence.

## Project Layout

```
chainguard-inspec/
├── controls/
├── inspec.yml
├── libraries/stig_mappings.rb
├── benchmarks/
├── tools/
│   ├── cinc-chainguard.sh
│   └── generate_stig_html.rb
├── results/
└── README.md
```

## Caveats

- **ASLR capture** uses the `chainguard-cinc-auditor` image's access to the host PID namespace; on macOS the value is usually recorded as `unavailable`, causing the ASLR control to skip.
- **APK-focused checks** assume the presence of `lib/apk/db/installed`; non-APK images will mark those tests as skipped.
- **This profile is not intended for runtime analysis** executing the profile directly on a live container is currently unsupported and is considered roadmap.

## Development Guidelines

- **Control updates**:
  - modify files under `chainguard_stig/controls/` and adjust `chainguard_stig/libraries/stig_mappings.rb` when STIG metadata changes.
  - update `chainguard_stig/inspec.yml` to customize input parameters.
- **Profile Validation**: run `cinc-auditor check /share/chainguard_stig` to validate the profile.

```bash
docker run --rm \
  -v "$(pwd):/share" \
  local/chainguard-cinc-auditor:latest \
  check /share/chainguard_stig
```

- **Testing**: re-run scans after modifications and review the resulting HTML evidence for regressions.

## License

This project is distributed under the Apache License 2.0. See `LICENSE` for the complete text.
