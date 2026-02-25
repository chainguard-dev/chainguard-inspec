# Chainguard GPOS SRG InSpec Profile

## Purpose

This repository provides an InSpec profile to evaluate Chainguard container images against the DISA GPOS v3r2 requirements with controls that mirror the [chainguard-dev/stigs](https://github.com/chainguard-dev/stigs/releases/tag/v3.2.6) benchmark.

## Components

- **Profile** `controls/` contains the control implementations along with the `inspec.yml` metadata file, and the `stig_mappings.rb` helper.
- **Report generator** `tools/generate_stig_html.rb` converts the JSON reporter output into a standalone HTML report.

XXX - drop some of below but also recreate wrapper scripts that work with the public chainguard cinc-auditor image

- **Dockerfile** builds the Wolfi-based Cinc Auditor image, embedding the STIG profile, benchmarks, HTML report generator, required glibc libraries, the `libcrypt.so.2` compatibility link, a cached Chef UUID, and the `/usr/local/bin/read-aslr` helper.
- **Scan script** `cinc-chainguard.sh` pulls images when they are not cached locally, exports the filesystem, captures host kernel information using the auditor image, invokes the profile inside Cinc Auditor and automatically generates HTML reports using the embedded report generator.

## Requirements

- **cinc-auditor** or **inspec** available to run [XXX - link to public image when ready]; see Caveats section if using a binary distribution of cinc-auditor.

## Optional

- **Benchmark data** `ssg-chainguard-gpos-ds.xml` from https://github.com/chainguard-dev/stigs/ supplies rule titles, descriptions, severities, and CCIs referenced in generated html reports.
- **Docker** with permission to build the auditor helper image and to pull target container images.
- **Ruby 2.7+** (only required when running the developer workflow that generates HTML on the host).
- **Linux host** recommended for tmpfs extraction; macOS and Windows are supported using on-disk extraction.

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

## Caveats

### Possible differences between the XCCDF and InSpec profile.

This profile is intended to be comparable to the Chainguard XCCDF GPOS profile; however, there are some subtle differences in evaluation that may cause differences in results. In particular:

- `NoUsersCheck.rb` examines both `/etc/passwd` and `/etc/shadow` for unexpected users, whereas the XCCDF profile just looks at `/etc/shadow`. The InSpec profile also will consider users added by apko as part of the image build process as intended added users, while the XCCDF is not currently capable of doing so.
- DetectOpenSslTest.rb` is able to look for correct openssl.cnf ini configurations, whereas the XCCDF profile does simple pattern matching.

### Using binary distributions of InSpec / cinc-auditor

When performing runtime scanning of containers using a remote backend (e.g. `docker://`, `k8s-container://`), cinc-auditor did not correctly detect Chainguard images and so examinations of file system objects would fail. This was fixed in the upstream inspec-train ruby gem in https://github.com/inspec/train/pull/812 and was released in [v3.14.1](https://rubygems.org/gems/train/versions/3.14.1); however, the most recent binary release of cinc-auditor [7.0.95](http://downloads.cinc.sh/files/stable/cinc-auditor/) has not been rebuilt with the fixed version of the train gem, and so will break. Building and deploying cinc-auditor from source (or using the publicly available Chaingaurd cinc-auditor image) will incorporate the necessary fix.

### Runtime image scanning issues

InSpec as a tool and this profile are intended to be run against live containers. However, Chainguard container images are intended to be minimal, and thus a significant percentage of images do not include low level utilities needed for cinc-auditor to correctly perform its scans.

There are a few different ways to compensate for this.

#### Perform the evaluation on a `-dev` variant of the image

This should include enough utilities to permit cinc-auditor to evaluate the image with this profile.

#### Bind mount statically linked utilities into the image

If the system that is performing the evaluation has statically linked busybox installed (e.g. `apt install busybox` on Debian/Ubuntu), it can be bind mounted into the container image to provide the needed utilies for cinc-auditor to perform its scan. Specifically, the profile and cinc-auditor need a working `/bin/sh`, `/usr/bin/uname`, and `/usr/bin/stat`.

An example under docker:

```
$ docker run -it --rm --name target \
     -v /usr/bin/busybox:/bin/sh \
     -v /usr/bin/busybox:/usr/bin/uname \
     -v /usr/bin/busybox:/usr/bin/stat \
     --entrypoint /bin/sh \
     cgr.dev/chainguard/crane:latest

# [in another shell]
$ cinc-auditor exec . -t docker://target \
     --user root  --reporter json:results/output.json --no-create-lockfile
```

#### Perform the scan against the merged filesystem

The Chainguard InSpec profile supports setting an alternate top root directory for local scans, using the `--input rootfs=/rootfs` argument to cinc-auditor.

Example using docker:

```
$ docker run -it --rm --name target \
     --entrypoint jshell \
     cgr.dev/chainguard/jdk:latest


# in another shell
$ MERGED=$(docker inspect target --format '{{.GraphDriver.Data.MergedDir}}')
$ cinc-auditor exec .  \
     --no-create-lockfile \
     --reporter json:results/output.json \
     --input "rootfs=$MERGED"
```

#### Export the image filesystem for evaluation

[this is what cinc-chainguard.sh did]

### Keeping an image alive to be evaluated

Some images to be examined may not have a long-running process or are quite involved to set up, but may not have basic utilities that can be used as the entrypoint to keep the container from exiting while cinc-auditor performs its scan.

To compensate for this a tool like [`anchore-keep-alive`](https://github.com/anchore/anchore-keep-alive) can be used; build it locally, and bind mount it into the container and use it for the entrypoint.

An example with docker:

```
$ docker run -it --rm --name target \
     -v /PATH/TO/anchore-keep-alive:/anchore-keep-alive \
     --entrypoint /anchore-keep-alive \
     cgr.dev/chainguard/crane:latest

$ cinc-auditor exec . -t docker://target \
     --user root  --reporter json:results/output.json --no-create-lockfile
```

### ASLR capture

The `AslrCheck.rb` control attempts to read an attribute about the kernel that is running underneath the container under examination, specifically via the ProcFS file system interface. If that's not available, the ASLR control will skip, unless the value is captured and injected into the image at `/.runtime_capture/aslr_setting`.

### APK-focused checks

As the profile is intended for use on Chainguard (aka Wolfi) images, the assumption for validating whether specific packages are or are not installed in the environment assume the presence of the APK package database in `/lib/apk/db/installed`; non-APK based images will fail these controls. (This is also true for the XCCDF profile the Inspec profile is derived from.)

## Project Layout

```
chainguard-inspec/
├── controls/
├── inspec.yml
├── libraries/stig_mappings.rb
├── tools/
│   ├── cinc-chainguard.sh
│   └── generate_stig_html.rb
├── results/
└── README.md
```

## Development Guidelines

- **Control updates**:
  - modify files under `controls/` and adjust `libraries/stig_mappings.rb` when STIG metadata changes.
  - update `inspec.yml` to customize input parameters.
- **Profile Validation**: run `cinc-auditor check /share/` to validate the profile.

```bash
docker run --rm \
  -v "$(pwd):/share" \
  local/chainguard-cinc-auditor:latest \
  check /share/
```

- **Testing**: re-run scans after modifications and review the resulting HTML evidence for regressions.

## License

This project is distributed under the Apache License 2.0. See `LICENSE` for the complete text.
