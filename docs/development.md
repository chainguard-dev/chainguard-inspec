# Development

Contributor-facing documentation for working on the Chainguard GPOS InSpec
profile. For consumer/usage instructions (requirements, running scans, coverage,
caveats), see the top-level [`README.md`](../README.md).

## Running the checks

A `Makefile` wraps the same checks CI runs so they can be reproduced locally:

```bash
make          # (= make ci) every check CI runs: static checks + Docker-based control tests
make fast     # static checks only (pre-commit hooks, actionlint, zizmor) — no Docker
make help     # list all targets
```

Individual targets can be run on their own: `make pre-commit`, `make actionlint`,
`make zizmor`, `make cinc-check`, `make tools-test`, `make controls`, and
`make rubocop`. Notes:

- `make controls` prefers a system `rspec` and falls back to `bundle exec rspec`.
- Override the scanner image with `CINC_AUDITOR_IMAGE=… make ci` (defaults to the
  public `cincproject/auditor:latest`, matching CI).
- The Docker-based targets need Docker; the filesystem-ownership control specs
  still require root / passwordless sudo (see [`testing.md`](testing.md)) and are
  otherwise skipped.
- Full `rubocop` (`make rubocop`) is **opt-in** and intentionally not part of
  `make ci` — see [Pre-commit hooks](#pre-commit-hooks).

## Guidelines

- **Control updates:** modify files under `controls/` and adjust
  `libraries/stig_mappings.rb` when STIG metadata changes; update `inspec.yml`
  to customize input parameters.
- **Profile validation:** run `cinc-auditor check` to validate the profile
  structure:

  ```bash
  docker run --rm \
    -v "$(pwd):/share" \
    cgr.dev/chainguard-private/cinc-auditor:latest \
    check /share/
  ```

- **Local profile testing:** use `--use-local-profile` with any scan script to
  bind-mount the local profile and generate reports with host Ruby instead of
  the embedded copy:

  ```bash
  ./tools/cinc-chainguard.sh --use-local-profile cgr.dev/chainguard/nginx:latest dev
  ```

- **Unit tests:** the controls have an rspec behavioural test suite under
  `test/` that runs each control against synthetic fixtures with cinc-auditor.
  See [`testing.md`](testing.md) for how to run it — including the root /
  passwordless-sudo requirement for the filesystem-ownership checks and how to
  point it at the cinc-auditor image.
- **Regression review:** re-run scans after modifications and review the
  resulting HTML evidence for regressions.

## Pre-commit hooks

A [pre-commit](https://pre-commit.com/) configuration is provided for local
development. Ensure `pre-commit`, `shellcheck`, and `rubocop` are available on
your system (`pre-commit` and `shellcheck` are available via your system package
manager, and `pre-commit` can also be installed via `uv` or `pip`; `rubocop` via
`gem install rubocop`), then enable the hooks with:

```bash
pre-commit install
```

The hooks that run **on every commit** enforce:

- Trailing whitespace removal, end-of-file newlines, and LF line endings
- YAML validity and merge conflict marker detection
- `shellcheck` linting of all shell scripts (uses the **system-installed**
  `shellcheck` binary rather than a bundled version fetched from the internet)
- A Ruby syntax check on all Ruby files (`rubocop --only Lint/Syntax`)

A full rubocop style review is configured at the **manual** stage so it does not
run on every commit. Run it on demand with:

```bash
pre-commit run --hook-stage manual
```

The full run is expected to surface ~300+ `Style/StringLiterals` offenses
(single → double quote conversions) and ~17 `Style/WordArray` suggestions on the
controls; these are known and can be addressed incrementally.
`controls/.rubocop.yml` intentionally disables cops that conflict with InSpec's
DSL structure (e.g. `Naming/FileName` for PascalCase control files,
`Lint/NestedMethodDefinition` for control-scoped helpers) — see that file for
the full list and rationale.
