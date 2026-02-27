# InSpec Controls Developer Reference

You are helping develop or maintain InSpec controls for the Chainguard GPOS STIG
compliance profile.  Read this document before writing or modifying any control.

---

## Profile overview

This profile evaluates Chainguard (Wolfi-based) container images against the
DISA GPOS v3r2 STIG.  Controls live in `controls/`.  The profile is run by
cinc-auditor (or inspec) against container filesystems, not live processes.

---

## The rootfs input pattern

All controls must access the target filesystem through the `rootfs` input, not
through absolute paths.  The rootfs value is the path where the target
filesystem is mounted inside the cinc-auditor container.

```ruby
rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
some_path = File.join(rootfs, 'etc/passwd')
```

`File.join` is used only to construct path strings.  File *access* always goes
through InSpec's resource helpers, never Ruby's `File` class directly:

```ruby
# Correct — transport-aware, works for docker://, ssh://, local
describe file(some_path) do
  it { should exist }
end

# Wrong — bypasses InSpec's transport layer
File.read(some_path)
```

This matters because InSpec's `file()`, `directory()`, `command()`, etc.
resolve paths against the target system on remote transports.

---

## Control structure

```ruby
control 'oval:org.SomeName:def:N' do
  impact 0.5          # 0.1 low / 0.5 medium / 0.7 high / 1.0 critical
  title 'Short title'
  desc  'One-sentence description of what is being verified.'

  tag stig_rules: [
    'SV-203754r958928_rule',
    'SV-203753r958928_rule'
  ]
  tag stig_severities: ['medium']
  tag ccis: ['CCI-002824']

  rootfs = ENV['ROOTFS_DIR'] || input('rootfs')
  # ... setup ...

  only_if('Reason this control is skippable') { precondition }

  describe something do
    # ... assertions ...
  end
end
```

Control IDs follow the `oval:org.<Name>:def:<N>` convention to match the XCCDF.
File names use PascalCase (`AslrCheck.rb`, `NoUsersCheck.rb`) — this is the
InSpec convention for this profile and is intentionally exempted from rubocop's
`Naming/FileName` cop.

---

## STIG tag metadata

Rule IDs, severities, and CCIs come from the XCCDF benchmark at
`benchmarks/ssg-chainguard-gpos-ds.xml` (optional; used by the HTML report
generator).  When adding or updating a control, find the corresponding Rule
elements in the XCCDF and copy their IDs and CCI references.

```ruby
tag stig_rules:      ['SV-...']          # one or more rule IDs
tag stig_severities: ['medium']          # low / medium / high
tag ccis:            ['CCI-000001']      # CCI identifiers from the rule
```

---

## Evidence capture

InSpec test output forms the audit evidence.  Controls should document *what
they found*, not just pass or fail.

### Showing file contents

```ruby
content = file(path).content.strip
describe "File: #{File.basename(path)} (#{content.lines.count} lines)" do
  it "Full contents:\n#{content}" do
    expect(content.length).to be_positive
  end
end
```

### Enumerating findings with per-item results

```ruby
items.each do |item|
  describe "Item: #{item[:name]}" do
    it "status: #{item[:ok] ? 'OK' : 'FAIL'}" do
      if item[:ok]
        expect(true).to eq true                          # always-pass evidence
      else
        expect(false).to eq(true), "reason: #{item[:reason]}"   # controlled failure
      end
    end
  end
end
```

### Always-pass and always-fail idioms

**Use `expect(true).to eq true`** to record passing evidence without a real
assertion.  An empty `it` block would show 0 expectations in the report.

**Use `expect(false).to eq(true), message`** to deliberately fail with a clean
message.  Do NOT use `fail message` or `raise` — these produce an unhandled
exception whose backtrace appears in the JSON output and alarms end users even
though the semantic result is the same.

### Summary describe block

End complex controls with a summary assertion that rolls up the findings:

```ruby
describe 'Compliance summary' do
  it "should have no violations (found: #{found.length}, ok: #{ok.length}, bad: #{bad.length})" do
    expect(bad).to be_empty, "Found #{bad.length} violation(s): #{bad.join(', ')}"
  end
end
```

---

## Skipping controls with only_if

```ruby
only_if('APK database must be present') { file(installed_db_path).exist? }
```

Place `only_if` after the tag metadata and before any resource setup that would
fail if the precondition is not met.  The argument is the skip message shown in
the report.

---

## APK package database

Controls that check installed packages read `/lib/apk/db/installed`:

```ruby
installed_db_path = File.join(rootfs, 'lib/apk/db/installed')
installed_db = file(installed_db_path)
```

Package entries start with `P:` followed by the package name and optional
version suffix.  Match with:

```ruby
pattern = /^P:#{Regexp.escape(pkg_name)}(?:-[\w\.+~:]+)?$/
lines.any? { |line| line.match?(pattern) }
```

Non-APK images will fail APK-based controls (same behaviour as the XCCDF
profile).

---

## Helper methods inside control blocks

Defining methods inside a `control do...end` block is idiomatic InSpec for
control-scoped helpers.  They are not available outside the control.

```ruby
control 'oval:org.Example:def:1' do
  def normalize_url(url)
    url.sub(%r{^(https?://)([^@]+@)}, '\1')
  end

  # use normalize_url below...
end
```

`Lint/NestedMethodDefinition` is disabled in `controls/.rubocop.yml` for this
reason.

---

## Running and validating the profile

Validate profile structure (no cinc-auditor image needed locally if using the
public Chainguard cinc-auditor image):

```bash
cinc-auditor check .
```

Run against an extracted filesystem:

```bash
cinc-auditor exec . --no-create-lockfile \
  --reporter json:results/output.json \
  --input "rootfs=/path/to/rootfs"
```

See `tools/cinc-chainguard.sh` (extract), `tools/cinc-chainguard-overlay.sh`
(overlay), and `tools/cinc-chainguard-live.sh` (live) for complete scan
workflows.

---

## Rubocop and pre-commit

On every commit: shellcheck (shell scripts) and `rubocop --only Lint/Syntax`
(Ruby files) run automatically.

Full rubocop style review (runs only on demand):

```bash
pre-commit run --hook-stage manual
```

Controls are expected to produce ~300+ `Style/StringLiterals` offenses (single
→ double quote conversions) and ~17 `Style/WordArray` suggestions on a full
run; these are known and can be addressed incrementally.  `controls/.rubocop.yml`
intentionally disables cops that conflict with InSpec's DSL structure —
see that file for the full list and rationale.
