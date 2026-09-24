# Releasing

Releases are cut by two workflows. You dispatch the first; merging the PR it
opens triggers the second.

## The invariant

`inspec.yml`'s `version:` is the profile version every scan report carries. It
is expected to equal the `vX.Y.Z` tag of the release the profile was cut from.

That used to be maintained by hand, and it drifted: the profile sat at `0.0.4`
across four releases while tags reached `v1.0.4`. The cost was real — a report's
`version:` field could not distinguish two profiles that behaved differently,
which turned an ordinary "which profile produced this?" question into a
forensic exercise (see
[Testing](testing.md#scan-scripts-default-to-the-profile-baked-into-the-auditor-image)).
Both workflows exist to keep that from happening again: `prepare-release` sets
the version, and `create-release` refuses to tag if it does not match.

## Cutting a release

1. **Actions → Prepare Release → Run workflow.**

   Leave **version** empty to take the derived suggestion, or type an explicit
   `X.Y.Z`. Either way the workflow refuses to proceed if the tag already
   exists.

2. **Review the PR.** It changes one line of `inspec.yml`. The body records the
   version, the bump level, and — when derived — which commit implied it, so
   the suggestion can be checked rather than taken on trust. The full Control
   Tests suite runs on it.

   If the version is wrong, see [Declining the derived
   version](#declining-the-derived-version) below. Nothing is tagged until a
   prerelease PR merges.

3. **Merge it.** `create-release` then re-checks that `inspec.yml` records the
   version the branch name claims, confirms the profile still loads under
   `cinc-auditor`, and creates tag `vX.Y.Z` plus a GitHub Release with
   generated notes, targeting the merge commit.

## How the version is derived

With the **version** field left empty, `tools/release-version.rb next` reads
the conventional commits since the newest `vX.Y.Z` tag and takes the largest
bump any single commit implies:

| Commit shape | Bump |
|---|---|
| `feat!: …`, `fix!: …`, any type with `!`, or a `BREAKING CHANGE:` footer | major |
| `feat: …` or `feat(scope): …` | minor |
| anything else | patch |

The derivation is a *suggestion with its reasoning attached*, not an authority:
it names the commit that triggered the bump, and you can always override it by
typing a version. It fails rather than guessing when there are no commits since
the last tag.

Because the bump is computed from commit subjects, a release's version is only
as good as the commit messages behind it. Check the derived bump against what
actually changed before merging — particularly that a user-visible behaviour
change landed as `feat:` rather than `fix:`.

## Declining the derived version

The derived version is only ever a proposal on a branch. To release something
else instead:

1. **Close the prerelease PR, and delete its branch.** The "Delete branch"
   button appears on the closed PR; `git push origin --delete
   prerelease/vX.Y.Z` does the same thing.
2. **Dispatch Prepare Release again**, this time typing the version you want
   into the **version** field.

Deleting the branch is not tidiness. A closed prerelease PR keeps its `release`
label, and `create-release` fires on any merged PR that has that label and a
`prerelease/v*` branch. Reopening and merging an abandoned one later would cut
that release for real — and the profile-version assertion would *pass*, because
the branch's own `inspec.yml` matches its own branch name. Deleting the branch
makes the PR unreopenable, which closes that path.

`create-release` does not rely entirely on you remembering. It also refuses to
tag a version that does not come after the newest existing tag, and
`prepare-release` applies the same rule at dispatch so a mistyped version fails
immediately rather than after review and merge.

Be clear about what that does and does not cover. It catches a stale PR for a
version the project has since passed — you declined `1.0.5`, released `1.1.0`,
and the old PR is reopened later. It does **not** catch a stale PR for a
version still ahead of the current release, which is the more likely shape: you
declined a derived `1.1.0` as too large, released `1.0.5`, and the abandoned
`1.1.0` PR still satisfies every check if someone merges it. Deleting the
branch is what closes that case. That is why it is step 1 and not a tidiness
note.

The one thing that rule rules out is cutting a patch on an older line — `1.0.5`
once `1.1.0` exists. That suits a repo which releases only from `main`, and is
the check to revisit if backport releases ever become a thing.

There is no way to decline a version after the prerelease PR has merged: the
tag and the release are created immediately. Reverting a release means cutting
a new one.

## The tooling

`tools/release-version.rb` is the single implementation of every version
operation the workflows perform, so neither embeds an untestable `sed` and
neither carries its own copy of "what a valid version looks like":

```console
$ tools/release-version.rb get             # what inspec.yml records
1.0.4
$ tools/release-version.rb set 1.1.0       # rewrite it (idempotent)
$ tools/release-version.rb next            # derive the next version
1.1.0
$ tools/release-version.rb validate v1.1.0 # normalise, or fail
1.1.0
$ tools/release-version.rb assert-newer 1.1.0   # refuse to go backwards
1.1.0 comes after v1.0.4
```

Its logic is unit-tested in `test/spec/tools/release_version_spec.rb`, which
runs as part of `make controls`. The metadata cases exercise the repo's real
`inspec.yml` and the derivation cases build a throwaway git repository, so
`git log`'s own output drives the parser rather than a fixture written from the
same assumptions as the code.

## Permissions

Both workflows mint a short-lived token through
[octo-sts](https://github.com/octo-sts), configured by the policies in
`.github/chainguard/`. `prepare-release` needs one because a PR opened with
`GITHUB_TOKEN` does not trigger other workflows, so Control Tests would never
run on the release PR.

`create-release` is split into two jobs: `validate` runs repository code with
no token, and `release` holds the token and runs nothing but `gh release
create`.

## Why not derive the version from the tag instead?

`melange` and `apko` — same org, and worth comparing — have no bump commit at
all: their version is stamped into the binary from the tag at build time via
ldflags, so no file in the tree records it and there is nothing to keep in
sync.

That does not transfer here. This profile *is* the artifact, and `inspec.yml`
is part of it; consumers read `version:` out of scan reports. So
`chainguard-inspec` is structurally the `chainguard-dev/stigs` case — a version
held in a tracked file — and these workflows follow the pattern used there.

## Checklist for a release that is more than a version bump

- `README.md` — does anything describe behaviour that changed?
- `docs/testing.md` — new harness gotchas worth recording?
- `examples/inputs.yml` — do the documented inputs still match `inspec.yml`?
