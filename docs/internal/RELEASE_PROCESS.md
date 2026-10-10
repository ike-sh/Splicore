# Splicore Release Process

> INTERNAL MAINTAINER DOCUMENT
>
> This document is the authoritative release workflow for Splicore.
> Before any release, publication, version tag, GitHub Release, release asset
> or lean public export task, read this document in full. Do not proceed if
> it is unavailable.
>
> Classification: INTERNAL_MAINTENANCE. Public export: EXCLUDE.

Clear, deliberate instructions in the current maintainer request override
runbook defaults. A release check failing is not permission to change those
defaults or to expand the authorized task.

## Documentation responsibilities

| Surface | Responsibility |
| --- | --- |
| README.md | Stable product identity, capabilities, build and documentation entry points |
| Public technical docs | Usage, configuration, operations, integration, architecture and detailed capability limits |
| GitHub Releases | Version highlights, fixes, compatibility changes, downloads, checksums and relevant version warnings |
| This runbook | Internal maintainer release workflow |

README is not a changelog. Do not add version-specific update lists, current
release notes or release engineering state to it. Update README only when
product identity, meaningful capability scope, build instructions or public
documentation structure changes. An implementation fix may need no README edit.

## Internal source and public release trees

The internal development tree and public release tree are distinct.
The internal tree legitimately retains production source, tests, fixtures,
fuzz inputs, validation assets, review evidence references, maintainer documents
and release tooling.

The public release tree contains only approved production Core source, required
build inputs and runtime assets, native public distribution assets, licenses
and attribution, public user/operator/integration/architecture documentation
and public repository metadata.

Lean public export is **allowlist first**. Classify each retained path with a
reason; removing a few known internal files is insufficient. Preserve required
runtime embeddings and legal payloads. Check the resulting public surface,
including README link closure, for internal documents, evidence, local paths
and maintenance metadata before requesting independent review.

These exclusion rules apply to future exports:

| Path | Classification | Public export |
| --- | --- | --- |
| docs/internal/RELEASE_PROCESS.md | INTERNAL_MAINTENANCE | EXCLUDE |
| docs/internal/** | INTERNAL_MAINTENANCE | EXCLUDE unless a future file is explicitly reclassified |
| AGENTS.md | INTERNAL_MAINTENANCE | EXCLUDE |

Apply these rules to an existing export classifier when one exists, and verify
the actual exported tree obeys them. The runbook and AGENTS instructions are
policy; they do not automatically filter an export. Never add README links to
these excluded files or to validation/review reports. Resolve public links to
real retained documents; do not invent documents just to satisfy links.

## Release sequence

Each stage requires recorded evidence and a passing gate before the next stage.

1. Select and record the exact frozen internal source base.
2. Prepare the lean public export and its path classification manifest.
3. Obtain independent public surface review of the candidate tree.
4. If review finds a production source issue, fix it internally and prepare a
   corrected export. Preserve evidence of the failed candidate.
5. Re-review changed candidates until all required review findings are resolved.
6. Freeze the reviewed public tree, intended public parent and exact public
   release commit. Independent review must precede this freeze.
7. Build official release artifacts from that exact frozen **public commit**
   in a clean source checkout.
8. Verify the artifacts, legal contents, binary identity and checksum manifest.
9. Update public main to the approved commit using the authorized history model.
10. Create and publish the intended annotated version tag on that commit.
11. Create the GitHub Release with approved user-facing release notes.
12. Upload the exact approved official custom asset set.
13. Redownload every official custom asset from GitHub.
14. Verify byte/hash identity against the locally approved artifacts, including
    SHA256SUMS itself. Verify the downloaded archives against that manifest.
15. Seal external publication evidence and record the final public state.

If a stage fails, follow the failure policy below. Do not skip review, artifact
verification or integrity verification to finish publication.

## Public identity and history

The reviewed public **tree** and intended public **parent** are independent
identities. Record their exact OIDs and the resulting commit OID separately.
The internal commit is source provenance, not automatically public ancestry.

If an internal commit contains files that must not enter public history,
construct the public release commit from the exact reviewed public tree and
the exact intended public parent. Verify the resulting tree, sole intended
parent, commit identity and ancestry before publication. Do not publish the
internal commit merely because it supplied the production bytes.

After freeze: no amend, rebase, squash or history rewrite. A corrected source
candidate requires renewed review and a new freeze. Use ordinary fast-forward
updates when possible. Do not use a generic force push. Any deliberate public
history transition needs separate explicit authorization, exact expected old
and new OIDs, and a push safeguard bound to the expected remote OID. Never
rewrite a tag automatically.

## Official targets and assets

Current official binary policy is **Linux Core only**:

- linux/amd64
- linux/arm64

Successful compilation or test coverage does not authorize an official release
target. A future asset matrix change requires an explicit maintainer decision.

Use the version number without its leading `v` for `<VERSION>`:

- `splicore-v<VERSION>-linux-amd64.tar.gz`
- `splicore-v<VERSION>-linux-arm64.tar.gz`
- `SHA256SUMS`

Define the exact expected custom GitHub asset set before building. Do not invent
additional archives or assets. GitHub's automatically generated source archives
are separate from this custom asset set.

Each Linux binary archive contains:

- `splicore`
- `LICENSE`
- `NOTICE.md`
- `THIRD_PARTY_NOTICES.md`
- Required `licenses/third-party/**` payloads or their actual legal equivalents

Preserve the Linux binary's executable mode and inspect archive paths, modes
and legal contents. Exclude the development source tree, tests, fixtures,
review reports, validation evidence, maintainer documents, `.git` and internal
scripts. Generate SHA256SUMS from the approved archives using their exact names.

## Build source and toolchain

Read the frozen public checkout's `go.mod` and any toolchain requirement first.
From that checkout inspect the effective toolchain:

```sh
go version
go env GOVERSION
go env GOTOOLCHAIN
```

Use repository-supported/default Go toolchain resolution. Do not arbitrarily
override GOTOOLCHAIN or automatically set `GOTOOLCHAIN=local`. An older installed
launcher is not by itself a reason to upgrade Go; inspect the effective
toolchain selected for this repository. If the required effective toolchain
is unavailable, stop. Do not automatically install or change toolchains,
dependencies or machine configuration as a corrective action.

The current Core entry point is `./cmd/splicore`, and the current production
feature tags are `with_quic`, `with_utls` and `with_gvisor`. Before each release,
verify entry point, tags, flags and version metadata against the current frozen
repository; do not blindly copy an earlier release command. The current build
shape is:

```sh
go build -trimpath -tags with_quic,with_utls,with_gvisor ./cmd/splicore
```

Apply the approved target environment, output path and version metadata for
each artifact. Write outputs outside the source checkout. Record the effective
Go version, target, tags, flags, source commit and binary build/version identity.
Confirm the checkout and index are clean before and after building and that
HEAD still equals the exact frozen public commit.

Do not run `go mod tidy`, `go get -u`, dependency upgrades or dependency rewrites
during publication without separate authorization. Builds must not mutate source
or module files. Build success does not replace archive and identity checks.

## Release notes and completion

GitHub Release notes are for users. Include the version, meaningful changes,
relevant compatibility notes, official downloads, checksum instructions and
concise important caveats. Exclude internal Phase, review and freeze IDs,
Codex references, internal report paths, validation directories, local disk
paths and acceptance bookkeeping.

A normal official release requires all of:

- Verified public main/reference state
- An annotated version tag on the exact frozen public commit
- A GitHub Release
- The official downloadable assets and SHA256SUMS
- Successful post-upload integrity verification

Main plus a tag alone is incomplete. GitHub Release creation and downloadable
assets must not be silently skipped. Only an explicit maintainer declaration
of a source-only release changes the binary asset requirement; record that
exception and its expected downloadable set before publication.

## Tags and GitHub verification

Use annotated version tags such as `vX.Y.Z`. Resolve the exact frozen public
commit explicitly; never tag an arbitrary current HEAD. Verify that the local
and remote tag object is annotated and peels to that commit. Stop on an existing
mismatched tag rather than overwriting it. Push only the intended release tag;
never push all tags.

After publishing, verify main/reference identity, tag identity and the GitHub
Release:

- `draft = false`
- `prerelease =` the explicitly expected value
- Tag equals the exact intended version
- Custom asset names equal the exact expected set
- Unexpected custom assets = 0

Redownload all official custom assets from their GitHub Release download URLs
into a separate external directory. Compare every downloaded asset's bytes or
SHA256 with the locally approved artifact, including SHA256SUMS. Verify archive
hashes using the downloaded manifest. Record observed sizes, hashes and final
Release metadata. Publication is incomplete until redownload integrity passes.

## Failure policy and external evidence

**FAIL CLOSED.** If any release gate fails, stop and identify the root cause.
Do not automatically compensate with source edits, different flags or
toolchains, dependency upgrades, merge, rebase, force push, tag rewrite or asset
substitution. A correction needs appropriate authorization and renewed affected
gates. Preserve failed-attempt evidence alongside the corrected attempt.

Keep release evidence in an external evidence directory, outside both Git
trees. Record authorization, source/export identities, classification and
review results, freeze identities, build environment and commands, approved
artifact hashes, public reference/tag/Release state and redownload results.
Seal an inventory of evidence files with hashes after verification. Do not
commit evidence or expose its local paths in public source or documentation.
