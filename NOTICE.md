# Splicore

- Documentation status: Canonical
- Audience: Project visitors and distributors
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Independent derivative identity, attribution and non-affiliation.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Splicore is an independent derivative project based in part on
SagerNet/sing-box. Splicore is not affiliated with or endorsed by SagerNet.

Original upstream copyright and GPL licensing terms are preserved in
[LICENSE](LICENSE). The baseline is sing-box v1.14.1, commit
`1ac1a339cb1223e9c70eae14c44411c75033c02d`.

The upstream source, command names and package paths remain intact for Phase 0
architecture review and baseline verification. They do not identify a published
Splicore product. Future derivative binaries, services and packages must use
Splicore identity. No Splicore binary is published in this phase.

See [upstream provenance](docs/UPSTREAM.md) and
[license boundaries](docs/architecture/LICENSE_BOUNDARIES.md).

## Phase 17 internal development snapshot — 2026-10-06

The Phase 0 paragraph above records the preserved baseline. The current internal
development module is `github.com/ike-sh/Splicore`. The inherited sing-box command,
runtime trees and SagerNet Go dependencies have been removed from this working
snapshot. This does not remove the derivative provenance, upstream copyright or
GPL terms. Independent protocol adapters retain source-reference attribution in
the implementation evidence; reference peers are test processes only.

Current third-party module versions and preserved license texts are listed in
[third-party notices](THIRD_PARTY_NOTICES.md). The former WinDivert assets have no current package or embedding consumer and
were removed during Phase 21 Deep Core Purge. They were not required Core Windows
build resources. Historical archive and attribution remain preserved. At that development checkpoint, no Phase 17 publication, freeze or release
had occurred.


## Consolidated local freeze metadata

Phase 16 and Phase 17 were consolidated into one local Independent Core
Transition freeze commit; see
[the freeze report](docs/reports/PHASE17_INDEPENDENT_CORE_FREEZE_REPORT.md).
No publication or release is included. The attribution and license terms above
remain preserved.
