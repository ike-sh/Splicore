# License and attribution boundaries

- Documentation status: Canonical
- Audience: Maintainers and distributors
- Last reviewed: 2026-10-02
- Owner: Project maintainers
- Responsibility: Attribution, third-party provenance and future distribution review boundaries.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Design maturity: Experimental implementations and audited official Mieru dependency; no copied third-party source.
Primary local evidence: root `LICENSE`, `.fpm_systemd`, `go.mod`,
copyright headers in `common/ktls`, `transport/v2raygrpc/credentials`, and `constant/goos`.
The baseline upstream README and unchanged local LICENSE identify GPL version 3
or later and additional derivative naming/association wording. The root README
now introduces Splicore and links the preserved LICENSE/NOTICE. Packaging still
identifies upstream GPL-3.0-or-later and SagerNet. Preserve license text and file
headers exactly; do not replace original copyright with Splicore copyright.

| Boundary | Observed license / future obligation |
|---|---|
| sing-box derived source | Preserve GPL and notices, mark modifications, deliver required corresponding source and build/install material when conveying binaries. Product name is Splicore; no official sing-box or endorsement claim. |
| Mieru embedded source/library | Research v3.38.0, commit `b961978c3be9dd26b94158487c760858e19d1db2`; its API headers state GPL-3.0-or-later and LICENSE includes GPLv3 text. Embedding entails retaining Mieru notices and qualifying linked dependencies before distribution. |
| Xray external process | Official XTLS/Xray-core LICENSE is MPL-2.0. Keep executable/process boundary; retain its notices and satisfy covered-source duties for any Xray files modified/distributed. Phase 7 FinalMask/Sudoku use verified official v26.3.27; no fork or new artifact. MPL-2.0 and the existing external process boundary remain unchanged. |
| Future protocol code | Record repo, exact commit, license, copied/modified files, transitive linked libraries, notices and source delivery requirements before accepting code. Reject missing or incompatible licensing. |
| Go dependencies / copied stdlib | Inspect linked build graph and file headers, including BSD/Apache notices; root GPL label does not erase individual notices. |

Local research builds retain upstream names solely to verify the unmodified
baseline; they are not branded Splicore artifacts. First derivative distribution
must use Splicore binary/package/service identity, with upstream acknowledgment.

GPL source delivery is triggered by distribution/conveying, not assumed to have
AGPL network-service semantics. Separate-process deployment alone is not a
blanket legal exemption. Preserve the upstream naming clause without claiming
to resolve its legal interpretation; review any proposed distribution/licensing
change before release. This does not block architecture work.

Sources: [baseline LICENSE](https://github.com/SagerNet/sing-box/blob/v1.14.1/LICENSE),
[baseline README](https://github.com/SagerNet/sing-box/blob/v1.14.1/README.md),
[Mieru license](https://github.com/enfein/mieru/blob/b961978c3be9dd26b94158487c760858e19d1db2/LICENSE),
[Mieru API header](https://github.com/enfein/mieru/blob/b961978c3be9dd26b94158487c760858e19d1db2/apis/server/interface.go),
[Xray MPL](https://github.com/XTLS/Xray-core/blob/v26.3.27/LICENSE),
[GPL text](https://www.gnu.org/licenses/gpl-3.0.html).

## Phase 6 fixed Xray artifact

The official v26.3.27 archive LICENSE declares MPL-2.0. The inspected Linux archive
contains LICENSE/README and no NOTICE; Windows additionally ships LICENSE-wintun.txt
for its optional wintun DLL, which this adapter does not extract/use. No Xray source
or license text is copied into Splicore and no Xray Go module dependency is added.
The external binary boundary keeps implementation/source attribution separate;
it does not remove distribution obligations. Future bundling must preserve supplied
copyright/license/notice material, provide recipients the corresponding MPL-covered
source and clear access instructions, identify any modifications, and review other
bundled component licenses. Supplying an unchanged stock binary must still deliver
its license/source information. No distributor is authorized to rewrite copyright.
Future operator-path/installer strategies use reviewed pinned artifacts only;
Core never downloads. [Exact reference](../development/PHASE_6_XRAY.md).

## Phase 8 linked Mieru dependency

Official module v3.38.0/full commit above is now a direct Go dependency. Its API
headers declare GPL-3.0-or-later; LICENSE retains the GPLv3 text and authors retain
their copyrights. The GPL-3.0-or-later derivative can embed this library under that
same license boundary. No source is vendored/copied/modified; importing is not an
exemption from corresponding-source and notice obligations when conveying builds.
Preserve root/upstream licenses and each linked dependency's copyright/license/NOTICE.

The actual server import graph adds only Mieru and uses existing google/btree
(Apache-2.0), x/crypto, x/sys and protobuf (BSD-3-Clause). Its other module
requirements x/net/x/text (BSD-3-Clause), grpc/genproto/googleapis/rpc (Apache-2.0)
already exist at the same selected versions and are audited separately; apis/server
does not import the daemon or gRPC. The concrete
audit hashes each module's LICENSE/NOTICE/AUTHORS and compares baseline versions.
No CGO requirement. Binary size/build time and exact selected versions are in
[Phase 8 report](../reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md). No release is authorized.
