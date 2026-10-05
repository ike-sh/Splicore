# TUN Runtime Resource Ownership

Design established before implementation, 2026-10-05; updated to the implemented
contracts. The maintainer review passed; the
[local qualification-fix freeze](../reports/QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md)
records the new candidate. Platform Qualification is not resumed.

| Resource | Owner | Acquire | Release | Crash behavior |
|---|---|---|---|---|
| Linux TUN FD | host journal / Platform | interface creation | after runtime Wait, lease compensation | OS closes; journal reconciles identity |
| Wintun adapter | host journal / Platform | GUID-authorized create | lease restoration | OS closes; exact GUID recovery |
| Wintun session/quit handle | ownedWintun | Start | interrupt, I/O join, End | OS closes; durable session record reconciled |
| Stack | native runtime backend | Start | close flows, joined callbacks, public Destroy | process memory reclaimed |
| NIC | backend stack | after handler initialization | Destroy | process memory reclaimed |
| NIC/inbound link + owned egress queue | backend | Start | worker/flow join, Destroy/Close queue drain | no independent host resource |
| packet workers | native runtime | before Start returns | cancel/interrupt and Wait | process exit |
| ingress bytes | receive worker → PacketBuffer | read then owned copy | drop worker ref after inject | memory reclaimed |
| egress bytes | link → queue → send worker | synchronous immutable snapshot before link return | after synchronous write returns, or queue drain | memory reclaimed |
| writer guard | each runtime/device use | prepared | reject and drain during Stop | process exit |
| TCP request | backend reserved task | before Forwarder.HandlePacket | registered-handshake Abort barrier when pending; Complete exactly once; flow join | process exit |
| TCP/UDP endpoint | backend tracked flow | callback | flow close, then stack Destroy | process exit |
| application sessions | client Manager | guarded registerFlow | finishFlow and Manager join | memory reclaimed |
| generation reference | ingress/Manager | acquire before route/policy; per UDP DNS query | after joined cancellation/connection cleanup and dispatcher/query return | derived; SQLite intent restored |
| eventfd/internal pollers | backend / Go poller | channel backend has no eventfd; Go poller is process-wide | Destroy; no per-lifecycle descriptor | OS closes |
| route/address/proxy lease | host journal | durable Prepare | exact reverse Restore | durable identity recovery |
| DNS interception | generation DNS Engine + admitted query/stream | dispatch under generation ref | context cancel, query/flow join, ref release | SQLite intent restored |

The runtime never closes a journal-owned raw device to interrupt it. The device
must implement Interrupt to wake blocked I/O. The journal releases only after
runtime teardown has joined every borrower. Device cleanup errors retain debt.
