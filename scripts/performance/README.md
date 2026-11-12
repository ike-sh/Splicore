# Native network measurements

These are instrumented **BASELINE / OBSERVATION** measurements, with no absolute
performance SLO. They exercise real production compilers/dialers, TLS, protocol
framing, userspace WireGuard, OS sockets and application payload validation.
Reference-peer compatibility and security remain separate mandatory release
gates. No external proxy core is a production dependency.

Use a native Go matching `go.mod` and Python 3.9+. Store **all output, Go caches
and temporary files outside the checkout**. Set `GOCACHE`, `GOMODCACHE`,
`GOTMPDIR` and `TMPDIR` (Windows: process-local `TEMP`/`TMP`) accordingly.

```sh
python3 scripts/performance/run.py --profile baseline --repeat 3 --isolate --output /external/perf-baseline
python3 scripts/performance/run.py --profile matrix --isolate --output /external/perf-matrix
python3 scripts/performance/run.py --profile ci --conditions all --isolate --output /external/perf-netem
python3 scripts/performance/run.py --suite wireguard --profile baseline --repeat 3 --isolate --output /external/perf-wg
python3 scripts/performance/run.py --profile soak --soak-hours 24 --isolate --output /external/perf-24h
python3 scripts/performance/run.py --profile soak --soak-hours 72 --isolate --output /external/perf-72h
```

On native Windows omit `--isolate`; use `--conditions clean`. Linux builds or
WSL measurements do not qualify native Windows. `run.ps1` provides an equivalent
native Windows entry without requiring Python. Both ARM64 architectures require
actual native execution; cross compilation is only BUILD ONLY.

`profiles.json` specifies CI smoke, protocol baseline, one-factor matrix and
soak workloads. Matrix coverage includes 1/10/100 connections, 64 KiB/1 MiB/
64 MiB per connection, upload/download/concurrent duplex, IPv4/IPv6 and proxy
ingress/egress family changes, 64/1200/8192/60000-byte UDP datagrams. Unsupported
large datagrams are reported as failures, not retried or silently truncated.
This is not an exhaustive Cartesian product. Add explicitly named scenarios for
a specific question, preserving the configuration with its results.

`conditions.json` specifies independent 0/1/3/5/10 percent packet loss,
10/50/100/200 ms link RTT, normal-distributed jitter (1/5/10 ms one-way standard
deviation) and 1280/1400/1500 MTU. Changes apply only to a newly created user,
mount and network namespace. The host routes and qdisc are never changed. The
owned loopback has netem `delay=RTT/2` on each packet traversal. A local proxy
round trip traverses **two connections**, so its application RTT includes four
one-way delays. Use the actual raw RTT distribution; do not label the configured
link RTT as the measured application RTT. Netem loss is per traversal, not an
end-to-end loss promise. Loopback offload, fragmentation and instrumentation
can affect these results; this does not emulate a physical WAN or certify a
distribution. Before/after qdisc counters and actual MTU/configuration are saved.

Every TCP connection records DialContext time, application readiness time, all
RTT probes, verified transferred bytes, transfer duration and Close time. A
protocol-only cryptographic handshake is **NOT EXECUTED** as a separate timing:
lazy protocol handshakes, target connection and readiness are included in
`ready_ns`. Upload and download use independent generated/checked streams;
duplex writes and reads concurrently in each direction. Aggregate TCP goodput
uses the complete group duration, including startup/probes and concurrent UDP;
per-connection transfer goodput is also retained. These definitions must be kept
when comparing runs.

Native timers can return a zero elapsed duration for a fast transfer. Keep that
raw sample; the corresponding per-connection throughput is `null` and recorded
as below timer resolution in `timing_not_executed`. Never substitute a made-up
positive duration or interpret a zero timing as a zero-cost handshake.

UDP sends every sequence exactly once at the configured per-session rate. Raw
replies retain sequence and RTT. Counts include missing/duplicate replies;
received throughput includes a fixed two-second final settling window when
packets are missing. Loss does not imply a reliability failure for UDP. Payload
corruption, socket errors, missing TCP acknowledgement and fixture startup
failure remain failures. Synthetic patterned payloads are intentional and are
not representative of every content-dependent transport.

Resource JSONL samples include current RSS, cumulative process CPU time, live
goroutines, heap/allocation totals and Linux FD / Windows handle counts every
200 ms and before/after each scenario. One used logical CPU is 100 percent.
Metrics cover the instrumented client, server and targets in one test process,
not a standalone deployed server. Fast scenarios can have only boundary
samples. Counts are observations; existing bounded lifecycle/port-rebind/leak
assertions are still required. File-descriptor sampling can count its transient
directory descriptor. The sampler itself contributes one goroutine.

Retain `environment.json`, source commit/diff identity, build log, exact scenario
JSON, raw JSONL, test log, netem JSON and summaries. Compare repeated runs on the
same hardware, OS, Go, build profile and network setup, reporting spread as well
as central values. Do not compare Windows/WSL numbers as an optimization A/B.
Any proposed optimization must first reproduce a problem and retain before/
after data plus meaningful regression tests. Otherwise keep production code.

Soak profiles repeat complete startup, mixed traffic, close and cleanup cycles.
An interrupted/short run is **NOT EXECUTED** for 24/72-hour qualification. These
campaigns belong outside ordinary CI. Half-close, abnormal process death,
reconnect and immediate port rebind are covered by the existing native CLI and
protocol lifecycle suites; this harness does not independently measure recovery
latency or certify a process crash. CPU profiles can be obtained by invoking the
compiled test binary with Go's `-test.cpuprofile`/`-test.memprofile` flags while
retaining the same `SPLICORE_PERF_CONFIG` and a fresh `SPLICORE_PERF_RAW` path.
