# Pinned AWG engine

Official AmneziaWG v3.1.20260828, b5928efb6ca19f0153958460c3d141f04abc5c2e. MIT license retained. Only library packages needed by the native Core and their upstream tests are included; upstream netstack, daemon, SDK and examples are excluded. UPSTREAM.json records original file hashes.

Local changes:

- device/timers.go: clear pending duration while holding modifyingLock (upstream issue 204 / PR 205); prevents data race and lost concurrent reset.
- device/send.go: reload S4 after a blocked TUN read and overlap-safe relocate payload (issues 168/160, PRs 169/184); bounds checked before encryption.
- device/noise-types.go, splicore_random.go, device.go, noise-protocol.go, send.go, timers.go, obf_timestamp.go, obf_rand*.go: package-private per-object entropy/clock functions for deterministic qualification. H/CPA/timing choices, jitter, prefix/junk bytes and lengths have immutable per-device hooks; CPS has per-tag hooks. Production retains runtime.fastrandn, time.Now and crypto/rand.Read. No mutable global test RNG; no public entropy controls. Noise ephemeral keys and cookie secrets are unchanged.
- go.mod: restrict dependencies to included packages and use Core audited x/* versions.

Splicore prevalidates CPS, range, junk work, UDP size and HPK nonce sizes. RandomTrailers=true is rejected at the public configuration boundary due to upstream classifier issue 186 and kernel issue 226.

Local tests: device/splicore_qualification_test.go covers gated first S4 packet, timer expiry/reset race, HPK framing of four types, padding windows, CPS bytes and timestamp endianness, inclusive H/timing selection, junk count/exclusive maximum, forced-underload cookies, and classifier fuzzing.
