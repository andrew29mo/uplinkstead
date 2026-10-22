# Historical absolute DHCP T1/T2 client integration evidence

This receipt describes commit `8bae55a`. Its verifier did not bind the first
writer withdrawal publication to the writer deadline, and did not force the
ACK/quarantine ordering. It establishes its original scoped observations, not
those later review gates. Use that revision for historical reproduction; see the
[current reviewed evidence](../dhcp-timer-review/README.md).

Run `d2969a97bc45cafa`, matching-source fingerprint
`2dc9122815eca8bce9ec11c2b4a6efd43ff5b1ef5fe1f572f41487a3882d8c16`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [All attempts](attempts.json) ·
[Design, reproduction and limits](../../docs/DHCP_TIMERS.md)

## Observed results

- **215 identical-source tests per platform**, identical IDs, zero failures,
  errors or skips. Native macOS and Linux compile the exact first-party C timer
  functions embedded in the external client; only the Linux VM runs networking.
- **Six formal-service VM scenarios passed.** The runner builds complete BusyBox
  1.36.1 from the verified external source archive, verifies transformed source and binary hashes and records
  config hash and compiler version, then launches that binary through the formal
  foreground service and shipped hook. It does not manufacture lease callbacks.
- A 120-second lease with options 58/59 actually absent uses **T1=60, T2=105**.
  Explicit **T1=10, T2=25** produces two subsequent natural renewals. A separate
  **T1=8 / absent T2** case uses **T2=105**. A independently renews with dnsmasq's
  actual advertised options. Profiles are bootstrapped with SIGUSR1; the reported
  subsequent natural timer transitions use neither signals nor a rewritten clock.
- Zero, reversed, out-of-lease and malformed-length timer options are rejected.
  Each case exports the real client rejection event plus a receiving frame hash,
  formal capture ordinal/drain fence and subsequent full runtime publication;
  allocation, deadline and event sequence remain unchanged.
- B's real unanswered unicast REQUEST receives a held server ACK only after the
  new natural T2 broadcast REQUEST. That actual delayed ACK has no allocation
  effect; the new transaction's response explains the extension. B's deterministic
  fault server and A's independent dnsmasq server are explicitly different fixtures,
  not a claim of broad server interoperability.
- With a silent server and **240-second lease**, the third real broadcast retry
  still leaves **47.451 seconds** on the client schedule. The admitted lease
  remains present and fresh explicitly selected B traffic succeeds. Retry count
  therefore does not cause the former early loss. At absolute expiry the client
  deconfigures, the formal writer removes B's address and both its probe/LAN routes,
  and the LAN request fails despite a viable forbidden fallback. A remains usable
  after explicit selection. B then acquires **198.51.100.3** and new traffic succeeds;
  replaying its old ACK cannot restore the older allocation.
- **29 corrupted-evidence controls** reject missing/failed stages, timeout,
  wrong source/build provenance, missing natural timers or production processing
  fences, substituted invalid options, detached client rejection, early expiry,
  stale allocations and residual addresses/routes. String and integer route-table
  representations are both challenged. Normal and optimized-Python checks agree.
- Linux VM process RSS snapshots: service **25,528 KiB**,
  A client **1,612 KiB**,
  B client **1,592 KiB**.
  These are not peaks and exclude kernel/socket/fixture/whole-VM overhead. Scenario
  durations include intentional timer waits, not a throughput or outage benchmark.
- Owned children/namespaces/source/build artifacts were cleaned; root network state
  was unchanged and the dedicated VM finished **Stopped**. The source manifest did
  not change during validation. Private logs, raw frames, credentials, external
  source and binary are not published. Earlier failed and superseded attempts are
  summarized rather than discarded.

## Engineering findings and boundaries

The review exposed an integration race: capture quarantined an old address before
an ordinary UDP client could receive its replacement ACK. Both renewal phases now
use the client's existing raw DHCP receive path; admission still requires formal
wire proof and fresh health. Runtime snapshots are checked only after a complete
admission, and stale selection tokens are retried only after observed authority
changes. These changes preserve, rather than bypass, the safety checks.

Lease deadlines start at the fixed REQUEST origin. The writer uses the earlier of
that origin and its conservative capture-queue bound; it may withdraw slightly
before the exact client expiry. This is not identical-nanosecond scheduling or a
hard recovery deadline. It removes retry-count-driven loss, not all availability
costs of quarantine, scheduling or fresh-health requirements.

This is an explicitly selected, separately built adapter; the distro-client
**default remains unchanged**. Finite 1..86400-second leases only; no random timer
fuzz, infinite lease or full RFC/server-interoperability qualification. DHCP is
unauthenticated and the bounded transaction history/restart limits still apply.
The foreground dual-DHCP mode retains manual selection; no automatic failover,
continuous forwarding, installed-service recovery, adapter VM reboot recovery,
boot-zero-gap, physical WAN or sudden power-loss qualification is claimed.
The GPL-governed external BusyBox source/binary is not bundled in this MIT project.
