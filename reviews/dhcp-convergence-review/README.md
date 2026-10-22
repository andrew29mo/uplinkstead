# Selected-WAN convergence review

Run `2f504b56d43798e4`, matching-source fingerprint
`cda25b091d735188b006710755458097394e410be20ae44d2e29ee3e293166a0`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [Attempts](attempts.json) ·
[Contract and reproduction](../../docs/DHCP_CONVERGENCE.md)

## Review findings and corrections

Two independent read-only reviews examined the formal lifecycle/runtime and the
fixture/report correspondence before comparing findings. No reproducible product
logic defect was identified. The following evidence defects were corrected:

1. The original forbidden main default used B. B blackholing also broke that
   default, and removing B's expired address broke its return path. A failed LAN
   request therefore did not independently demonstrate rejection of a viable
   fallback. This fixture uses A/main instead. In **both** B blackhole and expiry
   windows, a new unmarked TLS request from the router, explicitly bound to
   `10.77.0.1`, succeeds through A (`peer=10.99.1.1`), while the forwarded LAN
   request fails. Main-route readback and witness timestamps are retained. No
   production RPDB guard or owned table is bypassed or removed for this check.
2. The original verifier accepted a future ACK timestamp, or a transaction
   detached from B's bound/renew event. Admission checks now join link, reason,
   xid, sequence, REQUEST/ACK time, conservative lease origin, current allocation,
   prefix, duration and expiry to the published processed record.
3. The original verifier did not require inactive B actually to renew. It now
   requires a newer B sequence/generation and its real renewal transaction while
   A's authority, child PID and selected route identity remain unchanged.
4. Operator RPC completion precedes the next status publication. The fixture now
   waits for the completed revision/selected link after success, and the published
   latch after budget rejection, instead of immediately trusting a cached status.

The [original run](../dhcp-convergence/README.md) is retained with a qualification;
its raw receipts have not been rewritten to imply it ran these stronger checks.

## New measured evidence

- **226 identical-source tests on macOS and Linux**, identical IDs, zero failures,
  errors or skips. Portable tests exercise the actual SQLite lifecycle and runtime
  with injected clocks/backends; actual Linux route/client behavior is covered
  separately by the VM fixture, not inferred from those injected dependencies.
- **Six formal-service VM cases pass** using the shipped foreground runtime,
  hook, hash-pinned compiled timer client and production Linux backend. The guest
  does not inject health or call core restore. A uses a long dnsmasq lease; B uses
  a controlled local DHCP fixture. This is not general server interoperability.
- Four subsequent **natural** B renewals restore fresh-generation B traffic.
  All four retain exactly two global history records with the budget set to two;
  no forced renewal or manual selection produces those four transitions.
- Real NAK/new acquisition exercises changed address/gateway; blackholed B remains
  DOWN/unselected despite the independently successful A/main witness. Unblocking
  permits fresh B quorum and B traffic. Gateway-only change also restores B.
- Expiry is sampled **193 times**, maximum gap **0.107 seconds**. The conservative
  writer deadline is **68.763583159 s**; the first withdrawn publication is
  **68.847147387 s**, on the same VM boot clock. B's actual address/probe/LAN routes
  are absent. A/main TLS succeeds while forwarded LAN traffic fails. New acquisition
  then restores B; the replayed old ACK has a capture/drain/publication fence and
  cannot change the new identity/sequence.
- A further manual WAN change is rejected and latches the full budget. A later
  accepted healthy B renewal remains withdrawn. Portable tests additionally cover
  pause, same-generation retry rejection, stale token/health, the separate
  16-dispatch/60-second bound, journal migration and writer-reopen disarming;
  these are not separate VM fault injections.
- **39 corrupted-evidence controls** pass in normal and optimized Python. JSON
  and HTML match exactly. Failed/timed-out stages, wrong source/build/cleanup,
  transaction corruption, missing renewal, wrong WAN, missing/failed/out-of-window
  fallback witnesses, premature expiry and latch bypass are rejected.
- Linux VM RSS snapshots: service **24,848 KiB**, clients A/B **1,612 / 1,612 KiB**.
  These are process snapshots, not peaks, and exclude kernel/fixture/whole-VM cost.
  Case durations include intentional waits: **5.131 / 20.270 / 4.981 / 0.430 / 21.113 / 0.323 seconds** in JSON case order. They are not failover SLOs or
  throughput/latency comparisons.
- Owned processes/namespaces and guest source/build cleaned, root network
  unchanged, VM stopped and source unchanged. Both review attempts passed; the final run includes the latch-publication wait.
  Private logs, keys, raw frames and external binaries remain excluded.

## Remaining boundaries

This is selected-WAN restoration, not automatic cross-WAN failover or a deployed
dual-DHCP service. Restart disarms restoration and retains budget/latch. Renewal
quarantine can interrupt traffic and break existing TCP connections.

The VM observes a post-admission DOWN state and final fresh-health restoration;
it does not continuously observe every ACK-to-DOWN state. An ACK arriving between
the runtime's pending snapshot and backend write has not been race-injected.
These results do not prove the absence of every transient stale-routing window.
Sampled publication timing is not exact kernel timing. No installed-service/VM
reboot qualification for this mode, long-history longevity, physical-WAN,
boot-zero-gap or sudden power-loss qualification is claimed. External BusyBox is
separately GPL-governed and is not bundled in this MIT repository.
