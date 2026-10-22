# P0 selected-WAN DHCP convergence evidence

**Historical run, superseded by the [convergence review](../dhcp-convergence-review/README.md).**
Its source/build receipts remain intact, but the original B/main fallback was not
independently viable during B blackhole/expiry. The original report also lacked
inactive-B renewal and transaction time/link/reason checks. The new run corrects
these evidence gaps; the claims below describe the original interpretation and
must be read with this qualification. Raw JSON/HTML are preserved, not rewritten
to imply the original run exercised the new checks.

Run `319ce0a3f44a1c2c`, matching-source fingerprint
`bfdc4a2ca68b1fec8211402cbae4c584b226b61744d1c1fd9afa36b2e1cb191e`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [Attempts](attempts.json) ·
[Contract and reproduction](../../docs/DHCP_CONVERGENCE.md)

## Actual scope

The formal foreground service owns both clients, capture, SQLite lifecycle,
pinned health and scoped Linux backend. The fixture does not call core restore or
supply health proofs. Only initial A then B selection is manual. Subsequent
selected-WAN recovery is dispatched by the actual runtime after fresh health.
This is **not automatic cross-WAN failover or an installed-service qualification**.

## Observed results

- **226 identical-source portable tests on each platform**, identical IDs, no
  failures/errors/skips. New tests directly challenge the production SQLite core
  and runtime for free new-generation restoration, no same-generation reuse,
  old token/health rejection, cross-WAN budget enforcement, pause/latch, rate
  limit, historical journal migration and writer-reopen disarming. Those portable
  faults are not claimed as separate VM injections.
- **Six formal-service Linux VM cases passed**, using the actual externally
  compiled/hash-pinned client and shipped hook. Its source/binary/config readback
  and the source snapshot are checked. A uses a 600-second dnsmasq lease to isolate
  B side effects; B uses the controlled raw DHCP fixture. This is not a server
  interoperability or server performance comparison.
- Initial state stays unselected. After explicit A selection, B naturally renews
  without changing A's allocation/session/PID or selected route identity; a new
  routed A TLS request succeeds.
- After explicit B selection, **four subsequent natural renewals** restore B with
  new lease generations and fresh TLS quorum. The configured global budget is two
  and its history remains exactly **two records** throughout, with latch false.
  No clock injection, forced renewal or manual selection produces those four
  transitions. The report joins each real REQUEST/ACK/xid/allocation to the
  processed event, deadline, new-generation route and actual B endpoint identity.
- Address/gateway change to **198.51.100.3 / 198.51.100.254** uses a real NAK then
  new acquisition. While B's data path is blackholed, new B health is DOWN and
  selection remains absent; usable A is not borrowed. Unblocking allows fresh B
  quorum and autonomous B traffic. A's authority stays unchanged. A separate
  gateway-only change to **198.51.100.253** restores the same B address.
- A 20-second B lease expires with its DHCP server silent. **194 runtime
  observations**, maximum observed gap **0.108 seconds** (limit two seconds),
  precede the first withdrawn publication at/after the conservative writer deadline.
  B's address, probe and LAN routes are removed, with LAN traffic failing despite
  viable forbidden fallback. New acquisition of **198.51.100.4** autonomously
  restores fresh B traffic. The original B ACK is then replayed on the segment;
  receiver hash, formal capture drain/ordinal and a subsequent runtime publication
  prove the new identity/sequence remains unchanged.
- A further manual A selection is rejected and durably latches the full budget.
  B's next accepted healthy renewal stays withdrawn: restoration cannot bypass
  pause/latch or turn a different WAN into a free recovery.
- **27 corrupted-evidence controls** reject failed/missing/timed-out stages,
  source/build/cleanup mismatch, old generation or health, budget mutation,
  gateway mismatch, premature expiry, residual routes,
  missing replay processing and borrowing the wrong actual WAN endpoint.
  Normal and optimized Python verification agree. HTML is the exact JSON render.
- Linux VM process RSS snapshots: service **24,776 KiB**, clients A/B
  **1,612 / 1,604 KiB**. These are not peaks and
  exclude kernel/fixture/whole-VM overhead. Case time includes deliberate lease
  waits; no throughput, speedup, outage bound or continuous-forwarding claim.
- Owned processes/namespaces/source/build artifacts cleaned, root network unchanged,
  VM stopped, source unchanged. Private logs/frames/credentials/external binaries
  stay excluded. All three attempts are retained, including the fixture failure
  and the passing run superseded by stronger report checks.

## Constraints and remaining gaps

Opt-in `runtime.restore_selected` defaults false. The qualified client is selected
explicitly; distro default unchanged. A writer restart clears restoration arming
and old allocations but preserves budget/latch. Same-WAN automatic restoration
has a separate 16-dispatch/60-second runtime bound; rate-limit saturation safely
leaves it withdrawn. Manual choose retains existing budget semantics. No foreign
route/default or another WAN is selected by this feature.

Conservative renewal quarantine still interrupts traffic and may break existing
TCP sessions. Sampling measures runtime publications, not exact kernel-removal
time. No long-history longevity, automatic cross-WAN failover, policy privilege
separation for this mode, installed systemd/reboot recovery, general DHCP server
compatibility, arbitrary packet floods/loss, physical WAN, boot-zero-gap or sudden
power-loss qualification follows. The external BusyBox program remains separately
GPL-governed; no source/archive/binary is bundled in this MIT project.
