# Automatic dual-DHCP milestone review

Accepted run `1baf8762680a6885`, matching-source fingerprint
`761538bd1c3aee9c247176f0ff48db6367529bb9b4e34c1ccea376eedf02ee4f`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [Attempts](attempts.json) ·
[Contract/reproduction](../../docs/DHCP_AUTOMATIC.md)

## Findings and corrections

Two read-only reviewers independently examined the production diff and the raw
fixture/report evidence before comparing diagnoses. No reproducible additional
production selection, budget or SUSPECT defect was established. The runtime/core
remain unchanged from `806be73`; this patch corrects the evidence gates and adds
one formal regression.

The original verifier accepted these mutations to the ACK write-race recovery:

- `good=0`, despite a required new-generation two-round quorum;
- `until=as_of+0.001`, so the health start predates the new lease event;
- an additional valid budget-history record, despite the free recovery claim.

The retained original data itself satisfied the claimed conditions; these were
false-positive validation paths, not evidence of a failed original runtime run.
The guest and report now both require quorum/timing, exact invalidation-to-recovery
history and an increasing lease-restoration counter. Four new corruption controls
also reject the three mutations and a non-increasing restoration counter, in
normal and optimized Python. A reviewer independently retested all four against
the old raw race data, avoiding rejection solely due to the new suite-count gate.

The generated HTML inherited a stage-one sentence denying any automatic failover
claim. Its wording now consistently qualifies automatic failover only in this
foreground fixture while preserving the installed-service/reboot/power-loss and
zero-gap exclusions. The [original receipts](../dhcp-automatic/README.md) remain
intact with an explicit qualification; their HTML was not silently rewritten.

## New actual validation

- **240 same-source tests per platform**, identical macOS/Linux IDs, no failures,
  errors or skips. Fourteen automatic-runtime tests invoke the production runtime
  and SQLite lifecycle under controlled time/IO. The new test proves an expired
  selected SUSPECT path cannot recover from one successful round: it needs full
  fresh qualification, and same-generation reselection consumes budget. This
  boundary is portable coverage, not an extra VM fault injection.
- **Eight service/fault VM cases and one fixture control pass.** Six cases launch
  the shipped foreground service directly. Two explicitly labelled bounded-delay
  cases delegate every mutation/readback to the actual production Linux backend;
  they do not mock lease admission, health or kernel results. Real client signals
  and the shipped hook supply ACK-backed renewal/deconfig during the write pause.
- Initial eligible A is selected automatically. A blackhole causes automatic B;
  four subsequent natural B renewals use new generations/fresh health and leave
  global history at two records. Actual B release selects A; a delayed old
  operator token is rejected without changing its route/history.
- The SUSPECT case observes **one failed round**, an unchanged selected route
  before/during/after, and exact unchanged history **3 → 3**, with B healthy.
  Backup/new leases still need their full quorum; the selected-path recovery
  exception does not qualify them.
- Both-down withdraws the selected route. A charged cross-WAN attempt exhausts
  and latches the four-record budget; a later healthy B renewal cannot bypass it.
  An independent A/main TLS request succeeds while forwarded LAN traffic fails,
  so rejection is not explained solely by an unavailable fallback.
- ACK during actual B write causes a formal invalidation/withdrawal. Recovery has
  **good=2**, health start **57.272297666 s** after lease event **57.063251800 s**,
  exact history **2 → 2**, and restore counter **0 → 1**. The pause was **0.095 s**.
  Real deconfig during another actual B write removes B's allocation; A recovers
  with actual A traffic. Delayed old-probe completion is portable coverage, not
  a separately injected VM executor crash.
- **36 corrupted-evidence controls pass** in normal and `-O` modes. HTML exactly
  renders JSON; standalone unit receipts exactly match their embedded copies.
  Client source/config/binary readbacks and the frozen source snapshot agree.
- VM RSS snapshots: service **25,204 KiB**, clients A/B **1,612 / 1,612 KiB**.
  These are not peaks and exclude fixture/kernel/whole-VM overhead. Scenario
  durations in JSON order are **4.504 / 0.070 / 2.424 / 17.247 / 0.919 / 2.481 /
  5.937 / 2.864 / 3.210 seconds**. They include deliberate waits and are not outage
  SLOs, application latency/throughput comparisons or cross-platform benchmarks.
- This review used one full VM attempt. Owned children/namespaces/source/build
  are removed, root network unchanged, VM stopped, source unchanged. Private
  logs, keys, frames, journals and external client binaries remain excluded.

## Limits

This is foreground milestone 1, not the deployed dual-DHCP MVP. The post-write
stamp is not atomic with future packets: events arriving after it are handled at
the next runtime step. No all-interleaving, zero-gap or continuous-forwarding
claim follows. Existing TCP sessions may break. The bounded backend-delay wrapper
is not an installed production service or proof of delayed/crashed writer takeover.

Privilege separation/root recovery API, installed start/stop/VM reboot, sustained
64-transaction history rollover, same-schedule application traffic measurements,
physical-WAN/general DHCP interoperability and sudden power loss remain outside
this review. The external BusyBox client remains separately GPL-governed and is
not bundled in this MIT project. Repository visibility/access settings are unchanged.
