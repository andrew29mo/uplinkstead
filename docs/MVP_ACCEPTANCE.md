# First MVP acceptance

Acceptance is tied to the retained matching-source evidence in [Validation](VALIDATION.md).
A passing portable test is separate from real Linux installed-service evidence.

## Required invariants

1. A probe cannot borrow B, or B borrow A, including missing route and link-down.
2. Only the declared LAN ingress/source and non-excluded scope changes; ordinary
   host/other-LAN and router-local traffic retain their own route semantics.
3. A route ACK, configured-target health and successful new LAN TLS requests are
   distinct evidence. No existing-flow migration or Internet-wide health is implied.
4. Unknown outcomes retain exclusive ownership until helper retirement/readback.
   Old process epochs, same-process revisions and old observation rounds cannot
   authorize a newer selection. Recovery does not replay stale health decisions.
5. Default no preference failback; alternating failures consume a persistent budget.
   Reboot/restart cannot clear a latch or replenish unknown cross-boot budget age.
6. Automatic dispatch rechecks fresh writer-owned health. An unprivileged client
   cannot fabricate health or provide arbitrary routes, commands, paths or proofs.
7. Missing/duplicate built-in RPDB lookups, inversion and unknown/intersecting
   selectors reject mutation. Unknown is not a healthy destination.
8. First service start is DISABLED without attaching routing. Enable durably
   installs owned layout and enters PAUSED; resume needs fresh health and explicit
   budget acknowledgement. Disable durably hands off to existing main routing.
9. Stop retains routes; restart retains mode/latch and rebuilds health. Partial
   enable/disable is reconciled by the next exclusive writer, never guessed complete.
10. Protocol/config/events/history/database are bounded. Low disk/SQLite write
    failures cannot be reported as successful route changes.

## Required evidence

| Area | Qualification |
|---|---|
| Original four explorations | Both pinned probe directions, scoped NAT/routed TLS paths, live writer/helper ownership, three crash boundaries, oscillation/latch and pending journal before boot recovery |
| Privilege boundary | Actual shipped writer/policy units, root writer and capability-free dedicated policy UID, denied operator RPC/state read/direct route mutation and unrelated peer access |
| Operator lifecycle | Fresh detached startup, enable paused, premature resume rejected, pause retains failed selected path, healthy manual selection, old revision/epoch rejected, explicit disable and stop/start semantics |
| Failure recovery | Injected actual-backend disable/partial-enable write failure recovered on reopen, actual ip helper timeout retired, query-only SQLite write failure before mutation, bounded systemd restart failure plus explicit reset recovery |
| Capacity | Real DB event retention and page limit, low-space boundary rejection, portable actual SQLite capacity error, request/schema/rate bounds |
| Measurement | Fixed-primary/automatic modes replay identical intended open-loop offsets and fault index; retain all success/failure/late attempts, elapsed useful throughput, latency, separate writer/worker RSS and main DB size |
| Reproducibility | Same source manifest and portable test IDs on macOS/Linux; actual isolated Linux VM stop/start; JSON/HTML and negative controls agree; cleanup/source removal/stopped VM required |

The old exploration driver still directly exercises the formal core for bounded
fault injection; it is not the deployed policy service. New MVP qualification
uses both installed services and the formal operator CLI. Independent scenarios
reset systemd's fixture restart counter when deliberately performing repeated
manual starts; the bounded-restart scenario separately verifies the unchanged limit.

## Deployment choices and exclusions

This MVP uses local root administration and a controlled TLS probe protocol. It
requires a qualified static routing/NAT/rp_filter contract. Disable's main-policy
handoff is explicit, not an automatic promise of connectivity. Service installation
is documented; distribution package-manager integration is not qualified.

Optional automatic preference failback remains portable-policy-tested, not live-VM
qualified; default non-preemptive mode is the tested operational choice. No claim
of physical-device/ISP failure, sustained saturated load, repeated-trial confidence,
HA, IPv6, storage-corruption repair, sudden power-loss recovery, kernel-stuck I/O,
whole-VM memory cap, boot-zero-gap or production readiness follows from these tests.
