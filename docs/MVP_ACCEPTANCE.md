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
   authorize a newer selection. Same-boot recovery reconciles actual before/after
   without replaying a past health decision. After boot, it reconstructs persisted
   owned layout/selection or pending intent, then collects new health; restoring
   the recorded route does not assert that destination is currently reachable.
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
10. One oversized optional target field is only one failed quorum vote; it cannot
    prevent complete sampling. Manual selection counts only relevant time-window
    history while preserving an actual persistent latch.
11. Protocol/config/events/history/database are bounded. Low disk/SQLite write
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

## Optional DHCP lifecycle slice

This slice is independent of the static dual-uplink MVP. Acceptance requires real
wire-acquired leases, renewal/address/gateway invalidation of health, new pinned
quorum before forwarding, real-deadline withdrawal with the client stalled, and
no use of an independently reachable backup default. Installed-service SIGKILL
recovery must reject an old session with otherwise current revision/time. A real
backend write followed by an injected exception must preserve both sides of intent
and recover without replaying the old lease. Portable tests separately check
cross-boot identity and actual SQLite save rejection. Same-source macOS/Linux
tests, failed-run retention, source change/timeout rejection and owned cleanup
are required. This does not qualify DHCP VM reboot, sudden power loss, DHCPv6,
PPPoE, dual-DHCP failover, transparent connections or production throughput.

## Dual-DHCP integration: exploration and future MVP gates

The [four exploration contracts](DUAL_DHCP.md) are separate from acceptance of a
deployed dual-DHCP service. Real DHCP acquisition/natural T1, scoped backend
mutations, both pinned blackhole directions, controlled conflict/option rejection,
actual partial network write and manually invoked core after an orderly VM reboot
can qualify the underlying mechanisms. They do not qualify service orchestration.

Future dual service acceptance additionally requires:

1. Two bounded independently supervised DHCP clients; loss of B does not restart
   A or reset A's fresh authority/proof/route. Writer failure quarantines both.
2. Immutable callback authority/time, finite queues and explicit timeout outcomes.
   Simultaneous renewals, slow probes/helper operations and queue saturation must
   not relabel old events or silently preserve expired health.
3. Exact supported lease-time origin and DHCP options/server routing contract;
   natural T2/rebinding and delayed delivery must be observed on the real adapter.
4. Default non-preemptive automatic selection, bounded persistent switching,
   explicit operator recovery, and safety withdrawal independent of pause/latch.
5. Shipped installed-service orderly reboot with unchanged pre-start journal and
   actual empty old allocations before any DHCP client is created, plus new wire
   acquisition and fresh health before LAN forwarding.
6. Real delayed network helper ownership and generation checks, and complete
   same-schedule fixed/automatic traffic with all failures retained before any
   throughput, outage or failover advantage claim.

No successful exploration may silently stand in for one of these untested gates.

### Stage-one service acceptance

The [stage-one contract](DHCP_STAGE1.md) adds a real foreground dual runtime.
Acceptance requires actual wire acquisition through its own clients, B-only crash
replacement preserving A, real renewal applied during an outstanding slow probe,
and deliberately backlogged wire renewal retaining its original conservative
REQUEST deadline. Retired-authority requests cannot extend leases. Current-authority
claims without ACK proof retire only that link. Both server and transport overload
are retained distinctly; actual queue overflow must be observed, bounded and
link-local. Real lease expiry must occur with clients stopped and servers offline,
not be explained by a client deconfig callback. Portable tests separately challenge
fully expired queued events, capture backlog lower bounds and revoked unread events.
Session-long xid replay/contradiction protection must survive claim, age and
history saturation. Same-xid renewals may be processed but must retain the original
deadline; expired-proof rejection requests only that client's fresh acquisition.
Those replay/contradiction and rejected-renewal recovery counterexamples are
portable formal-runtime/parser tests, not a claim of VM replay injection or
naturally timed renewal qualification.

These results do not complete automatic selection, root recovery/reset, natural
timer T1/T2, installed systemd/boot qualification or same-schedule traffic comparison.
Previously collected exploration reboot evidence is not new service boot evidence.

### P0 renewable-client exploration gate

Use the actual foreground service and its own explicitly selected external
client. Require two natural renewal rounds per link with new xids and service
expiry extension, natural broadcast rebinding after B-only unicast loss, real
lease loss and changed-address reacquisition, and old ACK replay before/after
reacquisition without mutation. A's authority must remain independent; fresh
explicitly selected A/B LAN TLS traffic and zero cross-WAN DHCP counters are
separate evidence. Build provenance, matching-source dual-platform tests,
negative receipt controls and owned cleanup are required.

This gate qualifies only the pinned client's actual timer algorithm. Arbitrary
server T1/T2 options, history-saturation longevity, hostile DHCP, automatic
selection/convergence, installed systemd/reboot and physical WAN qualification
remain open; it must not be reported as completing the entire DHCP MVP.
This is an exploration-evidence gate, not approval of a default client. The
observed early loss after bounded rebinding attempts and option 58/59 timing
interoperability must be resolved or explicitly constrained before deployment.
