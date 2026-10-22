# Milestone 1: automatic dual-DHCP foreground integration

This opt-in mode uses the production dual-DHCP runtime, SQLite lifecycle, wire
intake, pinned TLS probes and scoped Linux backend. It adds automatic decisions;
it does not complete the installed dual-DHCP service or its recovery interface.

## Selection contract

Configure a new, controlled service journal with:

```json
{"queue_capacity":8,"probe_interval":0.2,"restart_delay":0.2,
 "automatic_selection":true,"selection_hold":1.0,"failover_delay":2.0}
```

`automatic_selection` defaults false. It implies `restore_selected: true`;
explicitly disabling restoration while enabling automatic selection is rejected.
Both delay values must be finite numbers in 0.05..30 seconds. Configuration is
hash-bound to the journal: changing an existing live config is not a supported
migration, and deleting a live journal to reset budget is not a recovery method.
WAN interfaces must remain dedicated. The backend does not issue main-route
updates, but Linux can remove interface routes when its last IPv4 address is
deleted during lease withdrawal. It does not restore another manager's main
routes. The fixture reprovisions its independent A/main witness after a clean
service replacement; this must not be mistaken for a product recovery feature.

- Initial selection requires an admitted current lease, generation-bound fresh
  TLS health and a continuous observed HEALTHY interval of `selection_hold`.
  If both candidates qualify, A is preferred; a usable B need not wait indefinitely
  for A. Initial selection consumes one budget record, preserving existing choose
  semantics. This is not a guarantee that A always wins asynchronous acquisition.
- A selected HEALTHY/SUSPECT path is not preempted. There is **no automatic
  failback**. Consecutive failures/freshness expiration or lease loss cause the
  lifecycle to withdraw its route; no main-table default is selected as fallback.
  A fresh successful round on an already-qualified, still-selected SUSPECT
  generation repairs that path without forcing it through UNVERIFIED/withdrawal.
  This exception cannot qualify an unselected backup or a new/expired lease.
- After withdrawal, `failover_delay` gives the previously selected WAN time to
  recover a renewed lease. Another candidate also needs the healthy hold. A WAN
  change uses the existing authoritative `choose`, appends budget history and
  respects durable pause/latch. If both are eligible after withdrawal, the last
  selected WAN is preferred. No fixed detection/failover-time upper bound follows.
- Same-WAN **new-lease-generation** restoration retains the existing fresh-health
  contract and does not consume manual/switch budget. One success per generation
  and a separate 16-dispatch/60-second bound remain. A HEALTHY newer lease blocked
  by that restore bound cannot fall through to a charged same-WAN `choose` or
  induce an unnecessary cross-WAN change. A prolonged absence of usable new health
  can legitimately cause a charged switch; renewal is not a zero-outage promise.
- A same-generation path that failed and later recovered requires a charged
  selection; it cannot repeatedly use the free renewal exception. Budget
  exhaustion latches; later renewals/health recovery do not reset or bypass it.
  Pause/latch never blocks safety withdrawal.

The runtime records bounded `automatic` status, choice/invalidation counters and
up to 16 `selection_events`. Candidate hold and withdrawal timers are volatile.
Writer reopen still quarantines allocations and clears old health/restoration
arming; automatic mode may choose again only after new acquisition and fresh
qualification, with preserved budget/latch. Installed restart behavior is a later
milestone, not qualified by portable reopen tests.

## Intake/write interleavings

All runtime selections, including operator choose and free lease restoration,
check the target's capture version/pending flag, queued events/revocation and
intake sequence before dispatch, then recheck after the actual writer operation.
A changed stamp or pending event triggers production withdrawal, clears that
allocation/health and records the invalidation before the next publication.
An attempted charged selection remains charged if a concurrent event invalidates
it; unknown mutation outcomes retire the writer through its existing failure path.

A later ACK can still arrive **after** the final check. It is handled at the next
runtime step; this is not an atomic transaction between packet reception and the
kernel routing table. Neither the code nor these experiments promise zero-gap,
continuous forwarding, exact kernel-removal time or preservation of existing TCP
connections. Delayed probe results remain generation-bound; delayed operator
requests retain their original epoch/revision and are rejected after mutation.

## Reproduce and acceptance

Use the dedicated initially stopped Colima VM and existing external client build:

```sh
.venv/bin/python -m tools.dhcp_automatic_validate \
  --archive /path/to/busybox-1.36.1.tar.bz2 \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-automatic
```

Six service cases launch the shipped foreground service directly. They
exercise automatic initial A, A blackhole→B, four subsequent natural B renewals,
real client B release→A, delayed stale operator rejection, observed SUSPECT recovery/no
preemption, both-down withdrawal and exhausted-budget latch. The configured
budget is four, including initial selection. No manual choose drives successful
selections. A viable A/main TLS witness succeeds while latched LAN traffic fails.
The initial-A fixture withholds B server replies until A is selected; it does not
assume dnsmasq beats the deterministic B server. Simultaneous eligible-candidate
preference is a portable runtime test, not an inference from DHCP response speed.
To exercise budget exhaustion, A recovers while B remains unhealthy, forcing a
charged cross-WAN attempt. Only after latch is observed does B recover/renew:
full budget alone does not forbid the intentionally free same-WAN renewal path.

Two additional cases use `tools.dhcp_automatic_fault_service` only as a test
launcher. It delegates every mutation/readback to the production backend and adds
one bounded pause **after real B route write/readback, before writer completion**.
During the pause, the actual client receives a renewal trigger or release signal;
its shipped hook queues an ACK-backed renewal or deconfig. The pause is released
only after intake is observed. Require formal invalidation/withdrawal, fresh
new-generation recovery for ACK, and absence of B allocation after loss. This
wrapper is not installed or presented as the unmodified production service.
It does not model a crashed helper or every possible write interleaving.

Portable tests exercise the actual runtime/core under controlled time and IO,
including old probe completion, queued old operator requests, pause/latch, restore
rate saturation and both write-race conditions. They do not substitute for Linux
backend evidence. Same-source macOS/Linux test IDs, actual client build hashes,
failed/timed-out stage rejection, corrupted-receipt controls, exact JSON/HTML and
owned cleanup/stopped VM are mandatory. RSS is a VM process snapshot, not a peak;
scenario durations include lease/detection waits and are not outage SLOs.

See [retained evidence](../reviews/dhcp-automatic/README.md).

## Still outside milestone 1

Dual-mode privilege separation, root reset/resume API, installed start/stop and
VM reboot qualification, sustained history-capacity rollover, same-schedule
application traffic/outage distributions and physical-WAN interoperability remain
separate gates. The existing static/single-DHCP deployments retain their own
contracts. No IPv6, PPPoE, connection migration, boot-zero-gap or sudden power-loss
qualification is claimed. The pinned external BusyBox client remains separately
GPL-governed and is not bundled into this MIT repository.

### Probe-target fixture isolation

The fixture TLS server performs handshakes in request workers with a one-second
socket timeout, rather than blocking the accept loop on an unfinished handshake.
A separate VM fixture control holds two TCP connections open without sending TLS
and requires a concurrent normal LAN TLS request to succeed. This is a fixture
qualification case in addition to the eight service/fault cases, not a new
product capability or a claim about arbitrary probe-server failures.
