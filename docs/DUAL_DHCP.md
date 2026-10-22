# Dual-DHCP technical explorations

Historical exploration scope; the newer [formal stage-one service](DHCP_STAGE1.md)
replaces fixture event scheduling for its own separately recorded validation.
The hook-time approximation below applies to the historical adapter, not the
new runtime's conservative wire-derived deadline.

This is a bounded integration of the formal `DualLifecycle` core and Linux
`Backend`, not a shipped dual-DHCP daemon. The static dual-uplink and single-DHCP
services keep their existing semantics. The exploration driver owns orchestration;
it does not establish a production client supervisor, IPC queue or automatic
failover loop. Tests exercise the modules under `uplinkstead/`, not a second
implementation of routing/lease admission inside a report script.

## Ownership and state

One exclusive writer owns dedicated WAN addresses, tables 41201/41202 and the
LAN table 41203. Each WAN has marked probe and device-bound local lookup rules,
each with a terminal prohibit. Local DHCP unicast therefore has a per-device
lookup independent of which WAN carries LAN traffic. Raw DHCP discovery/broadcast
is client-interface-bound and needs separate wire observation; a TLS probe alone
does not establish DHCP control-plane isolation. The priority-zero local rule and
main routes remain untouched. Forwarding, rp_filter, upstream NAT and return
routes are explicit fixture/deployment responsibilities.

Per-link mutations remove/rebuild only that link's allocation and probe table.
An inactive B renewal must not flush or recreate the active A data route. Shared
selection is a distinct operation. A proposal that overlaps the other current
allocation is rejected by withdrawing only its own previous allocation. Recovery
retains both old/new pending allocations until exclusive quarantine. Unknown
foreign addresses/routes/rules block rather than being deleted or repaired.

Each link owns a client session, event revision, lease generation and monotonic
event ordering. New/renewed leases invalidate only their own health. Health is
generation-bound, volatile, quorum-based and expires independently of lease time.
New selection requires HEALTHY; SUSPECT can retain an existing route only until
the bad-round threshold or prior evidence deadline. UNKNOWN cannot retain a
selected route. Lease expiry or change withdraws regardless of pause/latch.

```text
phase:  RECOVERING | READY | RECOVERY_REQUIRED
paused: false | true
latched: false | true
active: none | {link, generation, value}
link:   WAITING | UNVERIFIED | HEALTHY | SUSPECT | DOWN | UNKNOWN
```

The core does not automatically choose the alternative: the exploration driver
explicitly requests a healthy target and the writer independently checks it.
Initial selection/reacquisition counts against the persistent budget. Safety
withdrawal does not. History from an older boot is conservatively retained; an
operator recovery/reset contract must be designed before a deployable MVP.

## Four exploration contracts

1. **Lease isolation:** two real BusyBox clients acquire separate dnsmasq leases.
   Inactive renewal/client replacement leaves the other link's allocation,
   authority, proof and selected identity unchanged, with a new LAN TLS request.
   Callback timestamps are retained, not refreshed on submission. Fixture hooks
   capture fixed client session/boot at process creation. Callback revision is
   assigned by this serialized adapter; production delivery/ack semantics remain
   an MVP gate, not a proven queue implementation.
2. **No borrowing:** both blackhole directions, missing own probe table and a
   positively usable main fallback are checked separately. Natural T1 renewals
   use each WAN's own server, with counters for wrong-WAN server packets. This
   does not qualify natural T2 rebinding, off-link servers or all DHCP stacks.
3. **Conflicts/options:** an explicitly synthetic cross-link callback challenges
   the formal admission path. A separate actual dnsmasq offer from isolated WAN A
   overlaps B's live subnet and must leave B's state/data path unchanged. The
   server-side extra address is an explicit fixture action, never a product write.
   A real wire option 121 challenges BusyBox hook export and formal withdrawal.
   These are different provenance layers; a synthetic conflict is not evidence
   of a conflicting wire offer. Option 33/249
   handling must receive actual wire qualification before claiming coverage.
4. **Fault recovery:** SIGKILL and successful address-write-then-exception exercise
   formal state and actual backend. A fresh writer quarantines both allocations,
   never replays persisted DHCP health, and requires wire acquisition again.
   Orderly VM stop/start retains the pre-stop journal after killing the core;
   before new-boot core entry the journal hash must still match. Topology and
   core startup are manually orchestrated, not automatically installed systemd
   startup. An actual inherited-descriptor delayed-helper test is portable;
   its fake network backend must not be presented as a VM route-mutation test.

## Reproduce and evidence

Use a dedicated stopped Colima `relay` VM already provisioned with Python 3.12+,
iproute2, nftables, BusyBox, dnsmasq and OpenSSL. Do not run namespace fixtures on
a production host. No new host default route, NAT or firewall is installed.

```sh
.venv/bin/python -m tools.dual_dhcp_validate \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-dual-dhcp-run
```

The runner retains matching-source native/Linux test IDs, separate stage timings,
guest observations, boot identities and JSON-derived HTML. Failure, timeout,
source change, missing stages, cleanup failure or a running VM rejects the run.
The fixture records owned namespace identities before testing; fallback cleanup
refuses to delete replacements. Raw logs, fixture keys, live SQLite and VM disks
stay ignored and are not exported as public evidence.

The measurements are controlled low-load VM scenario durations, not failover SLOs,
capacity benchmarks or evidence of physical ISP behavior. No comparison speedup
is claimed. DHCP hook time plus supplied lifetime is an approximate
exploration deadline, **not proof of the exact RFC lease expiry instant**; packet
request/ACK timing, queue delays and natural T2 require additional work. A delayed
hook can make this approximation later than the actual DHCP expiry; it must not
be used as a claim of protocol-exact lease validity. In
particular a hard kernel cleanup deadline is not established by a Python tick.

## Required MVP gates after these explorations

- Bounded intake that captures immutable authority/time, preserves required lease
  loss events, prioritizes expiry and reports unknown RPC outcomes without rebasing
  old events. Slow probes must not block callback intake. Validate real queue
  overflow, concurrent renewals and delayed ip helpers, not only direct API calls.
- Independent client supervision: only the failed client is retired/restarted;
  writer failure quarantines both. Ship and qualify the actual dual service unit.
- Define lease time origin and supported DHCP server/options contract. Test delayed
  delivery and natural T2, including successful B traffic while A renews/rebinds.
- Add the automatic non-preemptive selection loop and guarded operator recovery;
  preserve budget across boot without making restart free switching credit.
- Repeat dual service orderly reboot with pre-client backend evidence; qualify
  real delayed network helpers and same-schedule fixed/automatic traffic before
  making performance, availability or rollout claims.

Sudden power loss, torn writes, storage corruption, boot-zero-gap, connection
migration, IPv6, PPPoE and production readiness remain untested/unimplemented.
