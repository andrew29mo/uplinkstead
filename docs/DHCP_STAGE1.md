# Formal dual-DHCP service: stage one

This stage replaces the exploration's fixture-side event scheduling with
`uplinkstead.dual_dhcp_service`: a real foreground Linux service supervising its
own two BusyBox clients, observing DHCP packets and driving the formal SQLite
lifecycle/backend. There is **no automatic failover loop**. Root may explicitly
select a freshly healthy link. No installed systemd or new VM-reboot result is
claimed for this service stage.

## Event authority and finite resources

Each supervised client inherits a fixed link/session/boot identity. Its hook
creates one event ID and CLOCK_BOOTTIME creation time; it never fetches a new
writer revision, retries with a new identity, or starts a lease at delivery time.
Root-only SOCK_SEQPACKET intake validates a 4096-byte request and assigns an
immutable per-session sequence at admission. The sequence is persisted by
`wire_callback`; old session/boot/sequence/order is rejected without rebasing.
Historical `callback()` remains solely for old exploration fixtures.

The configurable queue capacity is 2..64 events (default eight). Each link gets
floor(capacity/2) reserved slots; an odd spare slot is unused. Filling B's slots
cannot consume A's in-process allocation. Overflow revokes B, drops its unread
events and requests B-only quarantine/restart. A loss event is not silently
discarded while retaining presumed-valid state. Duplicate IDs are rejected using
a bounded 64-entry per-session history; a duplicate ACK also cannot be claimed
twice. Queue acknowledgements mean **queued**, not durably applied. Inspect status
after a lost reply; never manufacture new authority to retry an old event.

Dequeue is the writer-operation ordering point. An operation already claimed
before revocation can complete; subsequent unread events cannot. Revocation
during a claimed write is serviced before publishing that write's final state.
This does not cancel a dispatched kernel helper or promise instantaneous cleanup.

One socket listener/backlog is bounded separately from the event queue. Connection
backpressure may reject a request before any payload is sent; this differs from
service rejection or an unknown outcome after sending. Packet-proof matching can
wait up to 0.2 seconds and operator replies up to 0.5 seconds on that listener.
Reserved event slots are not an end-to-end fairness guarantee for transport intake.

## Lease origin: conservative wire evidence

The original stage-one receipt below uses the distro client. The current
explicit [absolute-timer adapter](DHCP_TIMERS.md) adds fixed client REQUEST-origin
metadata, strict option 58/59 policy and a new xid at each T1/T2 phase. Admission
still requires the wire proof described here and uses the earlier origin; it
never substitutes a later client/hook timestamp to extend validity. Historical
stage-one receipts do not qualify the newer adapter.


The service opens an AF_PACKET ETH_P_ALL socket on each dedicated WAN **before
creating clients**. ETH_P_ALL is needed for outgoing REQUEST observation as well
as incoming ACKs. The strict bounded parser matches DHCP transaction/address/MAC/
server evidence to the hook's allocation. Unsupported/incomplete/ambiguous proof
does not authorize a new lease. The tested client reuses xid during renewal.
Because DHCP has no renewal sequence, an identical delayed ACK cannot be
distinguished from a fresh ACK after another REQUEST. For the entire capture
session, each xid therefore retains its earliest REQUEST bound and immutable
parsed ACK (including lifetime, gateway and route-option semantics). A new
REQUEST permits another claim, but never extends that xid's original deadline.
Contradictory ACKs or REQUEST address/server identities poison that xid and
invalidate queued proofs, including proofs already claimed from capture.
The bounded 64-xid history never ages out or evicts authority; saturation
invalidates all proofs until a fresh client session. Unproven hooks trigger
the existing link-local retirement path.

This is a deliberate availability tradeoff: a legitimate same-xid renewal is
processed but cannot extend validity. Expiry withdraws the link. A later hook
with an expired proof retires that client and schedules fresh acquisition,
subject to the restart limit; this path has portable formal-runtime coverage,
not a naturally timed VM renewal result. Short leases can exhaust the limiter.
Selection remains explicit after fresh health; no automatic reselection is promised.
DHCP transaction IDs are not cryptographic identities across client sessions;
hostile replay and colliding IDs across sessions are not qualified guarantees.

Each matched ACK retains its own observation version. A queued event cannot take
the current global version at delivery; if a newer allocation has been observed,
the older queued event is rejected. The pending-allocation flag remains set
until that newest matching proof is applied. This prevents a withdrawal followed
by accidental restoration of an older ACK from the queue. The two-ACK ordering
counterexamples (including same-xid replay and contradiction) are formal runtime/parser tests, separate from the live VM's
single-renewal backlog scenario.

RFC 2131 starts lease lifetime at the original REQUEST, not hook execution or
ACK processing. Ordinary userspace capture receipt time may be late. Therefore:

1. Immediately **before** a nonblocking recv that returns EAGAIN, record a
   CLOCK_BOOTTIME lower bound for the now-empty capture queue.
2. Every subsequently buffered REQUEST uses that previous lower bound until a
   new empty queue is proven. Retransmissions retain the earliest transaction
   bound. A stalled/draining observer does not substitute a newer receive time.
3. Match REQUEST/ACK proof once; keep request bound, observation bound, hook time
   and intake sequence immutable in the finite event queue.
4. Compute `expires = request_lower_bound + ACK_lifetime`. Processing a backlog
   cannot add time. If that deadline has passed, withdraw instead of activating.

This is a **conservative validity deadline**, not an exact packet-send timestamp.
Capture lag may shorten availability, including rejecting an otherwise live lease.
A newly observed supported ACK invalidates old allocation/health even if its hook
delivery fails. Current-authority hook claims without matching wire evidence also
retire only that client. An old client's hook cannot consume a replacement's proof.
DHCP itself is unauthenticated; this is not protection against a hostile L2 server.

The parser supports untagged Ethernet, unfragmented IPv4 and bounded DHCP options;
option overload is unsupported. Route options 33/121/249 are detected and rejected
as unsupported allocation semantics, rather than applied to external routing.
No general DHCP-client, VLAN/offload or off-link-server qualification is implied.

Primary material: [RFC 2131 lease calculation](https://www.rfc-editor.org/rfc/rfc2131.html)
and [BusyBox 1.36.1 client source](https://github.com/mirror/busybox/blob/1_36_1/networking/udhcp/dhcpc.c).
The installed distro build and actual VM behavior are recorded separately.

## Execution and supervision

Only the main writer thread enters SQLite and the network backend. At most two
probe rounds are in flight, one per link; each round uses the existing three
bounded TLS probes. Results retain their original start time and lease generation.
Slow rounds do not perform inline network waits on the event writer. Stale results
cannot update a replacement lease. Unexpected observer/probe failures stop safely;
not every worker fault is locally isolated.

A dead B client is reaped, B's lease/session/proofs are retired, and only B is
restarted after the configured delay. A is not restarted or assigned a new lease
generation. Each link permits three replacements within 60 seconds; exhaustion
leaves that client stopped until intervention/service restart. This limiter is
process-local, not the durable global automatic-switch budget. No automatic
infinite repair/restart promise is made.

Normal service stop reaps clients and removes DHCP allocations while retaining
terminal routing guards. It **does not hand the LAN to main's default route**.
Unknown backend/storage outcomes retain intent for exclusive recovery. Root,
CAP_NET_ADMIN/CAP_NET_RAW and cooperating ownership of the reserved objects remain
trust assumptions; threads/clients are not a separate privilege boundary.
Whole-writer SIGKILL/process-tree recovery is not qualified for this foreground
service. Normal stop reaps its children; deployment needs a process-tree supervisor
before promising recovery of orphaned clients after an uncatchable writer death.

## Run and reproduce

Install the package and the executable hook on a dedicated supported Linux host;
provision the documented routing/NAT/rp_filter contract first. Example foreground
invocation (not a distribution service installation):

```sh
python3 -m uplinkstead.dual_dhcp_service \
  --config /etc/uplinkstead/dual-dhcp.json \
  --journal /var/lib/uplinkstead-dual \
  --socket /run/uplinkstead-dual/events.sock \
  --hook /usr/libexec/uplinkstead-dual-hook.py
```

Runtime config extends the dual exploration config with
`runtime: {queue_capacity: 8, probe_interval: 0.2, restart_delay: 0.2}`.
The private socket directory must belong to root with mode 0700; the socket is
0600. Root-local status returns the writer snapshot plus snapshot time, bounded
recent event timing, capture counters, child PIDs and queue/rejection counters.
`processed` counts processed lifecycle notifications, including safety withdrawals;
it is not a count of admitted leases. Non-DHCP frames also count as unsupported
by the strict DHCP parser. `choose` requires the observed epoch/revision and link.

The dedicated VM runner launches this formal service and its actual clients; it
does not drive `DualLifecycle` directly or replace supervisors with fixture code:

```sh
.venv/bin/python -m tools.dhcp_stage1_validate \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-stage1
```

Native macOS runs portable tests only. Linux observations run in disposable
namespaces within one Colima VM. A deliberate one-second whole-service SIGSTOP
creates real capture/intake backlog; it is not an availability benchmark. Floods
separately account pre-send transport rejection and service rejection. Actual
expiry stops clients and servers so client deconfig cannot explain withdrawal.
Timeouts, source changes and cleanup failures cannot pass. Private keys/logs,
SQLite files, raw host-network snapshots and VM images stay excluded.

Still untested for this formal service: naturally timed T1/T2, physical WANs,
sustained capacity, installed stage-one
systemd/VM reboot, abrupt power loss, disk corruption, hard kernel cleanup timing
and boot-zero-gap. Stage two still needs automatic non-preemptive selection,
operator recovery/reset and an operational deployment contract.
