# MVP architecture

## Supported topology and ownership

One static routed IPv4 LAN, two different WAN subnets and a local management CLI.
The Linux kernel forwards packets. The privileged writer probes and checks
admission; the unprivileged worker proposes selections. Packets do not flow
through Python. No host-wide route, NAT or firewall is taken over.

Two fixed probe tables (41001/41002) and one active LAN table (41003) are reserved.
Local marked probes use explicit source/device bindings. Each probe lookup has a
matching terminal prohibit rule. Absence of a route must not fall through to main.
The priority-zero local rule stays intact. LAN selection requires both `iif` and
source prefix. Declared internal prefixes consult only non-default main routes,
then prohibit on lookup miss; unknown internal topology is not guessed.

After administrative link-up, the writer restores only missing owned probe and
connected routes. A selected route removed while its interface is observed down
becomes no selection; arbitrary disappearance while up blocks. External main-table
return routes remain the network provisioner's responsibility.

The backend rejects unknown/intersecting RPDB rules, duplicate/missing owned rules,
reserved-table conflicts, unexpected route state, absent sources, disabled
forwarding and unsupported effective strict reverse-path filtering. Only plain positive lookup rules with exactly priority/source/ingress/table
selectors and a disjoint non-loopback ingress are accepted unchanged. Inversion,
unknown selectors and actions block entry; all three standard built-in lookup
rules must exist uniquely. Other root processes can
still modify these objects; exclusive deployment ownership is a trust assumption.

## Health and selection

Per-link state: UNKNOWN -> RECOVERING -> HEALTHY, and on failed rounds
SUSPECT -> DOWN. Infrastructure errors, missing/expired rounds and boot changes
invalidate health. Results are bound to the config hash, boot ID and round ID.
Three configured TLS endpoints use 2-of-3 quorum. Three consecutive good/bad rounds
establish initial health/failure. These values are policy, not measured optimality.
Malformed JSON objects, non-object bodies, excessive nesting and non-finite
constants and optional peer strings exceeding 64 UTF-8 bytes are target failures,
not a reason to reject the complete sample or terminate the agent.
A target set can fail together and does not prove Internet-wide availability.

Selected route (A/B/none) is separate from automation status. Unknown is never a
new destination. Failure of the selected link permits a healthy alternative;
unknown current-link status alone does not trigger speculative switching.
Default failback is manual/non-preemptive. Optional automatic failback requires
continuous stable evidence. The admission budget allows three automatic selections
in 60 seconds, including initial admission; excess latches DEGRADED_LATCHED.
The latch preserves selection and keeps probing. Clearing it requires the
implemented root-only guarded resume with fresh health and an explicit budget
reset acknowledgement. It deliberately trades some availability for bounded mutation.

Freshness uses boot-relative time. Process restart rebuilds health and retains the
history/latch. Cross-boot events count conservatively until a full budget window
has elapsed in the new boot; restart is not free switching credit. No wall clock
is used for policy decisions. Thresholds are configurable through validated input.

Automatic selection carries a config/boot/round-bound health proof. The Writer
checks it after preflight/readback and again immediately before dispatch; helper
waiting is bounded by the remaining evidence lifetime. This does not guarantee
kernel completion before expiry or continued link health after dispatch. Recovery
reconstructs recorded intent without requiring old health to become fresh again.
The original core exploration driver retains `agent.cycle()` for fault injection.
The deployed MVP separately uses `worker.step()` and `control.Controller`; its
qualification runs both installed services and the formal operator CLI.

## Writer and recovery

One writer holds an exclusive non-symlink lock in a private state directory.
Mutation subprocesses inherit its descriptor. A live stopped writer or inherited
helper blocks a successor; no lease expiry grants concurrent mutation rights.
Epoch check, durable intent, the real ip operation, helper retirement/readback and
completion run within this ownership interval. A timeout is not proof of no effect.
The agent exits on an unknown write outcome; a successor must reconcile before work.

Within a boot, pending intent is reconciled against actual routes. If actual equals
before, the pending decision is abandoned without replaying old health. If actual
equals intended, completion is reconciled. A third state blocks mutation. After a
new boot destroys the namespace routes, the recorded layout and durable pending
selection (otherwise last selected route) are reconstructed, then fresh health is
collected; reconstruction does not certify reachability.

systemd restarts failures with a bounded rate. Exhausted restart limits require
intervention; no promise of automatic eventual recovery is made. The source unit
uses control-group cleanup, a five-second stop timeout and bounded capabilities.
The fixture substitutes only namespace, source/config/state and dependency paths;
external fault wrappers pause real Writer boundaries and are not the shipped agent.

## Service and operator boundary

The privileged daemon owns Writer and observations, with a bounded SOCK_SEQPACKET
UNIX socket. SO_PEERCRED accepts only root and the dedicated policy UID. Root-only
operator commands are separate from sample/automatic proposal operations. Every
operator change and automatic selection is checked against a process epoch and
a same-process revision. Startup recovery and owned-route maintenance instead operate under the
exclusive writer and reconcile checks; they do not accept a caller-selected target.
Automatic proposals
also carry the latest round; the writer independently recomputes admission from
its own observations. This keeps health forgery out of the unprivileged boundary.
The capability-free worker computes policy and proposes selections; it cannot
read the state DB or issue netlink writes. Trusted probe/admission validation
remains in the writer, rather than pretending it is a tiny untrusted syscall shim.

Service mode is independent from selected route and health:

- DISABLED: no attached owned layout. First daemon start is detached.
- Enable intent -> install/complete layout -> PAUSED, without selecting a WAN.
- PAUSED: probe and maintain owned layout, but do not select automatically.
- Resume: require fresh healthy explicit target and root acknowledgement of a
  recorded budget reset; select if needed, recheck freshness after persistence,
  then decide to enter ENABLED. The reply itself has no freshness deadline.
- ENABLED: admit healthy automatic proposals within the persistent budget.
- Disable intent -> remove validated owned objects -> DISABLED. The operator
  explicitly acknowledges handoff to the preexisting main policy.

Enable/disable intent is durable before any write. A successor completes partial
lifecycle work under the same inherited-lock discipline. Stop leaves routes intact;
restart retains modes and reconstructs fresh health. RPC loss does not undo a
completed mutation; clients must inspect status, never automatically retry with a
new token. Unknown mutation/storage outcomes terminate the writer for reconciliation.

## Capacity and remaining boundaries

Protocol packets, peer wait/backlog and probe rate are bounded. Events retain 128
rows and 32-KiB payloads; budget history retains only relevant admission entries
and rejects more than 64. The SQLite main DB has 2048 4-KiB pages; rollback files
and system journald are separate resource domains. A low-space check is a guard,
not a filesystem quota or guarantee against concurrent disk exhaustion.

See [operations](OPERATIONS.md) for exact limits and deployment prerequisites.
Root writer compromise remains outside the boundary; namespace capabilities are
broad. No storage corruption repair, remote fleet control, HA, distribution package
qualification, physical WAN result or recovery-time guarantee is established.

## Optional single DHCP uplink

The [DHCP lifecycle](DHCP.md) is a separate controller and journal. It owns dedicated
41101/41103 tables and a supervised BusyBox client. It does not alter the static
A/B controller or share its health, switch budget or authority. Every lease update
invalidates health; restart quarantines persisted allocations before a new client
session. Integration of dynamic links into dual-uplink failover remains future work.

## Dual-DHCP exploration architecture

The [dual-DHCP exploration](DUAL_DHCP.md) uses a separate formal core/backend with
tables 41201/41202/41203. It is not two single-DHCP daemons and is not integrated
into either existing installed service. Local lease mutations and shared LAN
selection are distinct. Per-link client authority and health generations cannot
be replaced by a global callback revision; writer epoch/global selection revision
are a separate fence. Inactive renewal must preserve the other active route.

DHCP-bound local unicast and marked probes each have a per-WAN lookup plus a
terminal prohibit. Raw discovery/rebinding needs separate client/interface
qualification. New admission requires fresh HEALTHY; stale/unknown health and
invalid leases require withdrawal even while paused/latched. Required withdrawal
has no health-admission deadline, though helper timeout can still force recovery.
Valid callback completion services expiry; rejected old callbacks are readonly.
No hard scheduling bound follows from the synchronous core API.

Process/boot recovery quarantines all known old/new DHCP allocations rather than
reconstructing a static selected route. A client-only restart invalidates only its
own authority; the fixture orchestrates that restart, not a shipped supervisor.
Before a dual service MVP, bounded event intake, actual per-client supervision,
exact lease-time origin, automatic non-preemptive selection and operator recovery
must pass the additional gates in [the exploration contract](DUAL_DHCP.md).

## Formal dual-DHCP stage-one runtime

[Stage one](DHCP_STAGE1.md) adds root-local bounded intake and actual independent
BusyBox supervision around that core/backend. Probe rounds run off the writer
thread and remain generation/time bound. DHCP hook authority/time is fixed before
queuing; per-session intake sequence is durable and is never replaced with a
newer core revision at delivery. Each link has reserved finite queue slots.
Overflow/missing current wire evidence causes link-local retirement, not presumed
health or retries with newer identity. Root may explicitly choose a healthy link;
no automatic selection loop is present.

An AF_PACKET observer establishes a conservative original-REQUEST time lower
bound from the last proven-empty receive queue and matches ACK to hook allocation.
Queued events keep that bound; processing cannot add a full lease at delivery.
Within a capture session, reused xids retain the earliest bound and immutable
ACK semantics. Conflicting evidence invalidates even already-claimed queued
proofs; bounded history cannot evict that protection. Legitimate same-xid renewals
therefore cannot extend validity. Rejected expired hooks request link-local
reacquisition under the existing restart limiter, without automatic reselection.
Unclaimed new allocation evidence invalidates prior health. This can shorten
availability and is not exact packet timing or a hard cleanup deadline. Clients,
listener, probe workers and writer share the trusted root runtime; this is not
the static service's separate unprivileged policy-worker design.

## Renewable client exploration (P0)

[P0](DHCP_P0.md) selects an experimental external BusyBox build explicitly.
Process-local nonrepeating xids provide a new transaction boundary; the writer
continues to require matching wire evidence and fixed hook authority. The first-seen REQUEST watermark retires prior unanswered transactions too;
known superseded xids cannot reopen after a later request. A new REQUEST alone
does not withdraw an unexpired allocation. New transactions may extend deadlines;
same-xid ambiguity remains fail-closed. The default distro client is unchanged.
The build is separately GPL-governed and is not bundled with the MIT package.
Natural client renewal/rebinding is separate from negotiated DHCP option 58/59
qualification. Automatic selection, privilege separation and installed dual-DHCP
service recovery remain later MVP gates.
