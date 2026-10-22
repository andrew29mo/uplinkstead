# Architecture after technical review

## Supported topology and ownership

One static routed IPv4 LAN, two different WAN subnets and a local management CLI.
The Linux kernel forwards packets. The agent probes and decides; packets do not
flow through Python. No host-wide route, NAT or firewall is taken over.

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
constants are target failures, not a reason to terminate the agent.
A target set can fail together and does not prove Internet-wide availability.

Selected route (A/B/none) is separate from automation status. Unknown is never a
new destination. Failure of the selected link permits a healthy alternative;
unknown current-link status alone does not trigger speculative switching.
Default failback is manual/non-preemptive. Optional automatic failback requires
continuous stable evidence. The admission budget allows three automatic selections
in 60 seconds, including initial admission; excess latches DEGRADED_LATCHED.
The latch preserves selection, keeps probing and requires an explicit future
operator workflow. It deliberately trades some availability for bounded mutation.

Freshness uses boot-relative time. Process restart rebuilds health and retains the
history/latch. Cross-boot events count conservatively until a full budget window
has elapsed in the new boot; restart is not free switching credit. No wall clock
is used for policy decisions. Thresholds are configurable through validated input.

Automatic selection carries a config/boot/round-bound health proof. The Writer
checks it after preflight/readback and again immediately before dispatch; helper
waiting is bounded by the remaining evidence lifetime. This does not guarantee
kernel completion before expiry or continued link health after dispatch. Recovery
reconstructs recorded intent without requiring old health to become fresh again.
The shipped agent and fault driver share the same `agent.cycle()`; the driver only
supplies tick commands and retains actual probe timestamps and persistent state.

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

## Deliberate gaps before MVP

- Restrict mutation behind a dedicated privileged writer API; policy/probe
  components do not yet constitute a privilege-separated service boundary.
- Implement authenticated local status/resume with fresh-evidence checks and
  audit semantics; editing the journal is not an operator API.
- Qualify the deployment contract and define safe enable/disable behavior.
- Bound event-history storage and complete packaging and operational documentation.
- Repeat fault/load measurements before any capacity or recovery-time claims.
