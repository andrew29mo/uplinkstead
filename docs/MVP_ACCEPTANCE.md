# Revised MVP acceptance after the four explorations

This document distinguishes current exploration evidence from work required for
an operational first MVP. Only outcomes linked by docs/VALIDATION.md are observed.

## Invariants retained

1. Probe A cannot use B, nor B use A, including missing-route and link-down states.
2. Only the declared LAN ingress/source and non-excluded destination scope changes.
3. A selected route, configured-target health and successful LAN requests are
   distinct observations. A route ACK is not application recovery.
4. Unknown operations do not release mutation ownership. A successor cannot
   overlap a live privileged writer/helper. Stale epochs cannot mutate successors.
5. The default is no preference-driven failback. Alternating faults consume a
   durable admission budget; excess latches automation without reboot reset.
6. Fresh automatic-admission proof is rechecked after preflight and immediately
   before dispatch; malformed individual target responses do not crash the loop.
7. Require unique built-in RPDB lookups and reject inversion/unknown selectors;
   test real LAN-to-router traffic as well as forwarded and excluded destinations.
8. Within a boot, reconcile durable intent against actual kernel routes. After a
   reboot, rebuild only the recorded owned layout/selection, then acquire new
   health evidence. Never infer health from an old success streak.

## Four exploration gates

| Gate | Required real evidence |
|---|---|
| Pinned probes | Both directions: up-but-blackholed remote path, deleted default, down interface; opposite path stays healthy; forbidden-egress counter unchanged; binding error UNKNOWN |
| Scope and round trip | Fresh LAN TLS flows select A/B; ordinary host and other-LAN flows stay on their route; main unchanged; declared internal lookup stays internal; unknown intersecting RPDB rejected; routed and NAT fixtures qualified |
| Mutation ownership/recovery | Actual Writer/backend at before-write, after-write and before-receipt crash boundaries; old pre-lock request rejected; stopped lock holder blocks successor; mutation helper keeps lock after parent death |
| Policy and restart | The shared formal agent cycle consumes timed real probe outcomes through alternating faults; all LAN requests retained; bounded selections and no default failback; real systemd SIGKILL restart and actual orderly VM stop/start; pre-Agent journal still pending |

Unit tests additionally challenge fresh/expired/old-config/old-boot/reordered results,
consecutive success/failure gates, missed rounds, optional stable failback and
cross-boot budget accounting. They are not claims of real hardware clock changes.

## Work remaining before calling this a usable MVP

- Separate privileged mutation from the policy/control boundary and qualify its
  narrow command schema; CAP_NET_ADMIN itself remains namespace-wide power.
- Add local operator status, guarded resume, explicit target selection and safe
  enable/disable. No direct SQLite edits as the supported user workflow.
- Qualify service deployment prerequisites, permission errors, drift detection,
  bounded history/disk usage and log retention. Do not silently alter other tools.
- Test enable/disable partial failure, actual command/helper timeouts and storage
  write failure; preserve unknown outcomes and ownership until retirement.
- Validate the optional automatic failback mode with live network timing; the
  current default non-preemptive mode is the initial deployment choice.
- Repeat identical arrival/fault schedules across a fixed-primary baseline and
  active failover. Count all attempted/unsent/failed/deadline-expired requests;
  report new-flow recovery, latency distribution, CPU and RSS with VM boundaries.
- Complete source/distribution integrity and separate native portable tests from
  Linux installed-service qualification. No public repository or license change
  follows automatically from passing tests.

## Excluded claims

No IPv6, bridge/VRF, dynamic uplink addressing, packet-level load balancing,
existing-flow/conntrack migration, transparent WAN reconnection, physical-device
qualification, HA, storage-corruption repair, sudden power-loss recovery or
boot-zero-gap protection. No Internet-wide health or maximum recovery time follows
from a configured probe quorum or one controlled VM run.
