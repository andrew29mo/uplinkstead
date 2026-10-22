# Four-exploration review corrections

Two independent read-only agents reviewed routing/backend and policy/recovery,
then reviewed the corrections. Their agreement is not runtime evidence: the
retained real VM run and matching-source tests establish the observed outcomes.

## Defects corrected

- An inverted `not iif other0` RPDB rule was incorrectly treated as disjoint.
  Restrict the accepted external rule shape and reject inversion/unknown selectors.
  Require unique local/main/default built-in lookups; a missing local lookup can
  incorrectly send router-local destinations to the selected WAN.
- A valid non-object JSON response could terminate the agent instead of consuming
  one failed quorum target. Reject non-object, excessive nesting, non-finite JSON
  constants and invalid peer types. NaN otherwise broke strict JSON event storage.
- Healthy destination evidence could expire during preflight/readback. Carry a
  config/boot/round-bound proof through automatic admission and recheck before
  dispatch, with a bounded helper wait. This is not a kernel completion deadline.
- The fault fixture duplicated policy processing and manually set its latch.
  Production and driver now share `agent.cycle()`, with real probe timings,
  persisted switching history and all attempted LAN request outcomes retained.
- Report assertions disappeared under Python optimization. Report checks are now
  explicit; optimized validation runners refuse to execute assertion-based fixtures.
  The former HTML/API weakness did not prove the entire old runner falsely passed:
  its corruption controls still rejected that optimized execution.
- Report validation now checks healthy pinned samples, internal/local paths,
  service unit transformation, actual policy replay and additional negative controls.

## Evidence and limits

See [current validation](VALIDATION.md) for exact run identity and counts. Added VM
cases exercise inverted rules, missing local lookup, stale health during delayed
preflight and a real malformed TLS target alongside two healthy targets. Rejection
cases compare routes/rules before and after. The timing and persistent budget trace
comes from the formal cycle; systemd restart still uses the installed service.

Portable tests use doubles for boundary control; VM tests use real Linux routing,
TLS, processes and systemd. The driver is not itself the systemd scheduler. Deep
JSON/NaN cases are portable formal-probe tests, not separately claimed VM faults.
No sudden power loss, physical WAN, kernel-stuck netlink, zero-gap boot, saturated
load, full privilege separation or production readiness was established.
