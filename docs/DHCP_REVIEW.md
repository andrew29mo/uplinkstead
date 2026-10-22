# DHCP lifecycle review

Baseline: commit `da9f29034864d96f5e53beff4750df37c23ddc69`.
The review examined the formal lifecycle/service, portable tests, isolated VM
driver, raw receipts and report verifier. Two read-only reviewers covered logic
and evidence separately; reproduced behavior and actual reruns, rather than
reviewer agreement, determine the result.

## Runtime corrections

- A current, authorized bound/renew with unsupported options previously raised a
  validation error while keeping the old healthy allocation. A short new lease
  already expired in transit, or a latest callback beyond the admission window,
  had the same defect. These now consume the event and withdraw the old allocation,
  returning `lease_rejected` or `event_expired`. Retired sessions, old
  revisions and reordered events remain read-only rejections.
- Cached healthy status could survive the deadline until the next loop iteration.
  Snapshot health now checks current intent/allocation/deadline, and the service
  expires the lease again after receiving a request, before answering/admitting it.
- Runtime backend checks previously tolerated missing owned lookup/guard rules.
  Active operations now require the complete layout. Partial layout is allowed
  only during explicit reconciliation of known allocations. This does not make
  interference by another root network manager safe or provide continuous policing.

## Evidence corrections

- The original expiry scenario followed a blackhole, so forwarding was already
  withdrawn. The new scenario restores a healthy path first, records the data
  default and a successful LAN TLS request, stalls client/server, then verifies
  deadline, removed address/probe/data routes, retained guards and no backup use.
- A failing stale-event subprocess was previously enough to claim rejection.
  Transport/import/namespace errors could therefore pass. The revised check reads
  the formal IPC reply directly and requires `RetiredSession`, compares old/new
  session/PID/InvocationID, and verifies unchanged network and state. Generic
  `Blocked` is insufficient: it could mean time/revision expiry instead.
- The installed service hash was recorded but not checked. A shared, explicit
  fixture transformation now produces the expected unit; the verifier compares
  the actual installed file hash. Fragment path, absence of drop-ins, active
  process identity and capability bounding set are retained and checked.
- Report checks now reject contradictions in initial/restarted service identity,
  installed unit, missing/reordered stages, stale-event errors/readback, active
  expiry prerequisites and RSS process identity. Synthetic verifier tests are
  separate from measured networking scenarios.
- Unsupported renew withdrawal is exercised through the installed service's formal
  root socket while it is healthy. This is injected option data, not a malformed
  DHCP offer produced on the wire. A controlled restoration using only remaining
  lifetime then tests a latest callback with a synthetic past timestamp, which must
  withdraw again. This does not measure real operating-system scheduling delay.
  Existing wire renewal/gateway/address exchanges
  still run through BusyBox and the shipped hook.

Existing raw baseline receipts were internally consistent on the checks then
implemented. Missing checks do not prove those original runs suffered the runtime
failure, and the earlier expiry result does not establish active-route expiry.
Historical receipts are preserved, not rewritten as evidence for the corrections.

## Verification scope

Current receipts and counts are linked from [Validation](VALIDATION.md). They
separate installed-service/wire/IPC scenarios, direct core/backend injection and
synthetic portable verifier tests. The DHCP and static regressions use the same
manifest-listed implementation/tools/tests/deployment snapshot.

DHCP process replacement was tested; DHCP VM reboot, physical ISP, sudden power
loss and long-running natural T1/T2 scheduling remain untested. Static-mode VM
reboot results do not establish DHCP reboot behavior. Timings include fixture and
polling work; RSS is a single writer-process snapshot excluding client/kernel/VM.
No forwarding-capacity, peak-memory, hard-expiry or production-recovery guarantee
is derived from these runs.
