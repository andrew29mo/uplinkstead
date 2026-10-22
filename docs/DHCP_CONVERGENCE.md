# P0: selected-WAN lease and route convergence

This foreground integration restores the **previously operator-selected WAN**
after a newly admitted lease has fresh health. It does not select a different WAN,
perform automatic initial selection or complete the deployed dual-DHCP MVP.
The static and single-DHCP installed modes retain their existing contracts.

## Decisions

A captured supported ACK still quarantines that link's old allocation and health.
Same-address renewal, changed address/gateway and reacquisition all require a new
lease generation and newly started generation-bound TLS quorum. This version does
not optimize away renewal interruption or preserve existing connections.

An explicit successful `choose` arms a volatile runtime target. With
`runtime.restore_selected: true`, the main writer can restore that WAN once per
new lease generation after fresh health and completed ACK admission. Pending
capture evidence, absent/expired lease, pause or latch prevents restoration.
A successful selection records a journalled link/generation anchor. It cannot be
used to restore another WAN, or to repeatedly restore the same generation after
health flapping. Stale operator tokens and old health remain invalid.

Automatic lease restoration does not append the global manual-selection/switch
history. Manual `choose` retains its existing charging semantics, including an
explicit same-WAN selection. A→withdrawn→manual B still consumes budget; withdrawal
does not erase history or grant free cross-WAN switching. New selections update
the anchor only after the formal mutation. A failed/unknown network write retires
the writer through its existing recovery path.

A separate runtime bound permits at most **16 restoration dispatches per rolling
60 seconds**. Saturation leaves the path withdrawn and reports `RATE_LIMITED`;
it does not reset global history or latch. This is not a general guarantee of
availability for extremely short leases or rapid configuration churn. Routine
5-second T1 renewals in the qualified fixture stay within that limit. One
successful restoration per generation also prevents same-generation health
flapping from becoming an unlimited retry loop.

Writer reopen clears the restoration anchor and quarantines old allocations;
runtime restart starts disarmed. Budget and latch remain durable. Explicit fresh
operator selection is required to arm restoration again. This is a deliberate
scope boundary, not installed-service or VM reboot qualification.

## Activation and operational scope

This feature is opt-in; `restore_selected` defaults to false. Add it to a freshly
prepared controlled dual-service configuration's existing runtime object:

```json
{"queue_capacity":8,"probe_interval":0.2,"restart_delay":0.2,
 "client_diagnostics":true,"restore_selected":true}
```

Use the explicitly selected, externally built [timer client](DHCP_TIMERS.md).
The distro client default is unchanged and is not the client qualified here.
The service configuration is hash-bound to its private journal; changing flags in
an existing live journal is not a supported hot migration. Do not delete a live
journal to bypass that check. Deployment/configuration handoff is a later gate.
The additive journal field migration supports otherwise unchanged historical
configurations and retains their budget; unknown state fields still reject.

Status reports `runtime.restoration` (enabled, target, status, recent dispatches,
limit/window), restoration attempt/success counters, and the journalled selection
anchor. Queue acknowledgement still means queued, not applied; operator timeout
still requires inspection. No new externally callable restore/health injection
API is introduced. The runtime remains trusted root code in this P0.

## Reproduction and acceptance

Use the same dedicated stopped Colima relay VM/toolchain and verified external
BusyBox archive as the timer workflow:

```sh
.venv/bin/python -m tools.dhcp_convergence_validate \
  --archive /path/to/busybox-1.36.1.tar.bz2 \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-convergence
```

The fixture launches the actual foreground service, shipped hook, compiled client
and production Linux backend. It does not call lifecycle methods to manufacture
lease acceptance or select the path after each renewal. A is served by dnsmasq
with a longer lease to isolate B side effects; B uses the deterministic local
DHCP server. This is not a comparison of those two server implementations.
Address changes use a real NAK followed by fresh acquisition; gateway-only changes
use the same address. Forced renewal bootstraps changed profiles; the repeated
normal renewal case uses subsequent natural T1 transitions.

Acceptance requires:

- Initial state remains unselected; B renews while selected A's identity, PID and
  selected route remain unchanged, with a successful new A LAN TLS request.
- After one manual B choice, four natural renewals automatically restore B with
  new generations and fresh quorum. The two-entry global history remains unchanged
  even though the configured global budget is already fully consumed.
- Changed address/gateway cannot restore while B TLS probes are blackholed, even
  with A healthy and a forbidden fallback usable. Unblocking permits fresh B
  health and automatic B traffic; gateway-only change is independently exercised.
- Expiry removes B's address, probe and LAN routes without selecting A. Sampled
  first withdrawal cannot predate the conservative writer deadline. Changed-address
  reacquisition restores B automatically; a received/processed old ACK cannot
  overwrite it. This is sampled publication evidence, not exact kernel timing.
- Another manual WAN choice exhausts/latches the budget. A later healthy B renewal
  remains withdrawn while latched. Safety cleanup still applies.
- Same-source macOS/Linux unit IDs, actual build readback, corruption controls,
  JSON/HTML agreement and owned cleanup/stopped VM are required. VM process RSS
  is recorded separately; scenario durations include intentional lease waits and
  are not speedup, throughput or failover SLO measurements.

See [matching-source evidence](../reviews/dhcp-convergence/README.md). Rate limiting,
old health/tokens, same-generation retry rejection, journal migration and
writer-reopen disarming additionally have portable formal-core/runtime tests;
these must not be labelled separate VM fault injections.

## Remaining work

No automatic cross-WAN failover, policy-worker privilege separation for this mode,
operator reset/recovery API, installed systemd/reboot recovery, 64-transaction
history longevity, full DHCP interoperability, arbitrary packet flood/loss,
physical WAN, boot-zero-gap or sudden power-loss qualification follows. Existing
TCP sessions may break; renewal interruption remains. No benchmark advantage or
production-readiness claim is made.
