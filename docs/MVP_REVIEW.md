# MVP review corrections

The review starts from commit `d5cb4af`. Two read-only reviewers independently
examined the privilege/recovery boundary and the service/measurement evidence.
The main agent reproduced and repaired defects; reviewers checked the resulting
diff and counterexamples. Agreement is not a substitute for the retained VM run.

## Reproduced defects and corrections

1. **One target could suppress the entire sample.** A valid UTF-8 response with
   `peer` equal to 4,000 CJK characters fits the 16-KiB wire limit. Re-encoding its
   retained value for both links inflated a service event beyond 32 KiB, so the
   worker could not receive a complete sample despite two other healthy targets.
   Limit optional peer data to 64 UTF-8 bytes and classify excess as one target
   failure. This is a byte limit, not a character limit. Native tests use the
   original UTF-8 wire encoding; the VM tests a real oversized TLS response,
   continued two-vote quorum and a successful failover with unchanged writer ID.
2. **Expired history blocked manual selection.** Manual selection counted every
   retained admission rather than the configured time window. Share the same
   recent-history calculation with automatic admission and pruning. An actual
   persistent latch still requires guarded resume. Expiry/cross-boot rules are
   challenged in portable tests; no VM clock adjustment is claimed.
3. **Same-selected resume bypassed the later freshness check.** A slow budget save
   could expire health while no new route write was needed, then still enable
   automation. Recheck writer-owned health after persistence and immediately
   before deciding to enable. Expiry leaves PAUSED durable state and unchanged
   routing; it does not block necessary disable/recovery. This is decision-time
   freshness, not a guarantee that the eventual reply contains fresh health.
4. **Reboot report contradictions could still display PASS.** The collector
   checked selected receipt and live service, but the offline verifier omitted
   them. It now checks the pre-Agent pending/receipt/mode/latch/epoch against the
   pre-shutdown record, actual pre-reboot B route, post-boot live process/unit and
   distinct invocation identities. New negative controls reject dead-unit or
   receipt/latch contradictions. Original retained observations were consistent;
   the counterexamples exposed validation holes, not a failed historical reboot.
5. **The fixed-primary baseline could use the wrong exit.** Receipt A and
   post-fault failures did not prove pre-fault successful packets used A. Both
   collector and verifier now require pre-fault successful A requests, fixed-mode
   successes on A and post-fault automatic successes on B. Record actual fault
   insertion offsets and process identity before/after RSS measurement; reject
   service replacement or a fault installed after the affected requests.

## Evidence boundaries

See [current validation](VALIDATION.md) and the linked JSON/HTML for exact source
identity, counts and measurements. The large-peer case uses the installed writer
and unprivileged policy service plus the formal CLI and real TLS traffic.
The delayed-resume case stops those units, then invokes the actual Controller,
Writer, probes and Linux backend while delaying a real durable save; reopen checks
the persisted mode. It is not an installed-RPC fault injection or an abrupt VM crash.
Synthetic verifier fixtures challenge individual checks and are not VM evidence.

Privilege/SO_PEERCRED and epoch/revision/round checks had no reproduced arbitrary
command/route or UID escalation in this review. That is a bounded review result,
not a proof of absence. The root writer retains broad namespace capabilities and
trusted probe/admission code. No sudden power loss, storage-corruption repair,
physical WAN, boot-zero-gap, sustained load or production SLA was established.
