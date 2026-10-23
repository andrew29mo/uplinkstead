# Independent closure review

Two read-only reviewers inspected the implementation and raw receipts separately.
Their agreement is not qualification; the concrete checks and rerun below are.

## Findings corrected

- The report accepted missing runner stages and excess writer capabilities.
  It now checks the exact stage sequence, interruptions, NoNewPrivileges and
  declared capability masks.
- Client binary equality alone did not check its upstream/transformation/build
  provenance. The qualified hashes are now checked against the frozen source.
- The report did not require the initial selection charge, fresh dual-link
  health/leases at final soak and restart, or retained restart-traffic evidence.
  Those conditions now have explicit gates.
- The old restart test submitted both an old epoch and old revision. A revision
  rejection could hide a broken epoch fence. The rerun independently varies
  each dimension, retaining actual arguments, replies and before/after state.
- A first draft of reporter tests depended on a receipt outside the VM source
  bundle. Review caught this before the VM run. The fixture is now self-contained,
  manifest-bound and labelled synthetic; a manifest-only temporary checkout and
  the real Linux source bundle both passed all 295 tests.

The original raw receipt actually had the correct writer privileges, qualified
client, first charge and new health. These were missing automated checks, not
evidence that those product behaviors had failed. No product code, resource
threshold, lease cadence or 64-entry capacity was changed in this review.

## Rerun evidence

Run `ab44c08f9940277e`, source
`a9b59ef9057ecb65e2f595576a1c402f9f628ce2c5deb49f4ba7ca5ff64199d7`:

- Fresh unmounted Ubuntu VM, documented installation of the same production
  wheel; installed modules and shipped units verified after retiring source imports.
- macOS/Linux: 295 identical tests, zero skips/errors/failures.
- Six real blackhole/recovery cycles; seven charges including initial selection.
- 268 samples over 540.006 seconds, same four process identities, no client restarts.
- Writer stable median RSS +1064 KiB; five-minute-tail median +176 KiB against
  unchanged +256 KiB allowance. Other tail RSS/FD/thread medians did not grow.
- Formal stop/start, fresh TLS, independent stale epoch/revision rejection and
  cleanup passed. The dedicated VM and its container-data disk were deleted.
- Thirty mutated-evidence controls reject; full JSON and exact HTML are retained.

## Remaining limits

The 64-entry history counts distinct first-seen REQUEST xids, including unanswered
requests. A new xid beyond capacity retires proof and requires a fresh client
session/admission/health, potentially interrupting traffic. The earlier capacity
attempt remains failed; it does not qualify rollover traffic or budget behavior.
Slower T1 in the final controls stays below capacity. Earlier failures and the
cadence change remain disclosed; this is not a causal RSS optimization comparison.

Resource allowances are finite short-run regression budgets, not a no-leak proof.
Historical failures retain summaries rather than complete raw samples. Power
loss, boot-zero-gap and physical-ISP interoperability were not tested here. Prior
reboot evidence keeps its own source and fixture-timer limitations.
