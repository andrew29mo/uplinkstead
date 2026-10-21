# Retained evidence

[Final exploration run](exploration/README.md) · [Attempt ledger](attempts.json)

Only the final matching-source run is current. Prior failures preserve their own
source manifests and are not reproducible using a newer source snapshot without
checking out the corresponding historical files. Their raw private logs are kept
locally under ignored results, not uploaded. Some failed intermediate snapshots
are represented only by hashes, not a retained Git revision; this limits exact
historical source reproduction. The final source and tests are fully retained.
