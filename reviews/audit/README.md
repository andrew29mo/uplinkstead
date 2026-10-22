# Historical audited exploration evidence

Run `0a60c943b1429c7f`, source fingerprint
`2d59b046105fdbcebb5903e0c906fc5de17bd2c30f8135e2ac11ae4969b9dba0`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Audit attempts](attempts.json)

56 tests per platform, 19 real Linux namespace scenarios, actual systemd process
restart and orderly VM stop/start, 20 rejected report corruptions, successful
owned cleanup, removed source snapshot and stopped VM. Counts describe different
evidence categories and are not summed into one test count.

Use the verifier at commit `732a518` for this historical 19-case schema.
[Current MVP qualification](../mvp/README.md) uses additional installed-service cases.

The first audit run passed its then-current 54-test source and is retained as
[superseded evidence](superseded/audit-01.json). A subsequently reproduced malformed
probe serialization defect prompted two more tests and the final full rerun.
Neither audit pass rewrites the initial exploration failures.
No raw logs, credentials, runtime database or personal settings are retained.
Manifest correspondence is not independent attestation. See
[validation boundaries](../../docs/VALIDATION.md).
