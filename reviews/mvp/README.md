# Historical first MVP qualification

Run `5f8e4f7a4027c930`, source fingerprint
`2a8ef69d31cfb697e7c71591128c06ae6d48d3f609b9c9bdd4e6adf1d76431f2`.

[Complete JSON](evidence.json) · [Deterministic HTML](report.html)
· [macOS](native-unit.json) · [Linux](linux-unit.json) · [Attempts](attempts.json)

75 portable tests per platform, 25 real VM scenarios,
27 rejected report corruptions, actual installed writer/policy services,
SIGKILL restart and orderly VM stop/start. These are separate evidence categories.

Use the verifier at commit `d5cb4af` for this historical 25-case schema.
[Current audited qualification](../mvp-audit/README.md) includes additional cases.

Prior failures and the superseded pass retain their own source identities.
Not every intermediate source is committed, limiting exact replay of old attempts.
Only the final current source is claimed reproducible. Raw logs, credentials and
runtime databases remain excluded. See [validation](../../docs/VALIDATION.md).
