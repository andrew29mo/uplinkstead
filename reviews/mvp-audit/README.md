# Historical pre-license audited MVP evidence

Run `6e56cd23e1a93f1d`, source fingerprint
`e3a3da9f938e0915e4b4ab49985878a1cb1ce3ebf65311ab7b2a776cb66f21a3`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Audit attempts](attempts.json)

81 tests per platform, 27 Linux VM scenarios,
36 rejected report corruptions, actual systemd process restart and
orderly VM stop/start. Counts are distinct evidence categories, not summed.

Use the verifier at commit `faf339b` for this pre-license manifest.
[Current MIT verification](../licensing/README.md) includes LICENSE and updated metadata.

See [review corrections](../../docs/MVP_REVIEW.md) and
[measurement scope](../../docs/VALIDATION.md). The first audit pass is preserved
with its own source fingerprint; only one native UTF-8 fixture expression changed
before the full final rerun. No raw logs, credentials, runtime DB or private settings
are uploaded. Source correspondence is not independent runtime attestation.
