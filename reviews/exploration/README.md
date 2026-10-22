# Historical initial exploration evidence

Run `0d654962a2900a8b`, source fingerprint
`c1de7e81770bd87a427209b087f478aebf8496e5db8ca376478de79190769a0b`.

- [Complete JSON](evidence.json) and [deterministic HTML](report.html)
- [macOS portable suite](native-unit.json) and [Linux portable suite](linux-unit.json)
- [All attempts](../attempts.json), including seven failures, never relabeled PASS

39 tests per platform, 15 live Linux namespace scenarios, actual systemd process
restart, actual orderly VM stop/start, ten rejected report corruptions, owned
cleanup and stopped VM. Different evidence categories are not one test count.

This is historical evidence for commit `db00f523171bd6aa1356383416b87189d5135439`.
Use that revision's verifier to reproduce its original 15-case schema. The current
19-case verifier intentionally requires the additional audit evidence.
See [current review](../audit/README.md).

No runtime journal, TLS key/cert, VM snapshot/image, private log or personal settings
are included. Source hashes establish correspondence, not independent attestation.
