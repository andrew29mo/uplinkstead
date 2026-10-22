# Pre-publication review

Reviewed implementation: commit `faf339bb8f7663d1718a7be54966e26a281cc588`.
Source fingerprint: `e3a3da9f938e0915e4b4ab49985878a1cb1ce3ebf65311ab7b2a776cb66f21a3`.
This review changes documentation and adds sanitized receipts, not runtime source.

[Review receipt](../reviews/prepublic/receipt.json)
· [Package receipt](../reviews/prepublic/package.json)
· [Retained VM evidence](../reviews/mvp-audit/README.md)

## Consistency and actual checks

The current source matches every file in the retained manifest. The native suite
was rerun: 81 tests pass. The retained Linux receipt has the same 81 test IDs and
source, 27 VM cases, completed cleanup and a stopped VM. JSON/HTML correspondence
and all 36 corruption controls were rechecked, including under Python optimization.
No new VM test was run for this documentation review; a read-only Colima query
confirmed the dedicated VM was still stopped.

The retained measurements were recalculated from all 40 attempted requests:
fixed-primary 4/20 successes versus automatic 13/20, useful rates 0.379 and 1.365
requests/s, and all-attempt end-to-end p95 of 1039.5 and 1031.0 ms. The documentation
matches the raw writer/policy RSS snapshots and main DB sizes. No speedup ratio,
capacity, peak-memory, physical-WAN or recovery-time guarantee is inferred.

Installed-service cases, direct formal-core fault injection and synthetic verifier
fixtures remain explicitly distinguished. A stale architecture paragraph called
the now-implemented guarded resume a future workflow; it is corrected. The same
text now distinguishes token-checked operator/selection requests from exclusive
startup reconciliation and owned-route maintenance.

## Packaging and dependency scope

The declared Python wheel build succeeded with isolated build dependencies.
The wheel contains the 11 first-party Python modules plus distribution metadata;
every module matches the checked source byte for byte. Running outside the
checkout, the isolated import check loaded CLI/daemon/worker from the clean target
installation, and the installed console entry point's help ran successfully. This is a native macOS packaging smoke check, not a
Linux service installation from a wheel. Distribution package-manager integration
remains unqualified. The exact wheel hash and observed builder are in the receipt;
a future rebuild is not promised to have the same archive hash.

Runtime Python imports are first-party or standard library; package metadata has
no third-party runtime Requires-Dist entries. Setuptools is an external build
requirement, not bundled runtime code. Linux iproute2/systemd are separately
installed system dependencies. The fixture additionally uses nftables, OpenSSL,
Colima/Lima and a VM image. None of those programs/images, the Python runtime or
third-party model/data files are vendored into this repository or wheel. External
components retain their own distribution terms; no new dependency license grant
is made by this project.

## Privacy, retained files and license status

All 135 reachable historical text blobs at the reviewed commit were scanned for
private-key markers, common credentials/tokens and personal home/temp paths; no
matches were found. Historical filenames and current tracked file types contain
no runtime DB, credential, raw private log, environment directory, personal agent
instructions, VM image or built archive. Commit metadata uses GitHub noreply email.
Boot IDs, process IDs and synthetic fixture addresses are test observations, not
credentials. This is a scoped pattern/content review, not a proof of no possible
secret. Generated wheel/install files and build logs stay under ignored results;
only sanitized receipts are retained. Earlier raw evidence was not rewritten.

The repository remains **Private**, with the owner as its only collaborator.
There is no project LICENSE/COPYING file, SPDX license declaration or package
license metadata. README agrees. This review does not choose a license, publish
a package, change repository visibility or declare the project open source.

No new claim is made for sudden power loss, storage-corruption repair, boot-zero-gap,
physical hardware/ISP operation, sustained load, HA or production SLA. Publication
and project licensing remain separate user decisions.
