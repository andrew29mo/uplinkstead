# MIT adoption verification (historical)

Project license: [MIT](../../LICENSE), copyright 2026 Andrew Yuan.
This verification was recorded while the repository was Private. The repository is
now public; no package registry release is published.

[Dependency scope](../../docs/THIRD_PARTY.md) · [Review receipt](review.json)
· [Wheel/sdist checks](package.json) · [JSON](evidence.json) · [HTML](report.html)
· [macOS](native-unit.json) · [Linux](linux-unit.json)

Run `ebff911bee98054a`, source fingerprint
`8d888c2acccf3e46af48f855b0d8b61d59ca03dd16d4bfef13cb0bbf798117b3`. LICENSE is now included in that manifest and the uploaded
source snapshot, alongside package metadata and the formal implementation.

81 tests per platform, 27 isolated Linux VM cases,
36 rejected report corruptions, owned cleanup and a stopped VM.
These are separate evidence categories. No runtime product module changed.

This receipt belongs to commit `b2df3be919f819e6d4cbb8672107c2dcc51ad902`.
Its original verifier/source must be used to replay it. For the current source,
use [DHCP validation](../dhcp-audit/README.md) and
[static regression](../dhcp-audit-static/README.md).

Wheel metadata declares MIT and includes the exact repository license. The sdist
also includes it. Native installed imports and console help passed; installing
these archives as a Linux service was not separately tested. Use the Git checkout
for the complete validation fixture and deployment unit sources. No compiled
archive, toolchain, private log or VM image is uploaded.

Earlier pre-license receipts stay historical and unchanged; their then-unset
license metadata is not a declaration of the current license. External components
retain their own terms. See [validation scope](../../docs/VALIDATION.md) for VM,
power-loss, hardware and performance limits.
