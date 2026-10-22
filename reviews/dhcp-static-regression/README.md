# Historical static regression after the DHCP slice

Run `1d722bbdd25827be`, source fingerprint
`b4bc56ad24c52e3f9d02ec3f0e223f40df54c3d3c5d09930d5fbaf9195b0ad2f`.
This is the same implementation/tools/deployment/test snapshot as the separate
[DHCP validation](../dhcp/README.md).

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json)

96 portable tests per platform, 27 existing isolated Linux namespace scenarios,
36 rejected report corruptions, installed privileged/unprivileged services,
SIGKILL replacement and orderly VM stop/start passed. Root-network preservation,
owned cleanup, source removal and a stopped VM are verified. Normal and optimized
report verification pass.

The low-load, fixed-order traffic trial again records 4/20 successes with fixed
primary and 13/20 with automatic switching. Failures, intended/actual arrival
schedule and both service identities remain in the report. These are observations
from one run, not a speedup, capacity claim or recovery guarantee. The orderly VM
restart here tests the **static dual-uplink mode**, not the new DHCP service.
No sudden power-loss or physical ISP claim is made.

This historical receipt belongs to commit `da9f29034864d96f5e53beff4750df37c23ddc69`.
Use its original source/verifier to replay it. The
[current regression](../dhcp-audit-static/README.md) covers the reviewed source.
