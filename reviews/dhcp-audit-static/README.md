# Static dual-uplink regression after DHCP review

Run `887f7604f7979e60`, source fingerprint
`18b9518ae1cbaaa8598c996bf73d3c4e8576508c02a6ede7745c1237cc652caf`.
The [reviewed DHCP run](../dhcp-audit/README.md) uses the exact same source manifest.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Review findings](../../docs/DHCP_REVIEW.md)

104 portable tests per platform, 27 existing isolated Linux namespace scenarios,
36 rejected report corruptions. Installed privileged/unprivileged static services,
SIGKILL replacement, orderly VM stop/start, owned cleanup, source removal and a
stopped VM passed. Normal and optimized report verification both pass.

The single, low-load, fixed-order trial records **4/20** successes with fixed
primary and **14/20** with automatic switching. All failures, arrival times and
service identities remain in JSON/HTML. Earlier runs recorded 13/20 automatic
successes; these runs have uncontrolled variation and do not establish a speedup,
capacity, improvement or recovery guarantee. Do not pool them as a controlled
repeated-trial benchmark.

VM reboot recovery here belongs to the **static dual-uplink mode**. It does not
qualify DHCP-mode reboot or power-loss recovery. Physical WANs, sudden power loss
and sustained/saturated forwarding remain untested. RSS snapshots exclude VM,
kernel and unrelated-process memory.

```sh
.venv/bin/python -m tools.report reviews/dhcp-audit-static
```
