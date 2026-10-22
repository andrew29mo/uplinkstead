# DHCP lifecycle review and corrected evidence

Run `52181356e66119f7`, source fingerprint
`18b9518ae1cbaaa8598c996bf73d3c4e8576508c02a6ede7745c1237cc652caf`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Review/failed attempt](review.json)
· [Findings and corrections](../../docs/DHCP_REVIEW.md)
· [Deployment/limits](../../docs/DHCP.md)
· [Same-source static regression](../dhcp-audit-static/README.md)

104 portable tests on each platform, identical source and test IDs, zero skips.
Nine isolated Linux scenarios comprise eight installed-service/wire/IPC checks
and one direct formal-core/backend command-boundary fault. Twenty-three corrupted
report variants reject. Normal and optimized report verification pass.

- Real wire acquisition/renewal, gateway and address replacement use BusyBox and
  the shipped hook. Renew/gateway changes are SIGUSR1-triggered; address replacement
  uses release/reacquisition. Long-running natural T1/T2 scheduling is not qualified.
- Actual systemd SIGKILL replacement records different session/PID/InvocationID.
  A frame with current boot/revision but retired session receives `RetiredSession`;
  state and independent network readback remain unchanged. Transport failures and
  generic time/revision `Blocked` errors cannot qualify this result.
- A current unsupported renew is injected through the formal root socket while
  healthy. It consumes the revision and removes old addresses/probe/data routes,
  without replacing the service. A controlled restoration uses only the original
  wire lease's remaining lifetime, then a newer but backdated current-authority
  callback must withdraw again with `event_expired`. These are synthetic IPC and
  timestamp tests, not on-wire invalid offers or actual scheduler-delay tests.
- A proven reachable main backup is present. Blackhole yields unhealthy status,
  failed LAN TLS and zero observed backup packets. The uplink is then restored.
- Deadline testing starts with healthy status, an active default and successful
  LAN TLS over the intended path. Client and server are stalled until the real
  lease deadline. Afterward the allocation/probe/data routes are absent, all six
  owned rules remain, LAN TLS fails and backup packets stay zero.
- A fault after an actual backend write retains old/new intent; reopening the
  formal lifecycle quarantines allocations rather than replaying saved health.
  This is command-boundary injection, not physical I/O failure.
- Actual installed unit content matches the declared fixture transformation.
  Fragment path, no drop-ins, capabilities, process identities, RSS provenance,
  ordered stages, source removal and owned cleanup are checked. VM is stopped.

Writer RSS snapshot: **23,916 KiB**; SQLite main file: **8,192 bytes**.
These exclude the client, kernel, temporary journal, filesystem and VM. Case
elapsed times include fixture operations/protocol timers/polling and establish no
capacity or recovery SLO. The expiry observation is one sample, not a deadline bound.

DHCP service restart and portable changed-boot logic are covered; DHCP VM reboot,
sudden power loss and physical ISP failures remain untested. Static-mode VM reboot
cannot establish DHCP-mode reboot behavior. Root interference and stalled services
are not covered by a hard always-on network/lease guard.

Earlier [baseline DHCP receipts](../dhcp/README.md) remain historical. Their expiry
case did not start with active forwarding; it cannot establish the corrected
active-route expiry behavior. The failed review attempt is retained in review.json:
its stricter test correctly failed on an error-wrapper mismatch, not a runtime
session-fencing failure. No private logs, fixture credentials or VM images are published.

```sh
.venv/bin/python -m tools.dhcp_report reviews/dhcp-audit
```
