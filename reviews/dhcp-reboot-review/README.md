# Reviewed DHCP VM restart evidence

Run `2d40cc540f51c289`, source fingerprint
`472aaede93793df9b014c22eba67653bdabe050ad4f901087c6ac7ecde46ba4d`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Review/failed trials](review.json)
· [Findings and fixes](../../docs/DHCP_REBOOT_REVIEW.md)
· [Reproduction and boundaries](../../docs/DHCP_REBOOT.md)

**113 portable tests per platform**, identical source and test IDs, zero skips.
All **nine lifecycle scenarios** and the **actual DHCP-mode orderly VM restart**
passed. **47 corrupted evidence variants** reject. Both normal and optimized
report verification pass. These are verifier controls, not 47 network experiments.

## Evidence chain

- The real wire lease (`192.0.2.3`) was healthy/forwarding before the service was
  frozen. A recorded runtime-only SIGKILL shutdown override retained the live
  journal. A different boot read the exact unchanged lease/session/deadline before
  production ExecStart. That excludes pre-shutdown graceful deconfiguration as
  the explanation; it does not simulate a disk losing power.
- The installed transformed shipped unit started automatically without the fault
  drop-in. Before launching BusyBox, the **formal service** checked cleared state
  and actual backend rules/addresses/routes, then emitted `dhcp_startup_ready`.
  Its journald PID/boot/invocation match the service. Initial revision was 29,
  exactly one after the retained journal's 28, before any client callback.
  Its recorded boot-time was 2.629512334 s; this is an observation point, not the
  beginning of protection or a boot-time/recovery upper bound.
- With no DHCP server running, three later observations required no old lease,
  expiry or healthy state, no owned address/probe/data routes, and exactly the
  six owned rules plus three builtins. Unknown/duplicate rules cannot pass.
  New LAN TLS attempts failed without counted packets on the viable backup.
- The backup positive control's full TCP tuple was read from the real socket:
  `198.51.100.2:50722 -> 203.0.113.2:8443`. Only that tuple is exempted from the
  subsequent counter, so its delayed teardown cannot pollute measurements. Actual
  nftables hook, all match conditions, return and counter rules are retained and
  verified. All other target flows remain counted, including LAN `10.77.0.2`
  and DHCP-source probes. No broad source/port exemption is accepted.
- A different real wire lease (`192.0.2.4`) remained unverified while the probe
  path was blackholed. After removing that hole, fresh quorum allowed LAN TLS
  through the intended WAN (`10.99.1.1` peer observation).
- Separate old-session, old-boot and old-revision requests used legal allocation
  options and otherwise current authority. Dispatch/completion times were fresh
  and after the last journal event (12.984368005 s), so bad time/order cannot
  explain the expected rejections. Status and independent network readback stayed
  unchanged; the proposed old address was not installed.

## Measurements and cleanup

The guest post-start verification routine took **9.98 s**. It includes intentional
waiting, negative requests and wire reacquisition, excludes VM stop/start and is
not downtime, a recovery bound or a performance improvement over prior trials.
Host driver stages retain their own durations.

Writer RSS snapshots: lifecycle **23,916 KiB**, post-restart **23,720 KiB**.
The latter has matching active service identity immediately before and after the
read. These are separate-instance snapshots, not peaks or a memory-saving result;
client, kernel and VM overhead are excluded. Lifecycle SQLite main file:
**8,192 bytes**, excluding temporary journal/log/filesystem overhead.

Fixture preflight refuses existing identical objects. Only actual exclusive
creations enter the owner/device/inode ledger; tested partial writes and a racing
link creator do not authorize deleting foreign objects. This is not persistent
cleanup recovery under failed ledger storage or sudden power loss.

Owned units, dependency/enablement links, directories, namespaces and source
snapshot were removed; the VM root network was preserved and the VM stopped.
Private logs, generated credentials, databases and VM images remain local.

## Limits and retained failures

This is an orderly VM stop/start with explicit forced process termination during
shutdown. Sudden power loss, torn writes, disk corruption, continuous protection
before service startup, physical ISP behavior and natural long-running T1/T2
renewal remain untested. DHCP is still a separate single-uplink mode, not dynamic
A/B failover. No hard expiry, uninterrupted connection, capacity or production SLO
is established. Portable tests on macOS are not execution of the Linux service.

Both review development failures remain failed in review.json. One saw a nonzero
shared counter after the positive control, without a flow trace identifying the
cause; it proves neither a LAN leak nor a confirmed warmup teardown. The next
completed all VM phases but failed verifier expression-order expectations. The
current receipt comes from a new full run after correcting the exact order.
[The original reboot receipt](../dhcp-reboot/README.md) remains historical and does
not retroactively establish the added startup/timestamp/rule/cleanup checks.
Older static VM receipts were not rerun at this manifest.

```sh
.venv/bin/python -m tools.dhcp_report reviews/dhcp-reboot-review
.venv/bin/python -O -m tools.dhcp_report reviews/dhcp-reboot-review
```

Replay at the source revision containing this exact manifest; later code/test
changes intentionally invalidate the current-source correspondence check.
