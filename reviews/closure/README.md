# Dual-DHCP MVP closure: clean install and bounded integration

Run `3c391f8967fca724`, frozen source
`d090d3daf8c5ad2c9e73718fd496941547587d0c19012b6e09ab25e0314dfc39`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [All attempts](attempts.json) ·
[Negative preflight](preflight-refusal.json) · [Prior-disk cleanup](prior-data-cleanup.json)

Both platforms passed **292 tests**, identical test IDs/source, no skips. All
**16 mutated-evidence controls** rejected. Normal and optimized Python report
verification and exact JSON/HTML correspondence were rechecked. This is a new
installed-wheel gate, not a relabelling of historical VM receipts.

## Installed production path

The runner created a new Ubuntu 24.04 aarch64 Colima VM (2 CPUs, 3 GiB), no host
mounts or prior product package/account/state. It executed the installation shell
block in [the public guide](../../docs/DHCP_INSTALL.md) verbatim, with controlled
inputs and recorded doc/recipe/wheel hashes. All installed Python module hashes
match the release snapshot. The checkout product package was moved out of import
reach before starting services; the installed package is in system site-packages.

The shipped systemd units, worker, hook and externally built qualified client
match recorded hashes. Only namespace isolation is added; there is no PYTHONPATH,
ExecStart replacement or fixture boot timer. Actual root writer capabilities and
NoNewPrivileges, capability-free worker credentials, Type=notify and actual
process instances were inspected. The fixture supplies DHCP/TLS servers, network
prerequisites and faults, never product recovery or route selection.

## Actual workload and operations

Six complete active-uplink blackholes caused six automatic cross-uplink choices,
with successful fresh LAN TLS over the expected alternate path. Removing each
fault did not preempt the healthy selected path. Initial selection plus six
switches left seven budget charges; intervening natural renewals added none.
From the post-baseline snapshot to the final soak snapshot, A/B event sequences
advanced by **27/34**, with no client restarts or renewal signals.
The same four long-lived process identities were required throughout sampling.

The actual documented CLI exercised status, pause, acknowledged reset, stale
revision refusal, resume and stale epoch refusal after formal stop/start. Stop
quarantined allocations, terminated the old four processes and emptied both
service cgroups. LAN traffic then failed while a separate viable main-path TLS
witness succeeded, challenging borrowing. New start required a higher epoch,
new client sessions, leases and health before fresh traffic. Main/RPDB readbacks
and root-network semantic cleanup checks passed; wrong-WAN DHCP counters stayed zero.

## Resource observations

**267 samples over 538.250 seconds** (about nine minutes), roughly
two seconds apart; 257 are comparable stable samples. The five-minute
tail is separately checked. RSS is KiB per Linux VM process; extrema below are
sampled values over **all** phases, not continuously measured peaks.

| Process | All sampled RSS range | Stable first → last third median | Stable delta | Tail median delta |
|---|---:|---:|---:|---:|
| writer | 24828–27276 | 26004 → 27196 | +1192 | +160 |
| worker | 11872–11880 | 11880 → 11880 | +0 | +0 |
| clientA | 1616–1624 | 1620 → 1624 | +4 | +0 |
| clientB | 1604–1620 | 1612 → 1616 | +4 | +0 |

FD/thread tail median deltas were zero for all four processes. The writer's
thread median was 13: main/capture/intake/control plus two outer and six target
workers. Service cgroup counts ranged 4–7 including transient helpers.
Product state-file lengths were 8192 bytes initially and 8192 finally,
with a sampled maximum of 16912 bytes including temporary journal files.
These are logical file lengths, not filesystem allocation/whole-VM disk usage.
Queues/diagnostic rings stayed within declared bounds; no sampler errors occurred.

**RSS did grow**, especially during the earlier portion; it is not a zero-growth
claim. Tail writer growth of 160 KiB fits the predeclared 256 KiB gate,
with other processes within 64 KiB. Global and tail thresholds, slopes, sampling
phases and exclusions are in [reproduction/scope](../../docs/DHCP_CLOSURE.md).
This short controlled series cannot prove long-term leak freedom. CPU utilization,
whole-VM overhead, fixture/server logs and systemd journal are not measured here.
No throughput improvement, outage SLO or recovery upper bound is claimed. The raw
cycle `selected_at` field is a post-settlement driver completion checkpoint,
not a kernel switch timestamp; it must not be used as failover latency.

## Corrections, failed attempts and cleanup

Five failed/interrupted attempts remain unsuccessful in the ledger. They include
a pre-install quote error, deliberate preparation interruption, an invalid
median-plus-two **peak** assumption, actual 64-transaction client-history retirement,
and a resource-observer race reading a short-lived helper without VmRSS. The exact
PID of the latter was not retained. Diagnostic samples from a failed run are not
promoted into qualification. An earlier full pass remains historical under its
original cleanup gate; the final run above repeats after data-disk hardening.

The production resource change is a bounded service-lifetime six-target executor;
it preserves fresh bound TLS sockets/nonce/authentication. The final T1 values
are A 20/B 15 seconds (120-second leases); earlier faster workloads remain visible.
Both scheduling and cadence changed, so this is **not** a controlled causal
before/after RSS comparison. The 64-entry history capacity was not enlarged or
silently evicted. Long-term rollover and its traffic/budget effects remain unqualified.

Owned namespaces/processes were cleaned, both units stopped, and the final VM
**and container-data disk** deleted with absence read back. Actual runner preflight
also rejected a retained same-name disk before VM creation and preserved its test
sentinel. Separate scoped cleanup removed earlier task-owned disks; the preexisting
relay profile stayed Stopped. Credentials, binaries, VM images, raw logs and runtime
journals are excluded from Git.

## Limits and stopping point

This closes the bounded dual-DHCP IPv4 MVP, not production qualification.
Sudden power loss, boot-zero-gap, arbitrary corruption repair, physical ISPs,
general DHCP interoperability, uninterrupted existing connections and long-term
capacity are untested here. The older [orderly reboot gate](../dhcp-boot/README.md)
retains its own source and 25-second fixture timer; this run does not requalify it.
No additional product features are needed for this stated closure scope.
