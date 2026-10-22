# Historical single DHCP uplink validation

Run `29d384d681407367`, source fingerprint
`b4bc56ad24c52e3f9d02ec3f0e223f40df54c3d3c5d09930d5fbaf9195b0ad2f`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Failed/superseded development attempts](attempts.json)
· [Deployment and limits](../../docs/DHCP.md)

- 96 portable tests per platform, same source manifest and test IDs; no skips.
- Eight isolated Linux namespace scenarios: seven installed-service/wire or
  runtime scenarios, plus one direct formal-core/backend command-boundary fault.
- Actual dnsmasq/BusyBox exchanges for acquisition, renewal, gateway and address
  changes (SIGUSR1 renewal; release/reacquisition for address replacement). Natural
  long-running T1/T2 scheduling is not separately qualified. Service invocation
  remains unchanged until the explicit SIGKILL.
- systemd replaces the killed writer; an old session with fresh timestamp/revision
  is rejected. The replacement acquires a new lease and fresh health.
- A viable main-route backup exists. After the DHCP path is blackholed, health
  becomes false, LAN TLS fails and backup observation counters remain zero.
- The real 120-second wire-acquired lease reaches its monotonic deadline while
  both server and client are stalled. The writer clears the lease/address and
  owned forwarding; LAN TLS still fails with zero backup packets.
- An exception injected **after** a successful real backend write preserves
  old/new intent; reopening the formal lifecycle removes both known allocations
  and waits for a new lease. This is not a physical disk failure.
- Twelve corrupted evidence variants are rejected; the JSON/HTML verifier also
  passes under Python optimization. Cleanup preserves the VM root network, removes
  owned namespace/unit/source objects and leaves the dedicated VM stopped.

Writer VmRSS snapshot: **23,816 KiB**; SQLite main file: **8,192 bytes**.
The client, kernel, temporary journal and VM are excluded from those measurements.
Case durations include fixture operations, DHCP timers and observation polling;
they are neither failover bounds nor throughput comparisons. This is a single
controlled VM run, not independent ISP or production qualification.

Environment: Colima VZ ARM64, Linux 6.8.0-117-generic, Python 3.12.3, systemd 255,
BusyBox 1.36.1 (Ubuntu package 1:1.36.1-6ubuntu3.1), dnsmasq 2.90.

This DHCP mode's **service restart** was tested; its changed-boot behavior is a
portable injected-identity test. No DHCP VM reboot, sudden power loss, physical
WAN, PPPoE, DHCPv6 or integrated dynamic A/B failover is claimed. Restart always
quarantines saved leases; it does not preserve existing TCP connections. An
unscheduled or stopped service cannot enforce a hard kernel lease deadline.

Earlier attempts remain failed, including source changes during exploratory runs.
Private credentials, raw logs, VM images and compiled archives are not published.

This baseline belongs to commit `da9f29034864d96f5e53beff4750df37c23ddc69`;
use that original source/verifier to replay it. The [corrected review](../dhcp-audit/README.md)
is current. In particular, the expiry case here followed an already-withdrawn
blackhole path and does not prove active forwarding is removed at expiry.
