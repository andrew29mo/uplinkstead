# Uplinkstead

A local Linux IPv4 failover service for two dedicated uplinks and one routed LAN.
The opt-in **dual-DHCP MVP** acquires and renews independent leases, detects
configured-target failures beyond the gateway and switches new traffic to a
healthy uplink. The kernel forwards traffic; Python owns control and recovery.
Static dual-uplink and single-DHCP modes remain separate deployments. Never run
multiple writers on the same interfaces.

Licensed under [MIT](LICENSE). The qualified external BusyBox DHCP adapter is
built separately and retains its GPL obligations; see [third-party scope](docs/THIRD_PARTY.md).
The repository is Public. This is a bounded systems MVP, not production qualification.

## Current dual-DHCP capabilities

- Wire-admitted independent leases with absolute T1/T2/expiry handling. Renewal,
  changed address/gateway and loss invalidate health; new pinned TLS quorum is
  required before restoration. Device/source/mark-pinned probes cannot borrow
  the other WAN or main default.
- LAN-scoped policy routing, separate probe tables and terminal guards. The
  service does not take over main routes or other tools' firewall rules.
- Automatic healthy selection, candidate hold, withdrawal grace, sticky failover,
  bounded same-WAN restoration and persistent switching budget/latch. Normal
  renewal does not count as a cross-WAN switch; initial selection does count.
- A capability-free proposal worker and privileged authoritative writer. Writer
  independently validates lease/health, tokens, hold/grace, budget and lock state.
- Local status and root-only pause/resume/explicit budget reset. Pause differs from stop;
  resume cannot clear a latch. Epoch/revision and bounded receipts reject retired
  operator/client/worker authority.
- Shipped systemd units, bounded restart, production-core stop/crash quarantine,
  storage-failure retirement and orderly VM reboot recovery. New writer authority
  must reacquire leases/health; pause/latch/history survive.
- A bounded service-lifetime TLS target executor, bounded queues/protocol/history
  and an 8 MiB SQLite main-file cap. Failed
  persistence is not success; repair is explicit. SQLite and kernel updates are
  not one atomic transaction.

## Install and operate

Start with the [clean-install and operator guide](docs/DHCP_INSTALL.md),
[dual-DHCP configuration](docs/DHCP_CONFIG.md), [systemd lifecycle](docs/DHCP_SYSTEMD.md)
and [storage repair](docs/DHCP_STORAGE.md). Python 3.12+, systemd, iproute2, a
qualified BusyBox adapter, dedicated interfaces and external forwarding/NAT/return
paths are prerequisites. Automatic dual-DHCP is explicitly enabled in configuration.

The [static-mode operations guide](docs/OPERATIONS.md) describes a different
service: its enable/disable semantics must not be applied to dual-DHCP stop.
Dual-DHCP stop withdraws allocations while retaining no-borrowing guards.

## Evidence and reproduction

[Current acceptance criteria](docs/MVP_ACCEPTANCE.md) distinguish portable tests,
actual installed services and labelled fault injection. macOS runs portable tests;
Linux networking evidence comes from isolated namespaces sharing a VM kernel.

- [Automatic failover](reviews/dhcp-automatic-review/README.md): real clients and
  traffic, natural renewal, flap/latch and labelled ACK/write interleavings.
- [Privilege and operator boundary](reviews/dhcp-control/README.md),
  [systemd takeover](reviews/dhcp-systemd/README.md) and
  [storage faults](reviews/dhcp-storage/README.md): separate source-bound gates.
- [Orderly VM reboot recovery](reviews/dhcp-boot/README.md): 284 matching tests per
  platform, five reboot cases and 28 rejected evidence corruptions at its recorded
  source. The preserved-journal case reads unchanged old allocations before Agent
  start, excluding pre-shutdown cleanup. ENOSPC persists across reboot and repair.
- [Clean installation and bounded soak](reviews/closure/README.md): current closure
  receipt: 292 matching tests per platform, six fault/recovery cycles and 267
  samples over 538.25 seconds. Tail writer RSS median rose 160 KiB; the other
  three processes and FD/thread medians stayed flat. These fit explicit short-run
  limits, not a zero-growth or long-term no-leak guarantee. Documented commands
  and installed wheel provenance are retained.

Each receipt retains its own source and test count; a newer portable suite does
not mean every historical VM experiment was rerun on that source. See
[DHCP history](docs/DHCP_HISTORY.md) for the stage-by-stage evidence and the
[historical static architecture](docs/ARCHITECTURE.md) for the original mode.

Portable checks:

```sh
python3.12 -m venv .venv
.venv/bin/python -m unittest discover -v
```

The [closure reproduction guide](docs/DHCP_CLOSURE.md) describes fresh-VM setup.
Never run network fixtures on a production host. Nonzero exits, timeouts, changed
source, missing observations or failed cleanup cannot qualify. Raw logs, generated
credentials, images and binaries stay outside tracked release evidence.

## Limits

IPv4 only; no IPv6, PPPoE, bridge/VRF, ECMP, HA, connection migration, general
firewall reconciliation or remote operator API. The DHCP adapter is qualified
against controlled servers, not arbitrary DHCP implementations or physical ISPs.
Per-session packet history is capped at 64 transactions; reaching it can require
a new client session and fresh health. Long-term rollover/capacity longevity is
not qualified by the same-client resource control.
The trusted writer/client/capture path retains network capabilities; process
separation is not containment of a compromised root writer.

Unknown ownership or kernel failure can prevent withdrawal. A crashed writer may
leave kernel state until supervision/cleanup executes. A switching latch may
intentionally prevent another failover; storage failure needs explicit repair.
Existing NAT mappings/flows may break when uplinks change.

The reboot fixture uses a labelled **25-second startup timer** to avoid Colima
provisioning interference. It is not product early-network gating or a recovery
bound. Sudden power loss, arbitrary storage-corruption repair and boot-zero-gap
remain untested. Controlled timings and VM RSS snapshots establish no physical-WAN
SLO, throughput advantage or whole-host memory claim. A short resource series
cannot establish long-term leak freedom.
