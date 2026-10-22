# Uplinkstead

A local Linux IPv4 dual-uplink failover service for one declared routed LAN.
It detects configured-target failures beyond the gateway, selects a healthy static
uplink, reconciles durable intent after crashes and limits repeated switching.
The kernel forwards traffic; Python handles control decisions and operations.

The first MVP adds a separate unprivileged policy worker, a narrow privileged
writer interface, local root operator controls, recoverable enable/disable and
bounded state storage. It is **not a general-purpose router or a production
qualification**. The repository is **Public**.

Licensed under the [MIT License](LICENSE), copyright 2026 Andrew Yuan.
Separately installed system tools and build dependencies retain their own licenses;
see [third-party scope](docs/THIRD_PARTY.md).

## What it does

- Device/source/mark-pinned fresh TLS probes, 2/3 quorum and consecutive health
  observations; no proxy, redirect, DNS fallback or borrowing the other WAN.
- One LAN-scoped active routing table, independent probe tables, terminal lookup
  guards and declared internal-prefix exclusions; no main-route or firewall takeover.
- Exclusive mutation lock inherited by helpers, durable intent, operation tokens
  and actual route readback; SQLite and the kernel are not one atomic transaction.
- A capability-free policy process proposes decisions over a bounded local socket.
  The privileged writer owns probe observations and independently rechecks health,
  budget, freshness and tokens. No caller-supplied route, command or proof is accepted.
- Local status plus root-only pause, healthy target selection, explicit budget reset/resume,
  and durable network enable/disable. Fresh start is detached; enable enters PAUSED.
- Persistent switching latch, bounded event/history/config/protocol sizes and an
  8-MiB SQLite main-file cap, with explicit temporary-journal and disk-space limits.

[Architecture](docs/ARCHITECTURE.md) · [Operations](docs/OPERATIONS.md)
· [MVP acceptance](docs/MVP_ACCEPTANCE.md) · [Validation](docs/VALIDATION.md)
· [Public release checks](docs/PUBLICATION.md) · [Publication review](docs/RELEASE_REVIEW.md) · [MVP review](docs/MVP_REVIEW.md) · [Earlier review](docs/AUDIT.md) · [Research](docs/RESEARCH.md)

## Experimental single DHCP uplink

An independent [DHCP lifecycle mode](docs/DHCP.md) adds supervised lease acquisition,
renewal, expiry, address/gateway changes and fresh-session recovery. Every update
invalidates health and requires fresh pinned TLS quorum before forwarding. It is
not integrated into the static dual-uplink controller. See the
[DHCP lifecycle and VM restart evidence](reviews/dhcp-reboot/README.md).
The restart check retains a live lease across an orderly VM stop/start using an
explicit shutdown-only process fault, then requires new DHCP acquisition and
fresh health. It does not establish sudden power-loss recovery or protection
before service startup. Earlier [DHCP audit](reviews/dhcp-audit/README.md) and
[static regression](reviews/dhcp-audit-static/README.md) remain historical.

## Reproduce

Python 3.12+ is required. Runtime uses the standard library and separately installed
Linux iproute2/systemd. The optional DHCP mode additionally requires BusyBox udhcpc.
The isolated fixtures use nftables/OpenSSL and, for DHCP, dnsmasq.
Do not run the fixture on a production machine.

```sh
python3.12 -m venv .venv
.venv/bin/python -m unittest discover -v
.venv/bin/python -m tools.validate \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-run
.venv/bin/python -m tools.report results/fresh-run
```

The runner locks a dedicated stopped Colima `relay` profile, uploads a manifest-listed
source snapshot, tests actual installed services in disposable namespaces, performs
orderly VM stop/start and verifies owned cleanup. Nonzero exit, timeout, source
changes, missing evidence or a still-running VM cannot pass. JSON/HTML retain all
benchmark requests; raw private logs and fixture credentials remain excluded.

For deployment prerequisites, state semantics and token-based commands, read
[Operations](docs/OPERATIONS.md). Stopping a service retains routes; disabling
network ownership explicitly hands traffic back to the existing main policy.
Those actions have different effects.

## Limits

The dual-uplink controller supports one routed LAN and two independent static IPv4
subnets. DHCP is available only in the separate single-uplink mode. No IPv6 or PPPoE,
bridge/VRF, ECMP, connection migration, HA, general firewall reconciliation or remote
operator API. NAT/return paths, forwarding and reverse-path settings are deployment
prerequisites. Other privileged managers must cooperate with reserved resources.

The writer retains CAP_NET_ADMIN/CAP_NET_RAW and trusted probe/admission code;
privilege separation does not confine a compromised root writer to specific tables.
Unknown write outcomes require exclusive reconciliation. A latch can intentionally
prevent another failover. Root-triggered resume requires fresh observations and an
explicit recorded budget reset. Storage failure is rejected, not automatically repaired.

Measurements come from controlled Linux namespaces sharing one VM kernel. macOS
runs portable tests only. Process RSS snapshots exclude whole-VM overhead. The short
fixed-primary/automatic trial compares identical intended arrival offsets, includes
failures and scheduling lateness, and establishes no speedup, capacity or recovery SLO.
Physical uplinks, sudden power loss, storage-corruption repair and boot-zero-gap
protection remain untested. Existing NAT mappings/flows may break after switching.
