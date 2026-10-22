# Uplinkstead

An exploratory Linux IPv4 dual-uplink failover service core. It selects a static
uplink for one declared routed LAN, detects configured-target failures beyond the
gateway, reconciles durable route intent after crashes, and bounds automatic
switching. This is **four technical explorations, not a completed general-purpose
router product or a production qualification**.

The repository is **Private**. No project license has been selected; no license
file or package license declaration is provided. External system tools retain
their original licenses.

## What is real

- `uplinkstead.policy`: the actual agent's health/freshness/quorum policy, default
  non-preemptive failover, optional stable failback and a persistent switching budget.
- `uplinkstead.probe`: fresh TLS connections bound to a configured source, device
  and mark; no HTTP proxy, redirect or implicit DNS fallback.
- `uplinkstead.linux`: real iproute2 mutations and readback; fixed per-uplink probe
  tables, an independent LAN active table, terminal RPDB guards and explicit
  internal-prefix exclusions. No host-wide default-route or conntrack flush.
- `uplinkstead.writer`: an exclusive writer lock inherited by mutation helpers,
  strict journal/config validation, generations and SQLite FULL-synchronous intent.
  Route writes and SQLite are **not** a shared atomic transaction.
- `uplinkstead.agent` and `deploy/uplinkstead.service`: the same core runs as a
  real systemd service in the disposable router namespace.

[Architecture](docs/ARCHITECTURE.md) · [MVP acceptance](docs/MVP_ACCEPTANCE.md)
· [Validation](docs/VALIDATION.md) · [Review corrections](docs/AUDIT.md) · [Research](docs/RESEARCH.md)

## Reproduce

Python 3.12+ is required. Runtime uses the standard library and separately
installed Linux iproute2; the fixture additionally requires systemd, nftables and
OpenSSL. Do not run the VM fixture on a production machine.

```sh
python3.12 -m venv .venv
.venv/bin/python -m unittest discover -v
.venv/bin/python -m tools.validate \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-run
.venv/bin/python -m tools.report results/fresh-run
```

The runner requires the dedicated Colima `relay` profile to be stopped and idle.
It locks the profile, uploads only a manifest-listed source snapshot, uses private
fixture credentials, performs actual orderly VM stop/start, checks owned cleanup,
removes the snapshot and stops the VM. Nonzero exits and timeouts cannot pass.
Private logs and credentials stay out of Git; only sanitized receipts are retained.

## Boundaries

One routed LAN and two independent static IPv4 uplink subnets; no bridge/VRF,
DHCP/PPPoE, IPv6, ECMP, connection migration or general firewall reconciliation.
Forwarding, NAT/return paths, reserved marks and compatible reverse-path filtering
are explicit deployment prerequisites. The service does not repair external rules.
Unknown or inverted RPDB selectors and missing/duplicate built-in lookup rules
block mutation. Automatic selection rechecks boot/config-bound health evidence
before dispatch; a helper deadline does not guarantee when the kernel completes.
Other privileged network managers must cooperate with the resource reservation;
CAP_NET_ADMIN is broad namespace authority, not a kernel-enforced table allowlist.

Exit probes establish reachability to the configured targets, not all Internet or
LAN applications. Old NAT mappings and established flows may fail after switching.
Unknown outcomes stop further mutation. A budget latch can deliberately prevent
another automatic failover; restarting does not clear it.

The Linux data plane is tested inside network namespaces of one VM. macOS tests
cover portable logic, not a macOS routing backend. Orderly VM restart is not
sudden power loss. Physical uplinks, independent devices, storage corruption,
boot-zero-gap protection, HA and performance SLAs remain untested. The exploratory
service currently runs with bounded capabilities in its namespace; full privilege
separation, safe operator resume and distribution packaging remain MVP work.
