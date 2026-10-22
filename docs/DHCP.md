# Single DHCP uplink lifecycle

This is a separate, opt-in IPv4 mode. It does **not** add DHCP to the static
A/B failover controller. Run neither controller on resources owned by the other.
One dedicated DHCP interface, one declared LAN, three configured TLS endpoints,
one root writer and a supervised BusyBox `udhcpc` client are supported. No PPPoE,
DHCPv6, multiple routers, DHCP classless routes, DNS changes or lease-cache reuse.

## Lifecycle and safety boundary

`WAITING -> LEASED/UNVERIFIED -> HEALTHY`, with every bound/renew event returning
to UNVERIFIED. A lease loss, expiry, failed quorum or infrastructure uncertainty
withdraws the owned LAN default. Renewal is deliberately conservative and may
interrupt traffic even when the address is unchanged. Two fresh rounds with at
least two successful TLS targets are required before attaching LAN forwarding.
A successful probe says only that the configured endpoints were reachable.

The service runs the exact hook in `deploy/uplinkstead-udhcpc.py`. The client passes
its fixed writer session and boot identity to that hook. A root-only local
SOCK_SEQPACKET API checks session, boot, monotonic event time and revision. Old,
reordered, duplicate or delayed events reject; hooks are synchronous, and rejected
updates are not silently retried with newer authority. The hook receives only
IPv4 address, mask, one on-link gateway and bounded lease duration. It never runs
DHCP values through a shell or accepts arbitrary route commands.

Every mutation saves a FULL-synchronous SQLite intent before executing commands.
The writer's exclusive lock is inherited by command helpers. Recovery quarantines
both old and intended addresses/routes rather than replaying a pre-restart lease.
Every service start creates a new session and requires a fresh DHCP exchange and
fresh health. An incomplete write retires the service; it cannot keep serving as
though the change succeeded. Corrupt state rejects rather than claiming repair.

Probe traffic binds source, interface and mark. Reserved tables 41101/41103 and
priorities 10206/10207/10210–10213 provide terminal prohibitions after lookup
misses. A missing route cannot fall through to the main default. The service
changes only its validated objects and DHCP address, uses `noprefixroute`, and
refuses foreign addresses, intersecting RPDB rules or unknown reserved routes.
It does not reconcile other network managers. Ownership/cooperation is required.
Only the declared LAN prefix is excluded from WAN forwarding; configure no other
internal routed networks in this first slice.

## Installation prerequisites

Linux, Python 3.12+, iproute2, systemd and BusyBox with `udhcpc` are required.
The service is root with CAP_NET_ADMIN/CAP_NET_RAW/CAP_NET_BIND_SERVICE; this is not a new privilege
separation boundary. Do not allow NetworkManager, networkd or another DHCP client
to own the same interface. Provision link-up, LAN address, forwarding, suitable
reverse-path filtering, NAT/return routing, TLS CA and endpoint service separately.
The example uses documentation addresses and cannot be deployed unchanged.

Install the Python package, copy `deploy/uplinkstead-udhcpc.py` to
`/usr/libexec/uplinkstead-udhcpc.py` (root-owned, executable), copy and edit
`deploy/dhcp.example.json` as `/etc/uplinkstead/dhcp.json`, and install
`deploy/uplinkstead-dhcp.service`. Store the configuration and CA in a root-owned
location. Inspect the service before enabling it. State/socket directories are
private; the journal has an 8-MiB main-file limit and a 2-MiB free-space guard.
These do not cap the filesystem, temporary journal or whole process memory.

Stopping the service normally withdraws the lease/address and keeps prohibition
rules. It intentionally does not hand the LAN to another default. Full removal
requires an operator to validate and remove the exact owned rules/tables after
stopping the service; no automatic takeover by a second manager is implemented.

Lease deadlines use boot-time monotonic time measured when the hook starts;
this is not a packet-level ACK timestamp. Expiry handling requires a scheduled,
working service. SIGKILL can leave routes until systemd starts the replacement;
a stopped/stuck service or exhausted restart limit does not enforce a hard kernel
lease deadline. Do not interpret this feature as an always-on network guard.

## Reproduce and evidence

Use a dedicated **stopped** Colima `relay` profile with busybox-static, dnsmasq,
iproute2, nftables, OpenSSL and systemd preinstalled in the guest:

```sh
.venv/bin/python -m tools.dhcp_validate \
  --colima-home /path/to/dedicated-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/dhcp-fresh
.venv/bin/python -m tools.dhcp_report results/dhcp-fresh
```

The driver uploads a manifest-listed source snapshot, runs identical portable
tests on macOS and Linux, transforms the shipped systemd unit only for fixture
paths/environment/namespace and explicitly created private directories, and runs
real dnsmasq/udhcpc exchanges. Renewal and gateway updates are triggered with
SIGUSR1; address replacement uses release/reacquisition. This validates real
exchanges through the formal hook, not long-running natural T1/T2 renewal behavior.
A viable backup default is deliberately present.
Blackhole and expiry cases must fail without packets on that backup. The expiry
case also stalls the client, forcing the service to enforce the real wire-acquired
lease deadline without relying on an earlier client deconfiguration callback. Controlled
core tests separately inject write failures; those are not physical disk failures.
The VM also injects an exception after a real backend command successfully changes
the address/probe route, then opens the formal lifecycle again to prove both old
and intended allocations are quarantined. This is a command-boundary fault, not
a physical I/O failure. A service SIGKILL is not a VM reboot or sudden power loss.

JSON and escaped HTML retain all cases, writer-process RSS snapshot (excluding the separate client), main-file bytes,
stage exits/timeouts, source identities and cleanup. Case times include setup,
protocol timers and polling; they are not recovery-time bounds or performance
comparisons. No forwarding throughput, peak RSS or physical ISP result is claimed.
Failed runs remain failed. Cleanup must remove owned units/namespaces/source,
preserve the VM root network and stop the VM. Private fixture keys/logs stay local.

Retained results: [DHCP JSON/HTML and measured scope](../reviews/dhcp/README.md),
plus [same-source static regression](../reviews/dhcp-static-regression/README.md).
