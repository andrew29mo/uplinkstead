# Dual-DHCP four technical explorations

Run `55936aa4724bd1de`, source fingerprint
`440e7f89ba76343924d068108cfb5116cb751e13b2d537b889cd0ff8fd99ba9d`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Failed development attempts](attempts.json)
· [Architecture and reproduction](../../docs/DUAL_DHCP.md)

## Observed evidence

- **151 tests each on macOS/Linux**, identical source manifest and test IDs,
  zero skips/failures/errors. These include 25 formal dual-core tests, five scoped
  backend tests and eight fixture ownership/event-isolation tests. Portable tests
  reuse actual SQLite and actual process locks; their injected network backends
  do not establish Linux routing behavior.
- **12 Linux VM namespace scenarios** call the formal `DualLifecycle` and Linux
  `Backend`. Two actual BusyBox clients obtain dnsmasq leases. Inactive B renewal
  and client replacement retain A's authority/selected path; new TLS LAN requests
  establish actual forwarding independently of route readback/probe results.
- Both blackhole directions and missing A probe routes reject borrowing. A fresh
  unmarked router TLS request establishes viable B/main fallback before the missing
  route challenge. Probe/LAN counter windows exclude that completed warmup by
  taking their baseline afterward, not by removing failed requests.
- Both clients naturally perform T1 unicast renewal with own-server counters
  increasing and wrong-WAN counters unchanged. This scenario took **59.281 s**;
  it includes waiting for client timers and is not a failover latency.
- A real overlapping A DHCP offer withdraws only the proposing link while B
  continues new TLS traffic. A separate synthetic conflict exercises the same
  admission path. A real option 121 is visible as `staticroutes` in the tested
  BusyBox hook and causes B withdrawal without invalidating A. No real-wire
  option 33/249 or natural T2 qualification is implied.
- SIGKILL/core restart quarantines both old allocations. Isolated retired-session
  challenges use otherwise current fields and preserve snapshot and actual owned
  network state. A successful real address replacement followed by injected
  `OSError` preserves old/new intent; the next writer removes both known sides
  and does not replay old health.
- A separate **actual orderly VM stop/start** changes boot identity. Before the
  new-boot core is invoked, the SQLite file hash still equals the live-two-lease
  pre-stop hash. The old core was SIGKILLed and never performed journal withdrawal
  during shutdown. New core entry yields no old allocations/selection before new
  clients; both reacquire real leases and new A LAN TLS succeeds. Session and boot
  fences are challenged separately for both links with other fields current.
- **23 receipt corruption controls** reject under normal and optimized Python.
  Retained HTML is exactly rendered from retained JSON. Owned namespace/process
  cleanup, root network semantic preservation, snapshot removal and stopped VM
  all passed. Earlier failed runs are not relabeled successful.

## Measurements and boundaries

One post-recovery formal driver `VmRSS` snapshot is **23,592 KiB**; SQLite main file
is **8,192 bytes**. This is not peak/PSS/process-tree or VM memory, and excludes
DHCP clients, servers, kernel, temporary journal and filesystem overhead. No
memory reduction, speedup, throughput capacity or recovery bound is claimed.
All scenario and host VM stage durations are separately retained in the JSON.

Colima/VZ Linux ARM64, kernel 6.8.0-117-generic, Python 3.12.3, BusyBox
1.36.1 distro build and dnsmasq 2.90. Five namespaces share one VM kernel; the
three probe ports share one TLS process. Upstream NAT and return routes are
explicit fixture setup, not product capabilities.

This is an exploration of formal core/backend mechanisms, **not an installed
dual-DHCP systemd service or automatic-failover qualification**. The fixture
serializes commands, captures real hook time/session/boot and assigns callback
revision during processing. It is not production IPC admission or supervision.
Natural T2, exact packet-based lease origin, bounded production queues, delayed
live network helper takeover and installed dual-service boot are still gates.
The real inherited-descriptor delayed-helper test uses a portable injected backend.
The core's hook-time lifetime approximation must not be called exact RFC expiry;
it can be later than the actual deadline after hook delay. These limits are
required design work before deployment, not capabilities proven by this receipt.

Sudden power loss, torn writes/storage corruption, boot-zero-gap protection,
physical uplinks/ISPs, transparent connection migration and production SLOs remain
untested. No fixture private keys, raw private logs, SQLite state, downloaded tools
or VM images are retained here.
