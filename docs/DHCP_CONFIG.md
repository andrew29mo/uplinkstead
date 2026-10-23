# Current dual-DHCP configuration

This is the installed automatic dual-DHCP mode. Static and single-DHCP configs
are not interchangeable. Supply root-controlled JSON to the
[clean installation recipe](DHCP_INSTALL.md); supply its CA separately at the
referenced readable root-controlled path. All addresses/targets below are
examples to replace, not functioning public probe services.

```json
{
  "links": {"A": {"interface": "wanA"}, "B": {"interface": "wanB"}},
  "lan": {"interface": "lan0", "prefix": "10.77.0.0/24"},
  "targets": [
    {"ip": "203.0.113.2", "port": 8443},
    {"ip": "203.0.113.2", "port": 8444},
    {"ip": "203.0.113.2", "port": 8445}
  ],
  "ca": "/etc/uplinkstead/probe-ca.crt",
  "server_name": "probe.test",
  "success_rounds": 2,
  "failure_rounds": 3,
  "freshness": 5,
  "budget": 32,
  "window": 3600,
  "storage": {"max_pages": 2048},
  "runtime": {
    "queue_capacity": 8,
    "probe_interval": 0.3,
    "restart_delay": 0.3,
    "client_diagnostics": false,
    "automatic_selection": true,
    "selection_hold": 0.3,
    "failover_delay": 0.8
  }
}
```

These accelerated timing values match the closure fixture, not a recommended
production policy. Choose explicit timing/budget for actual failure tolerance.
There must be exactly two distinct dedicated WANs and a separate LAN interface,
three distinct (IPv4, TCP port) TLS targets, a trusted CA and matching server name.
The controlled fixture uses one server at three ports; that is not independent
failure-domain coverage. Three real endpoints still only measure their declared
paths, not universal Internet availability.

The backend reserves WAN tables 41201/41202 and LAN table 41203 plus its explicit
RPDB/mark guards. Inspect the [backend ownership contract](DUAL_DHCP.md) before
using it with another network manager. Dedicated WANs must not carry unrelated
interface-bound main routes: removing their last DHCP address can remove such
routes as a Linux kernel side effect. The service does not reconstruct another
tool's routes. Forwarding, rp_filter, NAT/return paths and initial interface
readiness must be supplied by the deployment.

The installed qualified client owns lease acquisition/absolute timer behavior;
operators do not submit arbitrary leases as trusted health. A changed or renewed
lease invalidates its own proof and needs new pinned quorum. Pause/latch retain
safety withdrawal. Budget history is durable, including conservative old-boot
entries; recovery may require an explicit acknowledged reset while paused.

The closure report retains the **actual generated configuration indirectly via
its service state/config hash and source-bound recipe**; the private configuration,
CA/key and runtime journal are not uploaded. It does not qualify arbitrary timing
combinations, target topologies, DHCP options or servers.
