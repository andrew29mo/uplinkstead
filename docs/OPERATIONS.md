# MVP operations and deployment contract

## Scope and prerequisites

Linux, Python 3.12+, systemd and iproute2. The operator reserves tables 41001–41003,
marks 0x5101/0x5102 and the documented RPDB priorities for one routed IPv4 LAN.
Provision static addresses, gateway reachability, forwarding, compatible reverse
path filtering, NAT or explicit return routes, and the existing main routes first.
The service does not create those external prerequisites or edit firewall tools.

Each configured probe endpoint must accept a new verified TLS connection and a
`GET /<nonce>` HTTP/1.0 request, returning HTTP/1.0 200 with a JSON object containing
`ok: true` and the matching `nonce`. Optional `peer` must be null or a string of at most 64 UTF-8 bytes.
An oversized peer is one failed target, so it cannot inflate a complete sample
past event/RPC capacity and suppress the other two targets.
This is a controlled reachability protocol, not an arbitrary HTTPS website check.
The three endpoints should reflect the deployment's failure domains. The VM uses
three ports on one server and does not establish independent ISP availability.

Install the Python package into the Python 3.12+ environment used by both unit
`ExecStart` paths. Install `deploy/uplinkstead.conf` with systemd-sysusers, create
root-owned `/var/lib/uplinkstead` mode 0700, and put a root-owned config at
`/etc/uplinkstead/config.json` with a trusted CA. Install both service units and
run systemd daemon-reload. Keep package code, units, config and CA unavailable for
writing by the policy user. Do not give the policy user journal access or sudo.
Use the same chosen Python environment in both units if adapting executable paths.
The supplied configuration example uses documentation-only addresses and is not
ready for a real network without operator changes.

The VM qualification installs the two actual units, adapting only source/config/
state/namespace paths and fixture dependencies. It does not qualify a distribution
package manager, arbitrary OS image or an automatic host installer.

## Privilege boundary

`uplinkstead.service` is the single root writer with CAP_NET_ADMIN/CAP_NET_RAW,
a private journal and an inherited mutation lock. `uplinkstead-policy.service`
runs as a dedicated `uplinkstead` account with no capabilities and AF_UNIX only.
It proposes selections through a bounded local SOCK_SEQPACKET interface. The root
writer independently probes and checks health, budget, round and operation token;
it never accepts a client-supplied route, shell command, config path or proof.
Keeping probing and admission validation in the privileged service prevents a
compromised policy client from fabricating healthy observations. This makes the
writer more than a minimal syscall shim; it is explicitly trusted code.

The socket directory is root-owned and not writable by peers. SO_PEERCRED allows
only root or the configured policy UID. Only root can perform operator changes.
The policy account can request bounded sampling and propose automatic decisions,
not pause/resume or change routing ownership. It can still deny useful service by
stopping proposals or exhausting its permitted local API; there is no HA boundary.
CAP_NET_ADMIN remains broad namespace authority, not a kernel table allowlist.

## States and operator workflow

First service start creates a **DISABLED** journal and leaves routing detached.
The policy worker can run but cannot collect probes until an explicit enable.
Starting/stopping systemd is separate from attaching/detaching network ownership.

Every changing command needs `--epoch` and `--revision` copied from a prior
`uplinkstead status`. Refresh and inspect status after a stale-token rejection;
the CLI never retries a change using a silently refreshed token.

```sh
sudo uplinkstead status
sudo uplinkstead enable --epoch E --revision R --ack attach-owned-routing
# enable installs guards/probe layout and enters PAUSED; unselected LAN traffic
# is intentionally rejected until a healthy selection is authorized.
sudo uplinkstead status
sudo uplinkstead resume --epoch E --revision R --target A --ack reset-budget
sudo uplinkstead pause --epoch E --revision R
sudo uplinkstead select --epoch E --revision R --target B
sudo uplinkstead disable --epoch E --revision R --ack restore-main-routing
```

`E` and `R` are illustrative placeholders, not literal arguments. Inspect current
status before each command. `resume` requires newly collected consecutive healthy
observations for its explicit target and records a deliberate budget reset. It can
clear a latch but cannot authorize an UNKNOWN/unhealthy/expired destination.
`select` also requires PAUSED and fresh writer-observed health, and respects the
remaining time-window budget; a persistent latch still requires guarded resume.
Resume rechecks health after budget persistence, immediately before deciding to
enable automation even when the selected route is unchanged. This is a decision-
time freshness check, not a guarantee that evidence is still fresh when the reply
arrives. Stale process epochs and same-process revisions are rejected.

PAUSED retains selection, probes and owned-route maintenance, while preventing
automatic selection. It does not freeze every kernel write. DISABLED removes only
validated owned rules/tables and returns traffic to the preexisting main policy.
This handoff is not guaranteed to preserve connectivity: the operator must qualify
main routing and explicitly acknowledge it. Foreign objects block the operation.
A durable lifecycle intent precedes enable/disable; partial work is completed by
the next exclusive writer, without assuming that process death canceled a helper.

Stopping both services retains their last routing layout/selection; a selected
WAN can then fail without automatic repair. Disable explicitly before stopping if
main-routing handoff is intended. Restart retains mode/latch, reconciles pending
writes and rebuilds health from UNKNOWN. On reboot, namespaces/routes may disappear;
restoration follows recorded ownership and intent. No boot-zero-gap is promised.

If a write has an unknown outcome or persistent storage fails, the writer exits;
a successor must acquire the inherited lock and reconcile. systemd uses bounded
restart attempts. Inspect the failure, repair the deployment/storage condition and
then use systemd reset-failed/start; restart alone is not a storage repair API.
Never edit SQLite to resume automation or delete a live writer lock inode.

## Capacity and storage

- Exactly two links and three target endpoints; at most eight LAN exclusions.
- Config at most 64 KiB; policy budget at most 32, streak counts at most 100.
- Request at most 4 KiB, reply at most 32 KiB, socket backlog 16 and idle peer
  receive timeout two seconds. Probe sampling at most once per 0.8 seconds.
- At most 128 retained events, each at most 32 KiB; budget history at most 64.
  Admission prunes expired budget history; it does not grant cross-boot credit.
- SQLite main file at most 2048 4-KiB pages (8 MiB). DELETE rollback journal can
  temporarily consume additional space up to roughly another main-file size.
  A 2-MiB free-space reserve rejects new saves; it is not an OS disk quota or a
  guarantee against concurrent writers exhausting the volume. Provision at least
  32 MiB dedicated state capacity and an actual filesystem quota if required.
- Service stdout is quiet; events live in the bounded DB. Configure journald's
  host retention separately; this service does not cap system-wide logs or VM RSS.

The bounded local event stream is operational history, not tamper-proof audit.
Root compromise is outside the authentication boundary. The journal can refuse a
corrupt/oversized state; no general corruption repair or sudden-power-loss result
has been established.
