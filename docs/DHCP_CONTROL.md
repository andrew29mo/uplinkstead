# Dual-DHCP policy/operator boundary

This is the first slice of milestone 2: a capability-free proposal process,
authoritative privileged writer and fenced root operator interface. It extends
foreground dual-DHCP mode. [Installed systemd/process-tree recovery](DHCP_SYSTEMD.md)
has a separate gate; reboot qualification and capacity rollover remain later work.

## Authority

The writer owns actual DHCP capture/admission, lease generations, health probes,
candidate hold/withdrawal grace, budget/latch, SQLite and Linux mutations. A separate
worker can read a minimal status and submit only:

```json
{"op":"propose","epoch":1,"revision":3,"target":"A","generation":2}
```

It cannot submit a command, route, gateway, health proof, client event, reset or
operator identity. Linux SO_PEERCRED must match the explicitly configured policy
UID; group membership alone is insufficient. The writer recomputes its candidate
at admission and independently checks the current token/generation, non-preemption,
hold/grace, fresh lease/health, pause/latch and budget. Capture/intake guards still
surround the actual network write. There is no trust in worker-supplied clocks.

When configured with a policy UID, the writer does not fall back to charged
inline automatic choices if the worker is absent. It still probes, expires leases
and withdraws unsafe routes. Deterministic bounded same-WAN new-lease restoration
remains inside the writer; it is not a worker-supplied privilege or budget reset.
Without the new CLI flags, the earlier foreground inline mode retains its contract.

The worker checks non-root UID, zero effective/permitted/inheritable/ambient
capabilities and NoNewPrivs. The VM launcher also drops the bounding set. This is
policy-process privilege separation, not a complete sandbox: DHCP client/capture
and the writer remain trusted privileged components. Generic unprivileged process
abilities are not removed by this code, and a compromised root writer is not
confined to declared routes.

## Endpoint and launch contract

Use a dedicated, non-root UID/GID and a root-owned non-writable control directory.
The control socket is root-owned, group-accessible 0660 in a 0750 directory. The
separate DHCP event socket and journal remain private to root. Control status
omits DHCP sessions/capture authority; it includes epoch/revision, lease generation,
health/availability, candidate, selected identity, budget/latch and operation receipts.
Status is a timestamped publication, not a promise that a later operation will pass.

A prepared host can launch the writer with its existing explicit timer client:

```sh
python3 -m uplinkstead.dual_dhcp_service \
  --config /etc/uplinkstead/dual-dhcp.json \
  --journal /var/lib/uplinkstead-dual \
  --socket /run/uplinkstead-dual-private/events.sock \
  --hook /usr/libexec/uplinkstead-dual-hook.py \
  --client /path/to/qualified/busybox \
  --policy-uid 1234 --policy-gid 1234 \
  --control-socket /run/uplinkstead-dual-control/control.sock
```

UID/GID 1234 are placeholders for the dedicated identity, not created by the
application. The automatic configuration still needs `automatic_selection: true`.
Install the exact `uplinkstead/dual_dhcp_worker.py` file root-owned/read-only at the
chosen worker path, outside private writer state. A root launcher can drop identity
and capabilities explicitly:

```sh
setpriv --reuid=1234 --regid=1234 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /usr/libexec/uplinkstead-dual-worker.py \
  --socket /run/uplinkstead-dual-control/control.sock
```

These describe foreground setup prerequisites, not an installed-service guarantee.
The VM tests use the exact hash-checked worker file under an owned temporary /run
directory and real numeric UID/GID 61001, without creating a host account.

## Root operations

```sh
python3 -m uplinkstead.dual_dhcp_cli --socket /run/uplinkstead-dual-control/control.sock status
python3 -m uplinkstead.dual_dhcp_cli --socket /run/uplinkstead-dual-control/control.sock pause
python3 -m uplinkstead.dual_dhcp_cli --socket /run/uplinkstead-dual-control/control.sock reset-budget --ack-reset-budget
python3 -m uplinkstead.dual_dhcp_cli --socket /run/uplinkstead-dual-control/control.sock resume
```

- **pause** persists pause and advances revision. It preserves an already safe
  route, but never stops health expiry, lease invalidation or safety withdrawal.
- **reset-budget** requires pause plus exact explicit acknowledgement. It clears
  only switch history/latch; it does not unpause, select, restart clients or clear
  the independent restoration/restart limits. It is rejected in RECOVERY_REQUIRED.
- **resume** requires pause, no latch and writer-owned fresh admitted lease/health.
  It does not reset budget and is not a forwarding-success response. Actual later
  choices still require writer-enforced hold/grace and a policy proposal. Health
  expiring during persistence, or changed intake during that operation, leaves it
  paused with a REPAUSED receipt; affected allocation is quarantined as necessary.

Every mutation carries original epoch/revision and a 32-hex operation ID. The CLI
fetches a snapshot once; explicit `--epoch/--revision/--id` retain those exact values.
It never refreshes/retries a failed mutation automatically. Lost replies and
`OutcomeUnknownInspectStatus` require status inspection; disconnect is not rollback.
A queued operation may complete after its caller times out.

The latest **32** operator receipts are stored in the same journal state as the
control change. Reuse of a retained ID rejects; old epoch/revision rejects even
when an old ID ages out. This is bounded local operational evidence, not unlimited
idempotency or external tamper-proof audit. Reopen preserves receipts, pause,
budget and latch; it does not preserve DHCP/health authority. Supported older
journal schemas receive an explicit additive empty receipt list; unknown fields
still reject. Journal write failure retires the writer instead of returning success.

Root commands have a separate four-entry queue; worker proposals have one reserved
slot and cannot consume operator slots. Socket waits and request sizes are bounded.
This is not qualification against arbitrary local peer floods or complete CPU DoS.
Durable operator/network changes, including entering budget latch, advance revision;
health samples alone do not, so live health/candidate validation remains mandatory.

## Validation

```sh
.venv/bin/python -m tools.dhcp_control_validate \
  --archive /path/to/busybox-1.36.1.tar.bz2 \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-control
```

Require actual worker UID/capabilities readback and hash, kernel denial of raw
sockets/route writes/private journal/event access, exact peer UID rejection despite
socket group membership, forged-proposal/admin rejection and actual root CLI
operations. Pause must continue safety withdrawal; a viable B/main TLS witness
must accompany blocked LAN traffic. With the worker absent, fresh B must not
receive an inline choice; restarting the worker must still respect budget latch.
Explicit reset stays paused/unselected; a real paused B renewal needs new health,
then fresh resume/proposal can select B. Stale resume and pause cannot change the
new state. Receipts, wire transaction, process RSS and owned cleanup must agree.

The same frozen tree/binary also reruns the prior nine-case automatic regression
in a separate owned fixture phase and fresh journal. The report gate compares
both phases' complete client build receipts and binary/configuration hashes;
changing any control-phase build field must fail verification. macOS runs portable tests;
actual credential, packet and routing evidence is Linux VM only. Resume/save
interleavings, queue reservation, receipt capacity/reopen and disk-write failure
are portable formal-runtime/core tests, not additional VM crash injections.

See [retained evidence](../reviews/dhcp-control/README.md). No installed-service,
whole-writer SIGKILL/process-tree takeover, VM reboot, sustained DHCP-history
rollover, physical WAN, boot-zero-gap or power-loss qualification is claimed here.
