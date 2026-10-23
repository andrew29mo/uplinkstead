# Installed dual-DHCP service and writer takeover

This extends the foreground dual-DHCP contract with installed systemd supervision.
It is separate from the older static `uplinkstead.service` and single-uplink
`uplinkstead-dhcp.service`. Do not run these writers against the same interfaces.
Use dedicated interfaces, the qualified DHCP client, three reachable TLS targets
and pre-provisioned forwarding/reverse-path settings from the dual-DHCP contract.
Do not attach unrelated main-table routes to those DHCP interfaces: Linux can
remove interface-tied routes/neighbours when their last IPv4 address is removed.
The service does not recreate another tool's routes to conceal that kernel effect.

## Installation contract

Install the Python package for `/usr/bin/python3` (Python >= 3.12), an existing
dedicated unprivileged `uplinkstead` user/group, the qualified timer-enabled BusyBox
client at `/usr/libexec/uplinkstead-busybox`, the exact standalone
`uplinkstead/dual_dhcp_worker.py` as `/usr/libexec/uplinkstead-dual-worker.py`, and
`deploy/uplinkstead-dual-hook.py` at `/usr/libexec/uplinkstead-dual-hook.py`.
The hook must be executable (0755); the standalone worker is read-only 0644
because its unit invokes Python explicitly. The client must also be executable.
Files and their parent directories must be root-owned and not writable by the
worker. Keep client provenance/licensing from [THIRD_PARTY](THIRD_PARTY.md);
no BusyBox binary or source archive is bundled in this repository.

Place the explicit configuration at `/etc/uplinkstead/dual-dhcp.json`, root-owned
and private, including `runtime.automatic_selection: true`. Install the two shipped
`deploy/uplinkstead-dual*.service` files into `/etc/systemd/system/`, reload the
service manager, and enable/start `uplinkstead-dual.service`. The writer pulls in
the policy unit; only the writer is enabled for boot. Interface readiness remains
a deployment prerequisite: the units do not enable or configure the host network.
Enabling a unit alone is not reboot evidence. The separate
[orderly VM boot gate](DHCP_BOOT.md) tests the installed units with explicit
isolated topology prerequisites; it is not general host-network provisioning.

```sh
systemctl daemon-reload
systemctl enable --now uplinkstead-dual.service
systemctl status uplinkstead-dual.service uplinkstead-dual-policy.service
python3 -m uplinkstead.dual_dhcp_cli --socket /run/uplinkstead-dual/control.sock status
systemctl stop uplinkstead-dual.service
```

`StateDirectory` creates private `/var/lib/uplinkstead-dual` mode 0700.
`RuntimeDirectory` creates root:`uplinkstead` `/run/uplinkstead-dual` mode 0750;
its event subdirectory is root-only 0700, while the control socket is group 0660
with exact peer UID enforcement. The writer resolves `--policy-user uplinkstead`
once at startup; do not change that account while services are running.
The worker runs without capabilities, with NoNewPrivileges and AF_UNIX-only
sockets. The writer retains NET_ADMIN, NET_RAW and NET_BIND_SERVICE for its actual
backend/capture/DHCP children; those components remain privileged and trusted.

## Start, stop and recovery

1. The writer holds the exclusive journal lock and uses production recovery to
   quarantine persisted allocations and selection. Sessions/epoch advance; health
   begins WAITING. Pause, latch, receipts and switch history survive.
2. It opens capture and IPC, starts the two clients and publishes status before
   sending systemd `READY=1`. This is writer readiness, not a DHCP lease or
   reachable WAN. The policy unit starts after that notification.
3. Only newly admitted wire leases and new health can authorize forwarding.
   A missing policy worker does not permit inline automatic selection.
4. `KillMode=control-group` applies to the writer and its clients/hooks/helpers.
   On a stop or failure systemd terminates the cgroup before `ExecStopPost` runs.
   `uplinkstead.dual_dhcp_stop` takes the same lock and invokes the same production
   recovery core to remove old allocations/selection, retaining terminal RPDB
   guards against main-default borrowing. It never deletes the journal or resets
   limits. An incomplete post-stop operation is a failure, not a safety receipt.
5. Automatic restart is bounded to three starts per 60 seconds with a two-second
   restart delay. The policy unit follows writer stop/restart through its
   dependency and PartOf relationship. Persistent failure requires diagnosis and
   explicit recovery; it must not trigger journal deletion or budget reset.

**pause differs from stop**: pause keeps a still-safe selected route while safety
withdrawal continues. Stop withdraws both allocations and the selected route.
Neither hands LAN traffic to main's default. A crash can leave old kernel state
until supervision/cleanup runs; this is not continuous health enforcement while
no writer is executing. Post-stop cleanup normally persists its recovery state. The separately qualified
[storage-failure path](DHCP_STORAGE.md) can withdraw under the same exclusive lock
without a successful write, using a previously validated ownership snapshot.
Kernel failures, invalid snapshots and foreign scope can still prevent quarantine.

After repairing a demonstrated startup problem, inspect the journal/status and
service logs, then explicitly use `systemctl reset-failed` on both units and start
the writer. This resets systemd's restart limiter only; it does not reset the
application's switch budget/latch. Use the separately fenced CLI operations when
operator policy intervention is actually required.
An inactive policy unit may already have been unloaded and have no limiter to
reset; that diagnostic must not conceal failure to reset the failed writer.
The invalid-configuration experiment begins after guards have been installed and
allocations withdrawn. On a fresh host, invalid configuration can prevent initial
guard installation entirely. These units do not shut interfaces to protect that
first-start interval; initial-network gating is not qualified here.

## Evidence and reproduction

Run `.venv/bin/python -m tools.dhcp_systemd_validate` with the same `--archive`,
`--colima-home`, `--toolchain` and fresh `--output` options as the control validator.
The dedicated VM must begin stopped. The runner installs the exact shipped unit
files; namespace and PYTHONPATH drop-ins point them at the isolated topology and
frozen package snapshot. It installs the exact worker/hook and qualified client,
then removes owned installation artifacts, processes and namespaces and stops VM.

Tests exercise startup/readiness, actual worker credentials, journal denial,
orderly stop/start with a viable forbidden main fallback, whole-writer SIGKILL,
stale root/worker/hook requests, and an actual inherited-lock ip helper stopped
before exec. That one fault case has an explicit test-only ExecStart shim and a
shorter stop timeout: the shim stops before exec, ignores TERM and waits at most
eight seconds for an explicit release after systemd's CONT. It uses the production
service and Linux.run, delays only execution, and cannot invent successful
backend/lease/health outcomes. A successor
must not acquire ownership while that helper holds the lock, and systemd must
kill it before takeover; no delayed old ip command may execute afterward.
The stop test's main fallback uses a third fixture-only static interface, so
withdrawing both product DHCP allocations cannot accidentally disable the
positive control. No product address or route is reinstalled for that witness.
An invalid-configuration case checks the real restart limiter, repair without
implicit limiter reset, then explicit operator repair.

The same source reruns the prior five control and nine automatic VM cases in fresh
fixtures. Portable tests check the formal stop recovery core and notify socket;
macOS does not execute systemd or Linux routing. JSON/HTML verification binds unit
hashes, worker/client provenance, epochs, fresh acquisition, rejection and cleanup.
VM RSS values are process snapshots, not peaks or physical host memory comparisons.
The evidence gate checks the writer's exact capability mask and NoNewPrivs as
well as worker credentials. Recovery must clear health counters, round and
deadline; later forwarding needs a different client session, higher generation
and new health quorum. Restart-limit journal entries are read after a cursor
sampled before the fault, retained with boot/time/unit identity, and rejected if
they belong to an earlier interval. A boolean copied from an old log is not proof.

This does **not** qualify VM reboot, sudden power loss, boot-zero-gap protection,
capacity longevity, every helper/kernel interleaving or uninterrupted existing
connections. No universal failover or recovery time bound is claimed.

The installed storage-fault extension and its explicit drop-ins are documented in
[DHCP_STORAGE.md](DHCP_STORAGE.md); historical systemd receipts above remain unchanged.

The separate [boot gate](DHCP_BOOT.md) adds five orderly VM restart cases. The
original process-restart receipts remain historical and do not themselves
qualify reboot behavior or power loss.
