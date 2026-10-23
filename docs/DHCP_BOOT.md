# Installed dual-DHCP orderly VM reboot recovery

This gate extends the installed dual-DHCP service; it does not replace the static
or single-uplink DHCP writers. Use dedicated interfaces and an existing deployment
that owns network provisioning. The product unit does not configure interfaces,
forwarding, upstream return routes or NAT. The isolated VM fixture supplies those
prerequisites before the actual writer starts.

## Recovery contract

A new Linux boot invalidates old lease sessions, health, capture transactions and
operator/proposal authority. The production writer must persist a new epoch,
quarantine old allocations, and start with empty leases and WAITING health before
READY. READY means the service is accepting work, not that a WAN is usable. New
wire ACKs and fresh health quorum are both necessary for new forwarding. An ACK
without healthy target paths must not authorize selection.

Pause, latch, operation receipts and switch history survive. Old-boot monotonic
timestamps cannot be aged against a new boot's clock, so old history is retained
conservatively. A reboot can therefore leave the switch budget exhausted. This
requires explicit operator intervention, not automatic history deletion. A budget
reset requires pause plus the explicit acknowledgement; resume additionally needs
fresh healthy evidence and an unlatched state.

A storage failure during boot must not publish readiness or admit selection.
The existing bounded systemd restart policy applies. Emergency quarantine still
requires exclusive ownership and scoped backend readback; its non-durable receipt
is a failed mutation, not successful persistence. Resource repair allows a new
writer to start, but does not authorize old leases/health or reset policy.

## Five controlled cases

1. **Normal reboot:** normal unit stop and ExecStopPost run. The next boot's
   read-only pre-Agent snapshot must show cleanup, followed by actual recovery,
   empty leases, new acquisition, new health and fresh TLS traffic.
2. **Preserved journal:** freeze the actual writer and clients, then install a
   runtime-only shutdown override with KillSignal=SIGKILL and an empty
   ExecStopPost. The actual D-Bus property must be the typed empty command array;
   omitted fields in systemctl display are insufficient. Normal VM shutdown still occurs. On the next boot the override
   is absent, and a read-only observer must see the exact old journal including
   nonempty allocations/selection before production ExecStart. This excludes
   pre-shutdown cleanup as the explanation for successful recovery.
3. **Paused:** pause through the formal control interface before normal reboot.
   Both fresh leases and health may return, but forwarding must remain blocked
   until a successful explicit resume.
4. **Latched:** use controlled edge blackholes and real automatic failovers to
   exhaust the configured eight-switch budget, then pause through the formal API.
   After normal reboot, fresh leases/health must not unlock the service. Resume
   must reject until an explicitly acknowledged reset, followed by resume. The
   fixture never edits journal fields to manufacture the latch.
5. **Capacity:** after an orderly service stop, copy the same journal bytes into
   a dedicated 32 MiB ext4 loop filesystem, and use labelled journal-path-only
   service overrides. Fill that volume until real ENOSPC, fail an operator API,
   then reboot with the volume still full. The boot fixture remounts the same
   image without deleting filler or repairing state. Startup must fail, worker
   stay inactive, restart attempts stay bounded, failed operations remain failed,
   owned tables be empty and the journal remain unchanged. Remove only filler,
   reset systemd's failed state, and restart the formal service: fresh authority
   is required before forwarding. The prior SQLite FULL/readonly validation is
   separate; this boot case does not imply those faults were tested across boot.

Each post-boot case starts DHCP servers absent. It then permits new DHCP while
blocking the upstream edge forwarding paths, observes unqualified health and
blocked LAN traffic, and only later removes the controlled fault. A third static
fixture NIC supplies an independent viable main-route witness through B, even
while the DHCP-facing B edge is blocked. Failure of the LAN request must not be
explained solely by a dead destination or missing upstream path. Wrong-WAN DHCP
counters, main/RPDB/foreign-route readback and old-operation replay challenge
borrowing, scope changes and stale authority both before and after fresh traffic.

## Fixture and evidence boundary

The exact shipped writer and worker unit file hashes are retained. The fixture
adds explicit namespace/PYTHONPATH drop-ins, a topology Requires/After dependency
and a fixture-only boot timer enable symlink. The timer starts the formal writer
at OnBootSec=25s, after Colima host provisioning normally completes; its actual
trigger receipt is retained. This deliberate startup delay is not a product
network gate or boot-availability guarantee. The topology unit only provisions disposable network
prerequisites and reads the journal; it never invokes DualLifecycle, synthesizes
recovery state, or installs Uplinkstead's managed routes/guards. Initial
managed tables must be empty before the writer starts. The actual production
backend owns all routing recovery, guards and selection. The capacity case
changes only journal paths and writable sandbox scope, not production recovery.

The Colima-specific topology fixture is ordered after Docker, Lima guest-agent
and network-online prerequisites, and before the writer. It also requires the
VM Docker interface before taking its root-network baseline. Docker/Lima are
Wants/After dependencies, so a host-side Docker restart does not itself kill
the topology. The explicit fixture boot delay avoids measuring host provisioning
as product-induced drift. Reverse stop ordering applies during VM shutdown;
root-network differences are not filtered out or accepted as equivalent. These
are fixture dependencies, not new Docker/Lima requirements for the product.

The topology service is a reproducible test deployment, not a supported host
network manager. It intentionally leaves pre-Agent network timing outside the
protection claim. Both ordinary and preserved-journal VM shutdowns are orderly:
SIGKILL and skipped stop cleanup are controlled process faults, not power loss.
Kernel rules and connections do not survive a VM reboot; durable old authority,
not a surviving process, is the cross-boot threat tested here. Previous-boot PIDs
are never used as authority to terminate a reused PID in the new boot.

The portable core tests separately change boot identity and exercise old budget,
pause/latch and failed-persistence recovery. They do not execute systemd on macOS.
Both platform receipts must use identical frozen source and identical test IDs.
JSON verification rejects failed/timed-out stages, unchanged boot IDs, missing
pre-Agent observations, policy loss, old authority acceptance, fake capacity
success and incomplete cleanup. Mutated-evidence controls challenge these gates.

## Reproduce

Use the same already provisioned dedicated relay VM, toolchain and hash-qualified
external BusyBox source archive as [installed validation](DHCP_SYSTEMD.md):

```sh
.venv/bin/python -m tools.dhcp_boot_validate \
  --archive "$BUSYBOX_ARCHIVE" --colima-home "$VALIDATION_COLIMA_HOME" \
  --toolchain "$VALIDATION_TOOLCHAIN" --output results/dhcp-boot-new
```

The VM must start stopped; the output directory must be fresh. The runner installs
owned assets, performs five VM stop/start cycles, and removes the enabled link,
units, drop-ins, state, fixture processes/namespaces, loop device/mount and source
snapshot before stopping the VM. Raw logs/keys/images remain in ignored results
or the disposable VM; export only reviewed receipts. Failed attempts remain
failed and are retained separately from qualification.

## Measurement limits

Post-boot driver seconds begin after the host can invoke the after-boot driver;
they include negative tests, deliberate delays, policy interventions and resource
repair. They are not boot time, WAN outage duration, a recovery deadline or an SLO.
Kernel boot-time observation checkpoints and systemd start/active timestamps are
retained separately. Process RSS snapshots belong to the Linux VM and are not
peaks, host consumption, or a performance comparison against macOS.

No abrupt power loss, boot-zero-gap, uninterrupted existing connection, arbitrary
storage corruption, every I/O failure, physical WAN or DHCP implementation-wide
interoperability is qualified. An invalid/missing ownership snapshot or foreign
kernel contents may prevent safe quarantine. Do not infer universal fail-closed
or automatic repair from these controlled cases.
