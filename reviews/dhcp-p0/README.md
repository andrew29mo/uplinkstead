# P0 renewable-client exploration evidence

Run `aa5b61234d455c18`, source manifest fingerprint
`9f17663c762afeed7a255ea9ea1df20ccb059b42f4dc99362dd903703748fe2c`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Attempts](attempts.json)
· [Decision, limitations and reproduction](../../docs/DHCP_P0.md)

## Observed results

- **200 matching-source portable tests per platform**, identical IDs, zero
  errors/failures/skips. They include the production wire tracker, runtime/core
  and exact upstream transformation checks. macOS uses portable injected
  backends/clocks; actual networking runs only in the isolated Linux VM.
- The VM builds a narrow BusyBox 1.36.1 xid adapter from the hash-verified official
  source archive. The receipt records original/patched source, config, compiler
  and binary hashes. The formal foreground service launches that actual binary
  and its shipped hook; fixture code does not directly call the lifecycle core.
- **Five formal-service scenarios passed.** B SIGKILL produces a replacement
  session while A's lease identity remains unchanged. Both links then complete
  **two naturally timed unicast renewals**, without SIGUSR1 or clock injection.
  The same client PIDs/sessions remain in place throughout those renewals.
- A's conservative deadlines advance from **142.226889 → 202.347632 → 262.423651**;
  B's from **142.640968 → 202.719689 → 262.768477** seconds on CLOCK_BOOTTIME.
  The two-round case takes **120.163 s**, primarily intentional timer waiting.
- Blocking only B's unicast DHCP traffic produces a real REQUEST at
  **202.836658 s**, followed by a natural broadcast rebinding REQUEST at
  **233.873306 s**. A real ACK extends B's deadline to **352.854811 s**.
  A's PID/session remains unchanged. Both WAN counters record **zero DHCP
  requests addressed to the other gateway**.
- During the newer unanswered request, the fixture transmits an originally
  captured old ACK from that same B client. B's allocation/deadline/event sequence
  does not change. The later real rebinding response explains the extension.
- With B's server offline, B declares lease loss. Restarting its server with
  **198.51.100.3** produces real acquisition and new TLS over B. A remains
  independently usable after explicit fresh selection. Replaying the earlier
  ACK for **198.51.100.2** cannot overwrite the new allocation/deadline/selection.
- **18 corrupted-receipt controls reject**, including failed/timed-out stages,
  changed source, missing renewals, wrong-path requests and replay mutations.
  They pass under normal and optimized Python. HTML exactly renders JSON.
- Owned processes/namespaces are removed, root network semantics remain
  unchanged, all uploaded/build artifacts are removed and the VM is stopped.

## Important interpretation

The pinned client uses its own half-remaining renewal/rebinding algorithm;
server-provided T1/T2 options 58/59 are **not qualified**. This is evidence of
natural client renewal and rebinding, not full RFC timer interoperability.

B's loss observation occurred at **327.802253 s**, before its conservative
**352.854811 s** deadline: approximately **25.053 s early**. The client gives up
after bounded unsuccessful rebinding attempts. This case is lease-loss and
reacquisition evidence, **not proof that the service independently waited until
expiry**; the earlier stage-one stopped-client test covers that different
condition at its historical source. Early loss is an availability limitation to
address before adopting this client integration as an operational default.

The new adapter remains explicit, experimental and separately GPL-governed. The
normal distro client retains conservative same-xid behavior. Process-local xid
nonreuse does not authenticate DHCP or guarantee collision freedom across client
restarts. The bounded 64-xid session history and restart limiter remain limits;
long-running history saturation was not exercised in this VM trial.

The service still requires explicit selection after fresh health. TLS checks do
not prove uninterrupted forwarding, automatic failover or preservation of old
connections. Installed systemd, dual-service VM reboot, power loss, boot-zero-gap,
physical WANs, arbitrary DHCP options and sustained-load guarantees remain untested.

## Measurements and retained data

The initial individual-process RSS snapshots are **24,192 KiB** for the service,
**1,604 KiB** for A and **1,608 KiB** for B. They are not peak/PSS/process-tree or
whole-VM memory; kernel capture buffers, fixture servers, cache, build tools and
VM overhead are excluded. There is no before/after memory or speed claim.

Scenario durations are **4.595 / 120.163 / 91.146 / 98.042 / 0.378 s** in report
order. These include setup/polling and intentional waits; they are not outage,
failover, throughput or recovery-time guarantees. This is one controlled trial.

Environment: Linux ARM64 6.8.0-117-generic, Python 3.12.3,
gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0. Namespaces share one VM kernel;
fixture routing/NAT and controlled TLS endpoints are not physical ISPs.
The dedicated VM was provisioned with build tools before the recorded run;
that provisioning time is not a measured service cost.

Raw packet frames, private fixture certificates/keys, compiler logs, SQLite
state, host network snapshots, external archives/source and executables remain
outside Git. Exported packet summaries contain frame hashes, not raw frames.
Earlier stage-one receipts remain historical and do not qualify this client.
