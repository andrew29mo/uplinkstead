# P0 renewable-client exploration evidence

Run `521a6979ee907e0e`, source manifest fingerprint
`556eb500ea4e4a9b29ad205ebd3db031e1b7659c1c7ae55de2e6a1399c00af90`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Attempts](attempts.json)
· [Decision, limitations and reproduction](../../docs/DHCP_P0.md)

## Observed results

- **206 matching-source portable tests per platform**, identical IDs, zero
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
- A's conservative deadlines advance from **142.182697 → 201.274198 → 261.341268**;
  B's from **142.575017 → 202.649840 → 262.761534** seconds on CLOCK_BOOTTIME.
  The two-round case takes **120.228 s**, primarily intentional timer waiting.
- Blocking only B's unicast DHCP traffic produces a real REQUEST at
  **202.818964 s**, followed by a natural broadcast rebinding REQUEST at
  **233.942192 s**. A real ACK extends B's deadline to **352.846313 s**.
  A's PID/session remains unchanged. Both WAN counters record **zero DHCP
  requests addressed to the other gateway**.
- During the newer unanswered request, the fixture transmits an originally
  captured old ACK from that same B client. B's allocation/deadline/event sequence
  does not change. The later real rebinding response explains the extension.
  Both original-ACK replays now require a new receiver-side frame hash, a matching
  production Capture hash/ordinal, a drained queue and a later complete Runtime
  step; identity/version/pending checks occur after that processing fence.
- A separately labelled **synthetic delayed reply** targets the earlier unanswered
  unicast xid after the next REQUEST. It is constructed from the original ACK
  template, not a captured historical reply for that unanswered transaction.
  Production consumption is verified and cannot withdraw or replace the current
  lease. Portable tests additionally cover delayed ACK arrival after a newer
  successful ACK and the next legitimate renewal, plus numeric xid wrap order.
- With B's server offline, B declares lease loss. Restarting its server with
  **198.51.100.3** produces real acquisition and new TLS over B. A remains
  independently usable after explicit fresh selection. Replaying the earlier
  ACK for **198.51.100.2** cannot overwrite the new allocation/deadline/selection.
- **43 corrupted-receipt controls reject**, including failed/timed-out stages,
  changed source, missing renewals, wrong-path requests and replay mutations.
  They pass under normal and optimized Python. HTML exactly renders JSON.
- Owned processes/namespaces are removed, root network semantics remain
  unchanged, all uploaded/build artifacts are removed and the VM is stopped.

## Important interpretation

The pinned client uses its own half-remaining renewal/rebinding algorithm;
server-provided T1/T2 options 58/59 are **not qualified**. This is evidence of
natural client renewal and rebinding, not full RFC timer interoperability.

B's loss observation occurred at **327.406427 s**, before its conservative
**352.846313 s** deadline: approximately **25.440 s early**. The client gives up
after bounded unsuccessful rebinding attempts. The actual client branch emits
`remaining=26, attempts=3` for the same B PID/xid. Three captured broadcast
REQUESTs match that xid; the formal `deconfig` hook is recorded at
**327.352203 s**, processed at **327.376054 s**. This directly observes retry
exhaustion with lease time remaining, rather than inferring causality only from
the final rules. The integer client budget and floating REQUEST-origin service
deadline are different clocks/accounting boundaries; 26 is not an exact 26-second
service outage measurement. This case is lease-loss and
reacquisition evidence, **not proof that the service independently waited until
expiry**; the earlier stage-one stopped-client test covers that different
condition at its historical source. Early loss is an availability limitation to
address before adopting this client integration as an operational default.

The new adapter remains explicit, experimental and separately GPL-governed. The
normal distro client retains conservative same-xid behavior. Process-local xid
nonreuse does not authenticate DHCP or guarantee collision freedom across client
restarts. The bounded 64-xid session history and restart limiter remain limits;
long-running history saturation was not exercised in this VM trial. A missed
new REQUEST cannot be inferred by the watermark; loss-free capture, arbitrary
reordering and unlimited packet delay are not guarantees.

The service still requires explicit selection after fresh health. TLS checks do
not prove uninterrupted forwarding, automatic failover or preservation of old
connections. Installed systemd, dual-service VM reboot, power loss, boot-zero-gap,
physical WANs, arbitrary DHCP options and sustained-load guarantees remain untested.

## Measurements and retained data

The initial individual-process RSS snapshots are **24,228 KiB** for the service,
**1,592 KiB** for A and **1,592 KiB** for B. They are not peak/PSS/process-tree or
whole-VM memory; kernel capture buffers, fixture servers, cache, build tools and
VM overhead are excluded. There is no before/after memory or speed claim.

Scenario durations are **4.560 / 120.228 / 91.194 / 97.517 / 0.124 s** in report
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

## Review corrections and evidence layers

Review reproduced a real tracker defect: an unanswered older xid's late ACK
could become latest after a newer success, withdraw the valid lease and make a
later legitimate claim ambiguous. First-seen REQUESTs now permanently retire
the prior transaction, without withdrawing the still-valid allocation merely
because renewal began. Already superseded requests cannot move that watermark.
The previous passing receipt remains accessible at Git revision `382a62a`; it
did not cover this regression. See attempts.json for the qualification history.

The verifier now rejects deadline extensions detached from actual ACK lifetime,
wrong packet types/MACs/times, missing runtime records, unconsumed replays and
incorrect build provenance. Original/patched source hashes are pinned, the recipe
hash matches the source manifest, and the launched binary is independently read
back. Synthetic payload metadata retains its original template capture time;
`sent_at` and `received.at` are the actual injection and receiving observations.
Neither the synthetic fault nor portable counterexamples are presented as a
packet captured from a previously delayed real server response.
