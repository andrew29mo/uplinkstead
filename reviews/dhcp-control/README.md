# Dual-DHCP policy/operator boundary evidence

Run `be3e1d4c110ac9f9`, matching-source fingerprint
`11c3448436e5e8723cf3cb5b04d555e850d38ba81024270d6fba81c37be5667e`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [Attempts](attempts.json) ·
[Contract and reproduction](../../docs/DHCP_CONTROL.md)

## Delivered scope

An optional capability-free worker submits only fenced suggestions; the root
writer owns lease admission, health, candidate hold/grace, budget/latch and all
network operations. Exact SO_PEERCRED policy UID is required. Worker proposals
cannot supply clocks, health, commands, routes or root identity. New automatic
charged selections require that worker in this mode; bounded lease restoration
and safety cleanup remain writer-owned. Existing inline foreground mode remains
available without the new CLI flags.

Root CLI pause, explicit reset-budget and resume retain original epoch/revision
and operation ID. Reset stays paused and does not forward or clear other limits.
Resume does not clear latch, requires writer-owned fresh lease/health and rechecks
after persistence/intake. Thirty-two local receipts persist with state; rejected
old operations cannot overwrite newer state. Entering budget latch now advances
revision, so a durable control change cannot leave an older token current.

## Measured Linux VM checks

| Control case | Actual observation | Seconds |
|---|---|---:|
| Real unprivileged worker/kernel boundary | No writer-only initial choice; actual worker then selects A; raw socket, route-write, journal and private-event access denied | 3.943 |
| Rogue worker rejection | Healthy B cannot preempt A; forged fields, root controls and a different UID sharing the socket group reject without state mutation | 0.105 |
| Pause/stale resume/safety | Real root CLI pause; old resume rejected; A failure still withdraws while paused; B/main TLS works but LAN cannot borrow it | 1.702 |
| Absent worker and budget | Resume without reset leaves history intact; no charged choice without worker; restarted worker's B suggestion hits durable latch | 1.378 |
| Explicit reset/new lease/resume | Resume cannot clear latch; reset without ack rejects; explicit reset remains paused/unselected; real paused B renewal gets new health; fresh resume/proposal selects B, stale pause rejects | 0.825 |

The actual worker readback is UID/GID **61001 in all four fields**,
**CapEff/CapPrm/CapInh/CapAmb/CapBnd = 0**, **NoNewPrivs = 1**. Its root-owned
read-only standalone file hash equals the frozen production worker module; the
actual root CLI module hash is also checked. These are real Linux credentials,
not a fake UID passed to a unit-test method. A test actor with UID 61002 and the
same GID reaches the socket but receives PermissionError from peer authorization.
No persistent OS account or GitHub access grant is created by this fixture.

The real root CLI produces the durable operation order:
`pause → resume → pause → reset-budget → resume`. Failed stale/unauthorized/no-ack
requests do not add successful receipts. After explicit reset, a real B ACK
changes generation/sequence while still paused. B obtains at least two new health
rounds with a health start after the new lease event; the final wire transaction,
current deadline/generation and actual B endpoint agree. Resumed selection records
one new budget entry, with no hidden reset in resume.

VM process RSS snapshots: root writer **25,032 KiB**, worker **11,816 KiB**.
These are not peaks and exclude clients/kernel/fixture/whole-VM overhead. Case
durations include intentional waits and are not throughput, failover-time bounds,
application latency comparisons or estimates of privilege-separation overhead.

## Matching-source regression and evidence checks

- **258 portable tests on macOS and Linux**, identical IDs, no failures/errors/
  skips. Eighteen new tests invoke the formal runtime/SQLite core/CLI/worker
  functions for roles, hold/non-preemption, tokens/generations, separate operations,
  resume/save ACK/expiry races, write failure, receipt bounds/reopen/replay,
  reserved queues, CLI no-retry behavior and latch revision. Injected clocks/IO/
  UID arguments qualify those logic paths, not actual Linux privilege enforcement.
- A **separate nine-case automatic VM regression** uses the same frozen source
  and compiled client in fresh owned fixtures. It covers the prior eight service/
  fault cases plus TLS fixture isolation, including natural renewal, SUSPECT,
  ACK/loss write interleavings, budget/latch and non-borrowing. No live journal is
  deleted to reset its authority. Its complete cases remain nested under
  `guest.regression`; the HTML top table lists only the five control cases.
- **54 corrupted-evidence controls** pass: 36 automatic and 18 control-specific.
  They reject source/build/stage/cleanup failures, invalid old health/budget,
  wrong UID/capability/access, accepted malicious/stale operations, reset-unpause,
  missing new quorum, borrowing and missing receipts. Normal and optimized Python
  verification agree; HTML exactly renders JSON, and standalone unit receipts
  equal their embedded copies.
- One full VM attempt completed. All owned processes/namespaces and the temporary
  control directory/source/build are removed; root network and source are unchanged;
  VM is stopped. Private logs/keys/journals/raw frames and external binaries stay
  excluded. The external BusyBox client remains separately GPL-governed.

## Material limits

This completes the foreground policy/operator slice, not installed deployment or
whole-writer recovery. DHCP clients/capture remain trusted privileged components;
a capability-free policy process is not a full sandbox or protection against a
compromised root writer. No arbitrary peer-flood/CPU-DoS qualification is claimed.

Resume/persistence failures and audit reopen are portable injected tests, not VM
SIGKILL/reboot or real disk-full injections. Stamps are not atomic with future
packets. Process-tree supervision, installed systemd start/stop/reboot, sustained
DHCP history rollover, physical WAN, boot-zero-gap, uninterrupted existing TCP
connections and sudden power loss remain untested in this slice. Bounded local
operation receipts are not external tamper-proof audit or unlimited idempotency.
