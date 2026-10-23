# Dual-DHCP storage failure and repair

Run `6c2e88e117fa9d80`, same-source fingerprint
`e94b2ed163e80cf69d09e1682fdec7dbd0134a0ec57a8896f1208f173a946441`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [All attempts](attempts.json) ·
[Contract and reproduction](../../docs/DHCP_STORAGE.md)

macOS and Linux each passed 273 tests, with no skips. The installed-service VM
suite passed five systemd cases, five control cases, nine automatic-routing cases
and three additional storage cases. All 97 corrupted-evidence controls rejected.
The VM was stopped; owned processes, namespaces, installed artifacts, source
snapshot, loop mount and loop device were removed. Root networking was unchanged.

## Actual fault scope

A dedicated 32 MiB ext4 loop filesystem with zero root reserve was filled until
real writes returned ENOSPC (errno 28, zero free bytes). The installed writer's
mutation failed and its reserve check retired it. A separate case triggered
actual SQLite FULL (code 13) through a two-page limit while filesystem capacity
remained available. Neither API returned success. Both used the production
writer and backend, not a replacement recovery implementation.

The readonly case killed the actual writer, held its real ExecStopPost at a
VM-only barrier until the cgroup released open files, and remounted the dedicated
volume readonly (real write errno 30). Releasing that barrier executed production
stop recovery, observed SQLite READONLY (code 8), and withdrew controlled routes.
This is post-crash recovery on a readonly volume, not a live-writer remount test.
Storage drop-ins used Restart=no to preserve the observation window; the inherited
systemd suite separately tests the shipped bounded restart policy.

Quarantine receipts explicitly say durable=false. They acknowledge neither the
failed API nor a new READY state. Real lock contention prevents recovery from
reaching the backend; an injected foreign route inside a managed table causes
scope validation to refuse mutation. After fixture removal of only that route,
recovery succeeds. Unrelated RPDB rules, main routes and foreign table 49999 remain
unchanged; LAN forwarding is blocked while an independent main-route TLS witness
still works, challenging accidental borrowing.

Repair preserves the journal, pause/latch, switch history and operation receipts.
Only root storage capacity configuration is enlarged in the SQLite case; it does
not change route authority identity. A new durable epoch starts with empty leases
and WAITING health; fresh acquisition and health are necessary for TLS forwarding.
Retired pause/resume/reset, worker proposals and client hooks reject before and
after fresh selection. New selection charges the ordinary switching budget.

SQLite FULL can reject a growing record while later, smaller post-stop cleanup
commits successfully. The evidence permits that safe higher-epoch quarantine;
it requires policy/history/receipts to remain intact rather than discarding this
difference by requiring every journal byte to remain unchanged.

## Measurements

| Case | Whole-case seconds | Recovered process RSS snapshots (KiB) |
|---|---:|---|
| enospc | 10.356 | {"worker": 11828, "writer": 24536} |
| sqlite_full | 10.405 | {"worker": 11832, "writer": 25376} |
| readonly | 9.681 | {"worker": 11832, "writer": 24556} |

These are Linux VM observations, separate from macOS unit receipts. Whole-case
time includes fault setup, polling, failed operations, repair and fresh traffic;
it is neither outage duration nor a recovery upper bound. RSS is a process
snapshot, not peak memory, host memory, or a performance comparison. Full raw
observations and monotonic checkpoints are retained in JSON.

No VM reboot, abrupt power loss, storage corruption, hot-journal repair, boot
zero-gap, unbounded capacity longevity, or all kernel/I/O failure modes are
qualified by this run. An unreadable/invalid ownership snapshot or foreign kernel
state must not authorize broad deletion; refused quarantine can leave existing
routing in place and requires operator repair. There is no universal fail-closed
claim or new persistent operator-only storage-fault latch.

Two unsuccessful attempts are retained separately, including manual cleanup of
the second run's owned source snapshot after its syntax error. They are not
relabelled as passes. The successful runner additionally checks all frozen Python
source syntax before installing anything.


## Follow-up review corrections

Independent code and evidence review identified and fixed:

- A failed initial SQLite CREATE can leave an empty file. The formal core now
  permits only a narrowly identified owned, single-link, zero-byte file without
  journal/WAL/SHM sidecars as uninitialized, granting no durable route authority.
  Three new portable tests reproduce initial FULL and repair, reject sidecars,
  and reject nonempty missing-schema databases. This edge was not separately
  fault-injected into systemd in the VM; external truncation/corruption remains
  unqualified.
- Repair validation now checks pause/latch retention before acquisition and after
  fresh health, and requires a successful explicit resume for previously paused
  policy. Negative controls reject cleared policy and missing resume receipts.
  Prior raw evidence had retained pause correctly; the defect was a validation
  gap, not observed unauthorized forwarding.
- HTML now distinguishes qualified bounded storage faults from untested capacity
  longevity; the inherited blanket denial of capacity qualification was removed.

The current receipts are a new same-source full run after these changes. The prior
successful run remains in Git history and its attempt metadata is retained; no
old observations have been relabelled as new measurements. Abrupt power loss,
VM reboot under these faults and boot zero-gap remain untested.
