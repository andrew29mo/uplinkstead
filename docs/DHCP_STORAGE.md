# Dual-DHCP storage failure: retire and quarantine

This P0 slice handles storage errors without interpreting an unwritable journal
as permission to keep admitting changes. It extends the installed dual-DHCP
service, not the older static/single-DHCP writers.

## Failure contract

Every normal mutation still writes its durable intent before changing routing.
On a reserve check, SQLite write or storage OS error, the writer enters
RECOVERY_REQUIRED and rejects further operations. It does not report the failed
mutation as successful. Lost replies remain OutcomeUnknownInspectStatus, not
proof of rollback or successful application.

A bounded emergency path may quarantine allocations without a successful journal
write only when it still holds the exclusive writer flock and has a validated
previously durable snapshot. It merges that snapshot's permitted allocations/
intent with the current validated in-memory intent, checks the actual backend's
scope, then uses the production backend to withdraw selection and both DHCP
allocations while retaining terminal guards. It never selects a new route,
starts clients, accepts a caller health proof, clears a latch or resets budget.
Helpers inherit the same lock descriptor.

An existing lock is opened read-only, so acquiring the same flock does not itself
require a writable filesystem. Startup reads and validates an existing snapshot
through a read-only SQLite connection before attempting normal writable recovery.
Invalid/mismatched/unreadable state, missing durable authority, a competing lock
or foreign scoped network contents do not authorize blind deletion. Failure to
confirm quarantine is reported as such; it is not a safety-success receipt.

Structured stderr records distinguish the outcome, for example:

```json
{"event":"storage_failure","kind":"sqlite_readonly","sqlite_code":8,"sqlite_name":"SQLITE_READONLY","errno":null,"quarantined":true,"durable":false,"lock_held":true}
```

The process still fails and retires after emitting this record. `quarantined:true`
means backend withdrawal was read back, **not** that the failed mutation committed
or that updated authority was persisted. `quarantined:false` requires intervention;
unknown scope may leave old kernel state in place. Do not treat a missing record,
old cached status or dead process as evidence of successful withdrawal.

## Capacity and repair

The default remains 4096-byte SQLite pages with a 2048-page maximum (8 MiB DB),
plus the existing 2 MiB free-space admission reserve. These limits do not bound
all temporary rollback/filesystem usage, eliminate races or prove disk durability.
A restart-only resource setting is supported:

```json
{"storage":{"max_pages":2048}}
```

`max_pages` must be an integer from 2 to 2048. A two-page limit is used to cause
real SQLITE_FULL in the VM; it is not a recommended operating size. Storage size
is excluded from the route-authority config hash, so an administrator can increase
capacity on a stopped service without editing/deleting the journal or resetting
application policy. Other policy/interface/target settings remain hash-bound.
Only root deployment configuration can resize storage; the worker/control protocol
has no operation to supply a size or bypass a capacity error.

Repair the actual resource: free space on its owning filesystem, restore intended
writability, or increase the configured DB limit within bounds. Inspect the failure
records and kernel readback; then restart with normal systemd failure handling.
A successful startup must persist a new epoch, quarantine old allocations and
rebuild sessions and health before any new selection. Pause/latch, receipts and
switch history survive; application budget reset remains a separate guarded action.

SQLite FULL is a statement capacity error, not necessarily a permanently unwritable
volume. A larger operator record can fail while a smaller post-stop quarantine
record later fits and commits. That is legitimate if the failed operation is not
acknowledged/recorded as applied and policy/history/receipts are preserved. The
affected writer never resumes; a successor still needs successful persistence and
fresh authority. Supervisor retries are bounded by the existing units; this slice
does not add a separate persistent operator-only storage latch.

## Real fault fixture and interpretation

`tools.dhcp_storage_validate` accepts the same archive/Colima/toolchain/output
options as the installed-service validator. It starts with a stopped dedicated
VM, checks source syntax, runs matching portable suites, installs the formal units
and runs their five existing cases. A further phase uses a dedicated **32 MiB
ext4 loop image**, no ext4 root reserve, and journal-path drop-ins. It never fills
the host or VM root filesystem. The extra fault phase temporarily disables automatic
restart so rejection/readback can be observed before explicit repair; the shipped
units retain their bounded restart policy.

- **ENOSPC:** fill only that image, require an actual failed write with errno 28
  and near-zero available space, then invoke the formal operator CLI. The failed
  operation must not return success; reserve failure must retire/quarantine the
  real service, preserving journal policy/receipts.
- **SQLITE_FULL:** use the supported two-page DB limit with ample filesystem space,
  issue bounded real CLI operations until code 13 is observed, and distinguish the
  failed statement from any later smaller successful post-stop cleanup.
- **Readonly:** kill the writer and wait at a documented test-only post-cgroup
  barrier before executing the production stop module. With old kernel allocations
  still present and writer DB descriptors closed, remount that ext4 volume read-only
  and require errno 30. Release the barrier and require real SQLITE_READONLY (8)
  plus read-back quarantine by the installed post-stop process. The barrier only
  delays/execs production code; it implements no backend or recovery behavior.

The readonly phase also runs the production stop entry while a real competing
flock is held: it must fail without changing routes. An injected foreign blackhole
route inside a managed probe table must cause an explicit refusal with that table
unchanged. The fixture removes only its own injected route before allowing scoped
quarantine. A separate foreign table, main routes and RPDB are read back unchanged;
a third fixture-only main path remains viable while LAN forwarding is rejected.

After each repair, the same journal is reopened, servers initially withhold new
leases, and new sessions/zero health are observed before new acquisition/quorum.
Old root operations, worker proposals and retired hooks reject before and after
fresh forwarding. JSON/HTML retain actual errors, scope/readback, API outcomes,
recovery, process RSS snapshots, case durations and cleanup. Durations include
fixture work, not universal withdrawal/outage bounds. No VM-versus-native speed
or RSS advantage is claimed.

## Reproduce and inspect

Use an already provisioned dedicated VM/toolchain as described in
[installed-service deployment](DHCP_SYSTEMD.md). Point these variables at your
local toolchain and separately obtained, hash-qualified BusyBox source archive:

```sh
.venv/bin/python -m tools.dhcp_storage_validate \
  --archive "$BUSYBOX_ARCHIVE" --colima-home "$VALIDATION_COLIMA_HOME" \
  --toolchain "$VALIDATION_TOOLCHAIN" --output results/dhcp-storage-new
```

A fresh output directory is required. The runner rejects optimized Python,
syntax errors, nonzero exit, timeout, source mismatch, incomplete cleanup and
invalid evidence. Logs stay under ignored `results/`; export only reviewed
receipts. [Retained results](../reviews/dhcp-storage/README.md) distinguish
successful qualification, failed attempts and their cleanup/remediation.

## Limits

This is not sudden-power-loss, corrupt/hot-journal recovery, arbitrary live I/O
failure, VM reboot or boot-zero-gap qualification. The real readonly remount is
made after the old writer/cgroup closes its DB, before production post-stop
quarantine; it is not a remount during a live SQLite commit. Portable query-only
and final-write injections are identified separately from real VM filesystem
faults. Unknown scope/authority or failing kernel operations can prevent safe
quarantine. Long-running history/receipt rollover and physical-WAN deployment
remain separate gates.
