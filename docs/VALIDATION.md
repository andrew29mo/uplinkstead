# First MVP validation

Run **5f8e4f7a4027c930**, source fingerprint
`2a8ef69d31cfb697e7c71591128c06ae6d48d3f609b9c9bdd4e6adf1d76431f2`.

[JSON](../reviews/mvp/evidence.json) · [HTML](../reviews/mvp/report.html)
· [macOS](../reviews/mvp/native-unit.json) · [Linux](../reviews/mvp/linux-unit.json)
· [MVP attempts](../reviews/mvp/attempts.json)

## Observed qualification

- **75/75 portable tests on both macOS and Linux**, identical test IDs and source
  manifest, no skips/failures/errors. Native macOS does not run a routing backend.
- **25 actual Linux namespace scenarios**: the 19 reviewed core exploration scenarios
  plus installed-service privilege, safe lifecycle, storage bounds, lifecycle write
  failure recovery, bounded systemd restart and identical-schedule benchmark.
- **27 report corruption controls rejected**, including privilege escalation,
  unsafe resume, missing attempts, altered arrival schedule, failed persistence and
  absent restart-limiter evidence. The report also verifies under Python `-O`;
  assertion-based validation runners explicitly refuse optimized execution.
- Shipped root writer and capability-free dedicated policy service are installed.
  Their source hashes and deterministic fixture transformations are checked.
  Operator tests use the formal CLI; no arbitrary network command RPC exists.
- Actual SIGKILL process replacement and orderly VM stop/start. A pre-Agent journal
  snapshot retains pending B intent with A receipt, excluding shutdown rollback as
  the explanation. New boot reconstructs B, clears pending after readback, retains
  latch and begins health at RECOVERING, with a successful new LAN TLS request.
- Root network semantics preserved, owned namespaces/units and source removed,
  dedicated policy account removed, VM stopped. Failed exits/timeouts/source changes
  never become a passing run.

The original core fault driver remains a separate test of shared Writer/Policy/
Linux logic. It does not pretend to be the unprivileged installed policy worker.
New MVP cases exercise the actual two services. The benchmark leaves a fixture-set
latch for the final reboot test; that write is explicitly not evidence of budget
exhaustion. Actual exhaustion is independently observed in the alternating-fault
core case, with complete timings/history and all failed LAN requests retained.

## Controlled traffic trial

Both modes start from healthy A and replay 20 intended arrival offsets at 0.5-second
intervals. A forwarding blackhole is installed before request index 4 at offset
2 seconds and retained through that mode's completion. Eight worker slots submit
open-loop scheduled TLS requests; actual start/end offsets and lateness are kept,
including failed and deadline-expired requests. This is low-load fault recovery,
not a saturated router-throughput benchmark.

| Mode | Successful / attempted | Failed | Useful requests/s | All-attempt E2E p95 ms | Writer / policy RSS KiB | Main DB bytes |
|---|---:|---:|---:|---:|---:|---:|
| fixed_primary | 4/20 | 16 | 0.379 | 1051.0 | 23920 / 20872 | 49152 |
| automatic | 13/20 | 7 | 1.364 | 1033.0 | 23972 / 20872 | 65536 |

Useful requests/s divides all successes by actual complete-trial duration; failed
requests remain in the denominator's elapsed window. End-to-end latency starts at
the intended arrival and includes fixture client-process startup, TCP/TLS and
failure timeout. p95 uses nearest rank over all 20 attempts, including failures.
RSS is an after-trial `/proc` snapshot for each service, not peak/PSS/whole-VM memory.
DB bytes refer only to the SQLite main file, not rollback journal, filesystem or VM.
Raw observations support rechecking these calculations; no speedup ratio is claimed.
The trial is single, fixed order and small; warm-up/order effects and run-to-run
variation are not controlled enough for general performance conclusions.

## Fault and capacity evidence

- Fresh installed service starts DISABLED without routing attachment. Enable enters
  PAUSED; premature resume is refused. Root must explicitly acknowledge both
  routing handoff and budget reset. Pause leaves the selected failed A route in
  place; healthy manual B selection works; stale revision and restart epoch reject.
- The policy UID has no effective capabilities, cannot read the journal, perform
  operator changes or directly alter routes. An unrelated UID is denied. Oversize,
  duplicate/non-object/unknown-op packets reject; an idle peer times out while the
  same writer instance survives.
- Partial enable and disable inject failures at real backend command boundaries;
  the next actual Writer completes the durable lifecycle intent. A real
  `ip monitor route` helper times out and is killed/reaped. Query-only SQLite
  rejects a save before a route write. These are controlled faults, not physical
  storage corruption, I/O device failure or power loss.
- Real DB retention settles at 128 events; page layout/cap is 4096 bytes x 2048.
  Portable tests trigger an actual SQLite FULL error and retain that original error.
  The low-free-space guard is tested by injected disk-usage return values; no VM
  filesystem is filled. Temporary rollback storage requires separate provisioning.
- systemd limiter proof uses three distinct actual invocations, its repeated-start
  rejection message and eight no-writer samples beyond RestartSec. `Result=signal`
  can persist and is not itself proof of a missing limit. Explicit reset/start then
  recovers. Other scenarios reset fixture counters between planned manual starts;
  this does not remove the deployed restart limit.

## Environment, history and limits

Colima VZ Linux ARM64, four CPUs/6 GiB configured, Linux 6.8.0-117-generic,
Python 3.12.3 and systemd 255. All six namespaces share one kernel/failure domain.
The three TLS target ports share one fixture server. No independent ISP claim.
The post-reboot writer RSS snapshot was `VmRSS:	   23808 kB`.

Initial exploration attempts and earlier audited evidence remain historical, using
older source and verifier schemas. Four MVP attempts failed, the fifth passed its
then-current source and was superseded; the final run matches this source. Source
mutation during attempt two was correctly rejected even though VM stages passed.
Some intermediate revisions are hashes only, limiting historical source replay.

Untested: physical NIC/ISP failures, IPv6/dynamic addresses, optional live preference
failback, sustained/saturated load, production deployment images, whole-VM memory
limits, storage-corruption repair, sudden power loss, actual kernel-stuck I/O and
boot-zero-gap protection. No maximum recovery time or production SLA is established.
