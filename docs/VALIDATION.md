# Current formal dual-DHCP stage one

[Formal service JSON/HTML and reproduction](../reviews/dhcp-stage1/README.md),
run `8ab8a09f428b2276`, source fingerprint
`c769cb0544513033b4e783f462bb14d40b733204fae676a4b892af6238980e59`.

- **193 same-source tests per platform**, matching IDs and zero skips.
- **Nine actual foreground-service VM scenarios**: real leases/data, independent
  B supervision, slow-probe/event overlap, real backlog REQUEST-based deadline,
  stale authority, absent wire proof, separate transport/server flood rejection,
  observed finite queue overflow and actual lease expiry with stopped clients.
- **19 report corruption controls** reject normally and under optimized Python;
  JSON/HTML agree. Owned cleanup/root preservation/source removal/stopped VM pass.
- Service RSS snapshot **23,992 KiB**, clients **1,356 KiB each**; VM-only snapshots,
  excluding kernel/fixture/whole-VM overhead. No performance superiority claimed.

Two-ACK ordering counterexamples are formal portable tests, not live VM two-ACK
injection. Foreground service is not installed systemd/boot qualification or
automatic failover. Naturally timed T1/T2, full writer-death process-tree recovery,
physical WANs, hard deadlines, power loss and zero-gap remain unqualified. Older
receipts below keep their own source identities and are not new service regressions.

# Historical dual-DHCP technical explorations

[Retained JSON/HTML and procedure](../reviews/dual-dhcp-explorations/README.md),
run `55936aa4724bd1de`, source fingerprint
`440e7f89ba76343924d068108cfb5116cb751e13b2d537b889cd0ff8fd99ba9d`.

- **151 same-source portable tests per platform**, identical IDs, zero skips.
- **12 isolated Linux VM scenarios**: two wire leases, inactive renewal/client
  isolation, positive main fallback/missing probe route, both blackhole directions,
  synthetic and actual wire overlap, natural T1 on both WANs, wire option 121,
  process restart fencing and actual partial backend write/quarantine.
- Separate actual orderly VM stop/start: changed boot, unchanged pre-core journal
  hash, old allocations not replayed, new wire acquisition and fresh TLS forwarding.
  Separate synthetic session/boot challenges leave state and actual network unchanged.
- **23 corruption controls** reject in normal/optimized Python; JSON/HTML agree.
  Owned cleanup/root network semantic preservation/source removal/stopped VM pass.
- Post-recovery core driver RSS snapshot **23,592 KiB**; main SQLite **8,192 bytes**.
  VM-only, not peak/tree/whole-VM memory, with no performance superiority claim.

This is a formal core/backend exploration driven manually, not a shipped dual
DHCP service or automatic-failover benchmark. Production queues/supervision,
exact lease-time origin, natural T2, live delayed network helper takeover and
installed dual-service boot remain unqualified. Power loss and boot-zero-gap are
untested. Older single-DHCP/static receipts below retain their original source
identities; they do not establish new installed-service regressions at this source.

# Historical reviewed single-DHCP validation

[Reviewed DHCP lifecycle and VM restart receipt](../reviews/dhcp-reboot-review/README.md),
run `2d40cc540f51c289`, source fingerprint
`472aaede93793df9b014c22eba67653bdabe050ad4f901087c6ac7ecde46ba4d`.

- macOS/Linux: **113 portable tests each**, identical source/test IDs, zero skips.
- Nine lifecycle scenarios plus an actual orderly DHCP-mode VM stop/start passed.
  The retained pre-service journal excludes graceful pre-shutdown lease clearing.
  Formal-service startup admission additionally checks actual backend emptiness
  **before client creation**, with journal PID/boot/invocation and initial revision
  evidence; the first client deconfig cannot explain this observation.
- Server-off waiting, different wire acquisition, unverified/fresh health and
  separately timed stale session/boot/revision challenges passed. Exactly the
  supported rules are required, including absence of foreign priority bypasses.
  The backup counter excludes only the recorded root positive-control TCP tuple;
  all other target flows remain counted. Actual nftables expressions are verified.
- **47 report corruption variants** reject under normal and optimized Python.
  JSON/HTML match. Owner/inode cleanup preserves foreign objects and removes owned partial creations
  in tests; actual VM cleanup, root network preservation and stopped state passed.
  Review development failures remain failed, with causes/uncertainty retained.
- Post-start guest verification: **9.98 s**, including intentional waiting and
  acquisition; host VM durations are separate. This is not downtime or a recovery
  bound. Writer RSS snapshots: **23,916 KiB** lifecycle / **23,720 KiB** post-restart,
  excluding client/kernel/VM, with no peak/reduction claim. Lifecycle SQLite main
  file: **8,192 bytes**, excluding temporary journal/filesystem overhead.

See [review findings](DHCP_REBOOT_REVIEW.md) and [procedure](DHCP_REBOOT.md).
Sudden power loss, torn writes, disk corruption, continuous early-boot protection,
physical ISP behavior and long-running natural T1/T2 renewal remain untested.
There is no hard kernel expiry, transparent connection migration or production SLO
claim. DHCP is separate single-uplink mode. Older receipts below remain historical;
the old static-mode VM run is not a new static regression at this source revision.

# Historical first DHCP VM restart validation (`7f836de`)

[DHCP lifecycle and VM restart receipt](../reviews/dhcp-reboot/README.md), run
`e9764f00ec645c79`, source fingerprint
`114835a344600925392a78640c9d464006f63ff9a3317219ea277e4299a251ae`.

- macOS and Linux: **108 portable tests each**, same source/test IDs, zero skips.
- **Nine lifecycle scenarios** plus **one actual DHCP-mode orderly VM restart**
  passed. A shutdown-only forced-process-termination fixture retained a live lease;
  pre-service journal equality excludes graceful pre-shutdown withdrawal as the
  explanation. New boot uses the original transformed shipped service without
  the runtime fault drop-in. See [the procedure](DHCP_REBOOT.md).
- With the DHCP server offline, three post-service observations showed no old
  allocation/health, empty owned routes and retained terminal guards. A usable
  alternate path was positively established; LAN failures did not borrow it.
  A different real wire lease required new health before forwarding. Old session,
  boot identity and revision requests left the new configuration unchanged.
- **38 report corruption controls** reject, with normal and optimized verification
  passing. JSON/HTML correspond. The VM root network was preserved, owned objects
  and source removed, and the VM stopped. Failed development attempts remain failed.
- Post-start verification routine: **12.82 s**, including intentional waits,
  negative requests and reacquisition; VM stop/start is separately recorded. This
  is not an outage measurement or recovery SLO. Writer RSS snapshots were
  **23,844 KiB** in the lifecycle phase and **23,728 KiB** post-restart, excluding
  client/kernel/VM and without a peak or reduction claim. Lifecycle-phase SQLite
  main file: **8,192 bytes**, excluding temporary journal/filesystem overhead.

DHCP remains separate single-uplink mode. Sudden power loss, torn writes, disk
corruption, pre-service boot protection, physical ISP behavior and long-running
natural T1/T2 renewal are untested. No hard scheduling/lease-expiry or uninterrupted
connection guarantee follows. Latest-delayed callback tests use synthetic past
timestamps; old-authority VM requests use synthetic IPC replay, not live old-boot
callbacks. Older static-mode VM results below are historical and do not stand in
for DHCP-mode reboot evidence or a new static regression at this source revision.

# Historical DHCP audit and static regression

At commit `5fcd66b`, the reviewed DHCP lifecycle and existing static dual-uplink controller were checked
against the exact same source manifest, fingerprint
`18b9518ae1cbaaa8598c996bf73d3c4e8576508c02a6ede7745c1237cc652caf`.

- [DHCP review](../reviews/dhcp-audit/README.md): run `52181356e66119f7`, 104 portable
  tests per platform, nine isolated Linux scenarios and 23 report corruption
  controls. Installed-service restart, valid/unsupported/latest-delayed callbacks,
  expired status, stale sessions, active-route expiry with stalled callbacks and
  partial backend recovery are covered at their documented layers. Some fault
  inputs use synthetic IPC/time or direct-core injection; these are labeled.
- [Static regression](../reviews/dhcp-audit-static/README.md): run
  `887f7604f7979e60`, same 104 portable tests, 27 existing Linux scenarios and 36
  report corruption controls. Installed services and static-mode orderly VM reboot
  recovery passed. The single low-load trial records 4/20 vs 14/20 successes;
  earlier 13/20 observations remain historical and do not establish a trend.
- Both runs verify correspondence and owned cleanup, leave the dedicated VM
  stopped and separate Linux VM measurements from macOS portable validation.
  The DHCP writer VmRSS snapshot is 23,916 KiB (client/kernel/VM excluded); SQLite
  main file is 8,192 bytes (temporary journal/filesystem excluded).
- [Review findings](DHCP_REVIEW.md) distinguish runtime defects from verifier gaps.
  Earlier DHCP receipts did not establish active-route expiry and are superseded
  for that claim; their original JSON/HTML are preserved.

At that revision DHCP remained a separate **single-uplink** mode. Its VM reboot
and sudden power-loss recovery were not tested; only process restart and portable
changed-boot logic were covered. Latest-delayed callback tests inject past timestamps; they do not measure
real scheduler stalls. Static-mode VM reboot cannot establish DHCP reboot behavior.
Neither run establishes physical-ISP reliability, transparent TCP migration,
sustained throughput, hard expiry scheduling or a production SLA. Read
[DHCP deployment/limits](DHCP.md) before reproducing.

The earlier receipt and measurements below remain historical, unchanged in their
original files. Their 81-test counts and older source fingerprint are not the
current validation matrix.

# Historical MIT-adoption static MVP validation

Run **ebff911bee98054a**, source fingerprint
`8d888c2acccf3e46af48f855b0d8b61d59ca03dd16d4bfef13cb0bbf798117b3`.

[JSON](../reviews/licensing/evidence.json) · [HTML](../reviews/licensing/report.html)
· [macOS](../reviews/licensing/native-unit.json) · [Linux](../reviews/licensing/linux-unit.json)
· [License/package review](../reviews/licensing/review.json)
· [Earlier audit attempts](../reviews/mvp-audit/attempts.json)

LICENSE and package license metadata are part of this source manifest. The
11 runtime modules match the pre-license package byte for byte; the matrix was
rerun so the retained snapshot and metadata also match the current MIT source.

## Observed qualification

- **81/81 portable tests on both macOS and Linux**, identical test IDs and source
  manifest, no skips/failures/errors. Native macOS does not run a routing backend.
- **27 actual Linux namespace scenarios**: the 19 reviewed core exploration scenarios
  plus installed-service privilege, safe lifecycle, storage bounds, lifecycle write
  failure recovery, bounded systemd restart, identical-schedule benchmark, a large
  optional peer response and delayed same-selected resume.
- **36 report corruption controls rejected**, including privilege escalation,
  unsafe resume, missing attempts, altered arrival schedule, failed persistence and
  absent restart-limiter evidence, dead reboot service, receipt/latch contradictions,
  incorrect baseline path, replacement measurement process and late fault insertion. The report also verifies under Python `-O`;
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
MVP service cases exercise the installed units; bounded storage, lifecycle I/O
faults and delayed-resume cases invoke the formal core directly, as detailed below.
The benchmark leaves a fixture-set latch for the final reboot test; that write is
explicitly not evidence of budget exhaustion. Actual exhaustion is independently observed in the alternating-fault
core case, with complete timings/history and all failed LAN requests retained.

## Controlled traffic trial

Both modes start from healthy A and replay 20 intended arrival offsets at 0.5-second
intervals. A forwarding blackhole is installed before request index 4 at an
intended offset of 2 seconds and retained through that mode's completion. Eight
worker slots submit open-loop scheduled TLS requests; actual start/end offsets and lateness are kept,
including failed and deadline-expired requests. This is low-load fault recovery,
not a saturated router-throughput benchmark.

| Mode | Successful / attempted | Failed | Useful requests/s | All-attempt E2E p95 ms | Writer / policy RSS KiB | Main DB bytes |
|---|---:|---:|---:|---:|---:|---:|
| fixed_primary | 4/20 | 16 | 0.379 | 1047.2 | 23912 / 20880 | 57344 |
| automatic | 13/20 | 7 | 1.364 | 1034.2 | 23948 / 20880 | 65536 |

Useful requests/s divides all successes by actual complete-trial duration; failed
requests remain in the denominator's elapsed window. End-to-end latency starts at
the intended arrival and includes fixture client-process startup, TCP/TLS and
failure timeout. p95 uses nearest rank over all 20 attempts, including failures.
RSS is an after-trial `/proc` snapshot for each service, not peak/PSS/whole-VM memory.
DB bytes refer only to the SQLite main file, not rollback journal, filesystem or VM.
Raw observations support rechecking these calculations; no speedup ratio is claimed.
The collector also records actual fault insertion offsets and verifies each
writer/policy PID and InvocationID remains the same across its trial. Both modes
require pre-fault successful A traffic; fixed successes stay A, and automatic
post-fault successes must use B. These checks qualify this controlled fixture, not
all future traffic or proof against a malicious producer.
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

## Additional review evidence

- One target returns a valid ~12-KiB UTF-8 JSON body with a 12,000-byte optional
  peer field. The installed services retain two-vote quorum on both links; A's
  subsequent blackhole causes a successful new LAN request over B without replacing
  the writer. Oversize is a target failure, not a complete-sample failure.
- Delayed same-selected resume stops the services and uses the formal Controller,
  Writer, real probes and backend. Delaying an actual durable save past freshness
  rejects mode activation; reopen confirms PAUSED and unchanged B. This is direct
  core fault injection, not a fault sent through an installed RPC service.
- Manual budget expiry and cross-boot accounting are portable tests; no actual VM
  clock change or long idle interval is claimed. A persistent latch remains binding.
- Native verifier fixtures independently challenge dead-unit, changed receipt/latch,
  wrong path, replacement process and late-fault contradictions. They are synthetic
  check tests, not runtime measurements.

## Environment, history and limits

Colima VZ Linux ARM64, four CPUs/6 GiB configured, Linux 6.8.0-117-generic,
Python 3.12.3 and systemd 255. All six namespaces share one kernel/failure domain.
The three TLS target ports share one fixture server. No independent ISP claim.
The post-reboot writer RSS snapshot was `VmRSS:	   23828 kB`.

Initial exploration and first-MVP evidence remain historical, using their original
source and verifier schemas. [MVP_REVIEW.md](MVP_REVIEW.md) records the reproduced
review defects and the distinction between missing verifier checks and the original
consistent raw observations. Both audit runs passed; the first is superseded only
by a more precise UTF-8 native fixture, followed by a full same-source rerun. Earlier
failed MVP attempts remain failed. Some intermediate old revisions are hashes only,
limiting historical source replay. MIT adoption then reran the same matrix with
the license and metadata included in the source identity. Pre-license receipts
remain unchanged and are labeled historical.

Untested: physical NIC/ISP failures, IPv6/dynamic addresses, optional live preference
failback, sustained/saturated load, production deployment images, whole-VM memory
limits, storage-corruption repair, sudden power loss, actual kernel-stuck I/O and
boot-zero-gap protection. No maximum recovery time or production SLA is established.

## Explicit DHCP timer adapter

The [T1/T2 validation workflow](DHCP_TIMERS.md) builds an external pinned client
and tests the same manifest on native macOS and isolated Linux. It separately
records natural unicast/broadcast timer transitions, invalid ACK rejection,
retry retention through absolute expiry and changed-address reacquisition. Its
foreground/manual-selection scope does not replace installed-service or reboot
qualification; earlier receipts retain their original source and scope.
