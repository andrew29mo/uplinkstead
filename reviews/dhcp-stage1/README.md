# Formal dual-DHCP stage-one validation

Run `8ab8a09f428b2276`, source fingerprint
`c769cb0544513033b4e783f462bb14d40b733204fae676a4b892af6238980e59`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json)
· [Linux](linux-unit.json) · [Development attempts](attempts.json)
· [Runtime, clock contract and reproduction](../../docs/DHCP_STAGE1.md)

## What actually ran

- **193 portable tests on each platform**, identical source/test IDs and zero
  skips/failures/errors. New tests invoke the formal packet tracker, SQLite core,
  finite inbox and runtime. Actual routing is separately Linux-qualified; native
  tests inject a clock/backend rather than pretending macOS has Linux networking.
- **Nine actual Linux VM scenarios** launch `python -m
  uplinkstead.dual_dhcp_service` and its shipped executable hook. The formal service
  starts/supervises its own BusyBox clients, performs AF_PACKET observation and
  drives its own writer. The fixture does not directly call `DualLifecycle`.
- Two real wire leases and new LAN TLS over A; B SIGKILL gives a new PID/session
  while A's session/generation/allocation/deadline/selection remain unchanged.
- A real B renewal is processed while B's slow failed probe is still in flight.
  The recorded renewal observation took **0.209 s** including polling/IPC. This is
  one controlled observation, not a scheduling/failover bound or capacity result.
- A whole-service one-second SIGSTOP creates real packet/intake backlog. The
  retained event has REQUEST/ACK observation lower bound **16.269079590**, hook
  **16.354440173**, processing **17.313157299**, and expiry **136.269079590** seconds
  on CLOCK_BOOTTIME. The 120-second lease was not restarted at processing time.
  These are conservative capture lower bounds, not exact packet-send timestamps.
- Retired-session input leaves state/network/expiry unchanged. A current-session
  renewal without matching wire proof retires/reacquires only B while A forwards.
- All **48** stale flood attempts remain accounted: **41 service rejections,
  seven pre-send transport rejections, zero accepted**. Connect EAGAIN is not
  relabeled a server rejection; no retries/timestamp rebasing occur.
- All **48** synthetic current-authority loss attempts remain accounted: **two
  queued, 42 service rejections, four pre-send transport rejections**. Actual B
  queue overflow increments once; peak observed depth is **two** against global
  capacity **four**, with two reserved slots per link. B is retired/reacquired;
  A's allocation identity remains unchanged. This is not general traffic fairness.
- Both clients are SIGSTOPed and both DHCP servers stopped. The actual deadlines
  expire with those same clients still stopped; both allocations and the selected
  route are withdrawn, and LAN TLS fails. The **120.038 s** scenario includes the
  intentional lease wait. A client deconfig cannot explain the withdrawal.
- **19 corrupted-receipt variants reject** under normal and optimized Python.
  HTML exactly corresponds to JSON. Owned process/namespace cleanup, root network
  semantic preservation, source removal and stopped VM all passed.

The fixture uses queue capacity four, probe interval 0.1 s, restart delay 0.2 s,
one good round and ten-second health freshness. These explicit test choices are
not measurements of optimal production policy.

## Corrections and evidence layers

Capture uses ETH_P_ALL to observe outgoing REQUESTs as well as incoming ACKs;
ordinary/non-DHCP frames do not kill observation. A receive-queue-empty timestamp
is sampled before the EAGAIN-producing recv and retained while draining backlog.
Malformed/ambiguous evidence cannot create a later lease deadline.

Independent review also found a two-ACK ordering gap after an earlier passing
trial. The final core assigns each ACK proof its own version, keeps pending-new
allocation sticky and rejects older queued proofs. Two targeted formal tests
challenge ACK1-queued/ACK2-observed and matching-old-proof/global-new-version
mislabeling. These tests are portable runtime/parser counterexamples; the live
VM backlog case contains one renewal, not a claimed two-ACK fault injection.

Earlier failures and the superseded passing trial are summarized in
[attempts.json](attempts.json). Raw development logs remain local/ignored;
intermediate source hashes do not imply every intermediate source is archived.
The retained final source is reproducible from its Git revision and manifest.

## Memory and limitations

One initial live `VmRSS` snapshot records **23,992 KiB** for the formal service and
**1,356 KiB each** for clients A/B. These are individual process snapshots, not
peak/PSS/process-tree/whole-VM memory, and exclude kernel capture buffers, fixture
servers, filesystem/cache and VM overhead. No reduction or performance advantage
is claimed. All scenario/host stage durations remain separate in JSON.

Linux ARM64 VM, kernel 6.8.0-117-generic, Python 3.12.3, BusyBox 1.36.1 distro build
and dnsmasq 2.90. Five namespaces share one kernel; three TLS probe ports share
one process. External upstream NAT/return routes are fixture provisioning.

This is a formal **foreground** stage-one service with explicit root selection,
not automatic failover, installed systemd or new VM-reboot qualification. Old
exploration reboot evidence is historical. Naturally timed T1/T2 for this formal
runtime, full writer-SIGKILL/process-tree recovery, physical WANs, sustained load,
power loss, disk corruption, hard kernel deadlines and boot-zero-gap remain
unqualified. The conservative lower bound can shorten lease availability; it is
not exact RFC timestamp measurement. No production SLO/readiness follows.

No fixture private keys, raw private logs/network snapshots, SQLite state,
downloaded binaries or VM images are exported here. First-party additions remain
MIT; no third-party dependency code/binary was bundled.
