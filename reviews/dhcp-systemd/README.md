# Installed dual-DHCP supervision and writer takeover

Run `ad52c54f857b06be`, matching-source fingerprint
`648ec015e1f0c99a4b56583cd6090d0d5465fa099de96d529fc9095bd6b3f012`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [All attempts](attempts.json) ·
[Deployment and reproduction](../../docs/DHCP_SYSTEMD.md)

## What was actually run

The isolated Linux VM installed the exact shipped writer and worker unit files,
with their source/installed hashes checked. Normal-case drop-ins set only the
owned network namespace and frozen package import path. The fixture installed
the exact standalone worker, executable production hook and hash-qualified
external BusyBox client. Configuration and journal used the units' actual
`/etc/uplinkstead`, `/var/lib/uplinkstead-dual` and `/run/uplinkstead-dual` paths;
these paths were verified absent before installation. Existing static/single-DHCP
units were neither substituted nor modified.

| Installed case | Observation | Case seconds |
|---|---|---:|
| Readiness and credentials | Actual Type=notify writer, then non-root worker, new DHCP/health and LAN TLS | 3.777 |
| Orderly stop/start | Old process tree and IPC removed; allocations/selection withdrawn; pause/history retained; old operations reject before and after new forwarding | 5.289 |
| Whole writer SIGKILL | New writer/worker invocation; old processes gone; higher epoch and WAITING/empty allocations before reacquisition; old requests reject; new TLS works | 7.165 |
| Delayed old ip helper | Real inherited lock blocks competitor after writer death; systemd kills old helper before replacement; deferred old ip never executes; fresh B works | 12.850 |
| Startup limiter and explicit repair | Invalid config exhausts the real start limiter; valid config alone remains blocked; explicit writer reset permits recovery without resetting switch history | 6.070 |

The actual installed worker readback is UID **996**, GID **990**, in all four
credential fields; effective/permitted/inheritable/ambient/bounding capabilities
are all **zero**, NoNewPrivs is **1**, and its process is in the policy unit's
cgroup. The root writer's effective/permitted/bounding mask is **0x3400**
(NET_BIND_SERVICE, NET_ADMIN, NET_RAW), NoNewPrivs is **1**. Worker journal access
was denied. The nested control suite separately exercises exact UID authorization,
malicious proposals and kernel/private-channel denials with numeric UID 61001;
it does not replace the installed worker's credential evidence.

## Recovery and fencing evidence

Normal stop and `ExecStopPost` both use production lifecycle/recovery code. The
post-stop invocation does not create clients, clear journal data or reset limits.
A new writer quarantines old DHCP allocations and starts health at WAITING before
servers allow a new acquisition. Real new leases/health are then required before
selection and successful TLS. Whole-writer SIGKILL uses the standard ExecStart,
not a replacement recovery driver.

The separately labelled helper case changes ExecStart to the checked-in VM-only
shim and TimeoutStopSec to three seconds. Linux.run still spawns the actual ip
helper with the writer lock fd. The shim stops before exec, ignores TERM and,
after systemd CONT, waits at most eight seconds for release. After the writer is
killed, a competing flock is denied while that helper remains alive. Systemd kills
it before the replacement is ready; its deferred-ip execution marker is absent.
Every actual kernel operation and recovery decision uses production code. This
qualifies that controlled pre-exec/cgroup case, not every helper/kernel failure.

Old root pause/resume/reset-budget, worker proposals and old client-session loss
hooks are replayed both before new acquisition and after fresh selection in all
three stop/replacement cases. All five requests reject at each checkpoint;
epoch, pause/latch, switch history, selection and operator receipts are unchanged
by them. Legitimate startup DHCP deconfig events may independently advance
revision, so the test does not demand a frozen revision while clients run.

The forbidden main default remains viable through a third fixture-only static
interface: root TLS succeeds through upstream B while stopped LAN TLS fails.
Neither product DHCP address nor owned route is restored for this witness.
Linux removes interface-tied main routes/neighbours when the last IPv4 address
is deleted; relying on that same interface would make a negative-only test weak.

## Measurements and limiter interpretation

One controlled SIGKILL-to-observed-writer/worker-ready-and-IPC interval was
**2.194 seconds**. It is not time to WAN restoration, a repeated latency
statistic, an upper bound or an availability guarantee. Subsequent lease/health
and TLS checks are separate observations. Case durations include server control,
intentional waits and observations; they are not comparative performance results.

VM process RSS snapshots after the SIGKILL recovery/forwarding check:
writer **25,232 KiB**, worker **11,820 KiB**. They are not peaks and exclude clients,
kernel, fixture and whole-VM overhead. No native-macOS-versus-VM speed/RSS advantage
is claimed; macOS runs portable tests only.

StartLimitBurst is **3** in **60 seconds**; RestartSec is **2 seconds**. In this
VM the recorded NRestarts is **1**, while the service-manager log confirms the
start-request limit. NRestarts is not the count of all start requests. Result
remains **exit-code** here, so the gate checks the actual limiter observation,
bounded/stable restart count and repaired-start rejection rather than assuming
Result must be the string start-limit-hit. A failed/inactive worker has no network
write authority. Explicit reset restores service while preserving prior switch
history; the new initial selection adds its normal charged entry.

## Correspondence, failures and cleanup

- **263 identical portable test IDs on each platform**, zero failures/errors/skips.
  New tests invoke production post-stop recovery/SQLite, real notify datagrams,
  notify failure and the renamed-client dispatch path; injected backend/clock
  behavior is portable logic coverage, not Linux enforcement.
- The same frozen source/client runs **five control plus nine automatic VM
  regression cases** in fresh fixtures after the five installed cases.
- **71 corrupted-evidence controls** reject: 57 inherited and 14 installed-specific.
  Normal and optimized Python verification agree. Unit hashes, cross-phase client
  builds, source, credentials, old requests, quarantine, limiter and cleanup are
  checked; HTML exactly renders JSON and standalone test receipts match embeds.
- Twelve recorded workflow attempts are retained: eleven failed during integration
  and the twelfth passed all gates. None of the failures is relabelled a pass.
  Attempts include hook permissions, a production BusyBox argv[0] dispatch defect,
  fixture API errors, invalid fallback assumptions, legitimate revision changes,
  unloaded-unit reset handling and actual systemd CONT/Result semantics.
  BusyBox filename dispatch was independently reproduced with help-only commands,
  fixed in the formal runtime and regression-tested. Raw logs stay excluded.
- Final owned installation files/state, processes and namespaces are removed;
  VM root-network semantics are unchanged, source/build snapshot is removed and
  the dedicated VM is **Stopped**. Existing host accounts are left unchanged;
  a fixture-created account is removed only after ownership checking.

## Material limits

This is **installed process restart**, not VM reboot or sudden power loss. No
boot-zero-gap, initial-interface gate, physical-WAN interoperability, capacity
exhaustion, uninterrupted connections or complete privileged-parser sandbox is
qualified. Storage/kernel failure can prevent post-stop quarantine; it must not
be interpreted as success. DHCP clients/capture and root writer remain trusted.

The invalid-config limiter test starts with guards already installed and both
allocations withdrawn. It does not prove that a fresh host with invalid config
has protective guards. Units do not disable interfaces, and a crash leaves a
supervision/cleanup interval before stale kernel state is removed. Journal latch
recovery is covered portably; the installed crash cases preserve an unlatched
history and do not claim a separate live-latched writer-crash injection.
