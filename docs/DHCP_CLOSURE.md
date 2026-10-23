# Reproducing the DHCP MVP closure

Use macOS/Python >=3.12 with Colima/Lima, virtualization and network access for
Ubuntu package installation. The runner creates a **new** dedicated
`uplinkclose-*` profile with 2 CPUs/3 GiB RAM, no host mounts, and deletes that
profile and its container-data disk even after failure. It refuses an existing
profile or retained same-name data disk. It does not reuse
the older `relay` VM. Never run guest fixtures on the host or a production machine.

Build the wheel and obtain the external hash-qualified BusyBox archive as in
[installation](DHCP_INSTALL.md). The runner builds the adapter inside Linux and
records its source/transformation/config/compiler/binary provenance. Supply an
absolute toolchain path containing Colima and Lima. Example:

```sh
.venv/bin/python -m pip wheel --no-deps --wheel-dir results/closure-wheel .
.venv/bin/python -m tools.dhcp_closure_validate \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --archive /path/to/busybox-1.36.1.tar.bz2 \
  --wheel results/closure-wheel/uplinkstead-0.1.0-py3-none-any.whl \
  --profile uplinkclose-new-run \
  --output results/new-closure
```

The runner tests a frozen source snapshot on macOS and Linux. It extracts and
executes the installation shell block in DHCP_INSTALL.md verbatim with explicit
trusted paths; doc/recipe/wheel/module/unit/client hashes are recorded. Formal
services use installed site-packages after checkout product modules are moved
out of import reach. A namespace-only systemd drop-in supplies network isolation;
no product ExecStart replacement, PYTHONPATH override or boot timer is added.

The fixture alone provides DHCP/TLS servers, forwarding/NAT/return routes, faults
and a separate positive main-path witness. It never invokes product recovery or
selects on the service's behalf. A uses dnsmasq with a 120-second lease and T1=20,
T2=90; B uses the isolated packet server with a 120-second lease and T1=15, T2=90.
There are no renewal signals during the soak. These are accelerated controlled
servers, not general server interoperability or real ISP coverage.

After initial acquisition, sample for 40 seconds, then perform six cycles of
15-second stable period, active-path blackhole, observed automatic selection,
remove fault, and 15-second recovery. End with a 300-second tail. Case times
include waits and checker work; no outage SLO is inferred. The raw cycle field
`selected_at` is sampled after the 15-second recovery settlement/checks; it is
a driver completion checkpoint, not the kernel switch instant or outage latency. All cycles and failed
attempts remain visible. Stop/start and operator tests occur **after** sampling;
resource analysis requires the same four service/client process identities
throughout the series, so a restart cannot disguise growth.

Every approximately two seconds, sample writer, worker and both DHCP clients:
RSS, FD, threads, process identity, service-cgroup process count, state-file bytes,
queue bounds and selected authority. Compare comparable stable samples (baseline,
steady, recovered and tail), keeping fault samples in raw evidence. Report
first/last-third median, min/max and linear slope. Predeclared regression limits
are writer RSS +4096 KiB, worker +1024 KiB, each client +512 KiB, FD/threads median +2. Writer sampled-maximum FD/threads limits are 24/13 (two links,
three concurrent TLS targets each, two outer probe workers plus capture/intake/
control/main threads); worker/client sampled-maximum limits are 8/2. Short-lived probe
concurrency must not be mistaken for retained resources. RSS stable maxima must
also fit their declared allowance. The five-minute tail separately requires at
least 100 samples spanning 250 seconds, RSS first-to-last-third median growth
<=256 KiB for writer and <=64 KiB for each other process, with no positive
FD/thread median delta. Main DB must fit 8 MiB, product
state files 16 MiB, queue 8, and bounded diagnostic rings 16. Initial DB allocation
and retained switch/receipt state may grow within these limits; that is reported,
not hidden as a zero-growth result. Short-run allowances do not prove leak freedom.

RSS values are per-process VM observations; shared pages can be counted repeatedly.
They exclude VM overhead, systemd journal, fixture/server logs and whole-host cache.
CPU utilization is not measured; the VM CPU count records allocation only.
Cgroup process counts may briefly include route helpers. The report does not
claim peak RSS or a comparison against native macOS. The sampler must have no
errors and enough samples/duration, and must not observe hidden service restarts.

Actual CLI status/pause/reset/resume, stale tokens and formal stop/start are
checked afterward. Normal stop withdraws DHCP allocations, rejects LAN traffic
while the independent main-path witness succeeds, and reaps old processes.
Restart must acquire new authority and health; old epoch operations reject.

Nonzero/timeout stages, changed source/doc, failed checks or cleanup never qualify.
Only sanitized JSON/HTML and portable receipts are retained publicly; keys, wheel,
client binary, raw packets/logs and VM disks remain outside Git. The newly created
VM and its data disk are deleted, and their absence is checked. Sudden power loss, VM reboot and boot-zero-gap are not exercised by
this run. Prior [orderly reboot evidence](DHCP_BOOT.md) remains a separate source-bound gate.

## Review findings and workload boundary

The initial short run used T1=10/5 and its writer FD/thread peaks legitimately
exceeded the initial median+2 peak assumption. A longer run reached B's
64-transaction capture-history limit: the service replaced its client session
and required new admission/health. That is actual observed capacity retirement,
not a same-client resource pass. The writer's tail RSS median also rose by 312 KiB,
exceeding the declared 256 KiB allowance. Both runs remain failed in the attempt ledger.

The dual-DHCP runtime now reuses one bounded six-target executor across probe
rounds, shutting it down after the two outer workers finish. This retains up to
six idle target workers between rounds instead of tearing them down, trading
thread churn for a predictable resident pool; no lower RSS baseline is promised.
Fresh sockets, source/device/mark binding, TLS authentication, nonce validation and health
authority are unchanged. Standalone/static probe calls retain their owned
per-call executor. Portable tests check actual runtime scheduling/thread reuse,
concurrency across both links, cleanup and injected-probe compatibility; the VM
uses actual fresh TLS and the installed implementation.

The final same-client control uses slower natural T1 values so the bounded
nine-minute observation stays below 64 transactions per session, without enlarging
or evicting security history. Earlier faster runs remain recorded. Because both
probe scheduling and lease cadence changed, this is **not** a controlled before/
after attribution of RSS improvement to the executor change. Passing this control
does not qualify long-term client rollover, capacity longevity or endless
renewal without interruption/budget effects. Do not tune production renewal
intervals solely to reproduce a benchmark.

The first fixed-executor trial still failed: one resource sample raised
`StopIteration` while enumerating process details. The exact PID was not retained.
Source inspection identified that full `/proc` inspection of transient cgroup
helpers could read a zombie without VmRSS. The observer now counts kernel cgroup
membership without reading each helper's RSS; four long-lived process resources
are still inspected and must retain identity. Missing active cgroups fail, and
stopped cgroups must be empty. The failed run's valid samples are diagnostic only;
one observer error does not become a successful receipt.

The first passing full run deleted its VM/rootfs but Colima's default teardown
retained a separate container-data disk. Final teardown uses `delete --data
--force`, verifies disk absence and refuses an existing same-name disk before
creation. Earlier disks from this task were removed with a separately retained
scoped receipt; the existing relay profile remained stopped and was not deleted.
The final source-bound run repeats the whole gate after this cleanup change.
