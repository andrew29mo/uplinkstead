# DHCP-mode VM restart validation

Run `e9764f00ec645c79`, source fingerprint
`114835a344600925392a78640c9d464006f63ff9a3317219ea277e4299a251ae`.

[JSON](evidence.json) · [HTML](report.html) · [macOS tests](native-unit.json)
· [Linux tests](linux-unit.json) · [Failed development attempts](development-attempts.json)
· [Procedure and limits](../../docs/DHCP_REBOOT.md)

108 portable tests per platform, identical source/test IDs and zero skips. Nine
existing isolated Linux lifecycle scenarios were rerun, followed by one actual
DHCP-mode orderly VM stop/start workflow. All stages passed, including cleanup.
The report verifier rejects 38 corrupted variants in both normal and optimized
Python. These controls are not 38 additional network/failure experiments.

## What the restart evidence establishes

- A wire-acquired `192.0.2.3` allocation was healthy and forwarding before the
  restart. The installed service/client were frozen; a recorded runtime-only
  `KillSignal=SIGKILL` override prevented shutdown-time graceful deconfiguration.
  This is explicit process fault injection during an **orderly VM stop/start**.
- A fixture-only prerequisite recreated disposable network namespaces/TLS peers.
  Before the formal service started, a read-only journal capture exactly matched
  the old lease/session/deadline. Boot identity changed; no old allocation was
  rewritten by the fixture. The new service used the expected transformed shipped
  unit, no drop-ins, a new InvocationID and new session.
- With no DHCP server running, three observations showed no current lease,
  deadline or healthy flag, no owned address/probe/data routes, and all six guards
  and lookups present. LAN TLS attempts failed. A separate positive control proved
  the main-table backup path usable; subsequent negative tests recorded zero
  backup packets. This is post-service evidence, not a pre-service boot guard.
- A new real wire allocation, `192.0.2.4`, stayed unverified under a controlled
  probe blackhole. Removing the hole allowed fresh TLS quorum and LAN traffic
  through the intended WAN (`10.99.1.1` peer observation).
- Old session, old boot and old revision were separately injected through the
  formal root socket with otherwise current authority. Exact errors plus unchanged
  status and independently read addresses/routes/rules show they did not replace
  the new allocation. Those are synthetic replay requests, not callbacks surviving
  a reboot as live processes.

## Measurements and boundaries

The guest post-start verification routine took **12.82 seconds** in this one run.
It includes intentional observations, failed requests and DHCP acquisition. It
excludes VM stop/start and is **not** downtime, a recovery bound or an SLO.
Host driver stage durations remain separate in JSON/HTML.

Writer RSS snapshots: lifecycle phase **23,844 KiB**; post-restart phase
**23,728 KiB**. They are observations of different service instances, not a
memory-saving comparison or peaks; they exclude DHCP client/kernel/whole VM.
The lifecycle-phase SQLite main file was **8,192 bytes**, excluding temporary
journals, logs and filesystem overhead. No throughput or capacity claim is added.

The VM ended stopped. Owned units, runtime fault, enablement/dependency links,
namespaces and source snapshot were removed, and the VM root network was preserved.
Private logs, generated TLS credentials, SQLite files and VM images remain local.

This does **not** establish sudden power-loss/torn-write/disk-corruption recovery,
protection before the service installs guards, hard kernel lease expiry, long-running
natural T1/T2 renewal, physical ISP behavior or DHCP dual-WAN failover. No static
controller VM result is reused as DHCP evidence. The earlier same-source static
regression pair is historical at `5fcd66b`; it was not rerun at this snapshot.

Three failed development attempts remain failed: SIGSTOP did not prevent graceful
cleanup; missing FIB tables produced partial JSON in the observer; and a report
corruption control removed a builtin rule instead of its intended owned guard.
Their summaries are retained above. The final receipt comes from a fresh full run,
not changing a failed run's passed flag.

```sh
.venv/bin/python -m tools.dhcp_report reviews/dhcp-reboot
.venv/bin/python -O -m tools.dhcp_report reviews/dhcp-reboot
```

Replay using the source revision containing this exact manifest; later source or
test changes intentionally invalidate the current-source correspondence check.
