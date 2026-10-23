# Installed dual-DHCP orderly VM reboot recovery

Run `25afed44b464a4ec`, same-source fingerprint
`516b1db02be989910ad6e7e8e6f4c3bcc55bc7423dfa80a9385165b653cf919d`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [All attempts](attempts.json) ·
[Deployment, fault scope and reproduction](../../docs/DHCP_BOOT.md)

Both platforms passed **284 tests**, no skips, with identical frozen source and
test IDs. Five orderly VM stop/start cases passed with five distinct new Linux
boot IDs. All **28** mutated-evidence controls rejected, including failed/timeout
stages, reused boot identity, missing old journal, nonempty shutdown commands,
policy loss, stale acceptance and false capacity success.

## What was actually exercised

The exact shipped writer and worker unit hashes match the source manifest. The
actual production service, core, Linux backend, compiled qualified DHCP client,
installed hook and capability-free standalone worker perform recovery and routing.
The fixture supplies disposable namespaces, interfaces, forwarding/NAT/return
paths, controlled DHCP servers and TLS targets. It never calls the recovery core,
edits journal policy, or restores product-managed routes on the service's behalf.

A fixture-only systemd timer automatically starts the formal writer using
OnBootSec=25s / AccuracySec=1ms / RandomizedDelaySec=0. Actual trigger values are
retained per boot (about 25 seconds here). The delay avoids Colima host-side
Docker/Lima provisioning interference. It is not a product early-network gate or
an assertion that the network is protected before service startup. Production
interface prerequisites remain the deployer's responsibility.

- **Normal:** normal stop/ExecStopPost produced an empty allocation snapshot in
  the next boot's pre-Agent observation. New service authority then acquired new
  leases and health before successful new TLS traffic.
- **Preserved:** the real writer/clients were frozen, and a labelled runtime-only
  shutdown override used SIGKILL and cleared ExecStopPost. The actual systemd
  D-Bus ExecStopPost property was type `a(sasbttttuii)`, data `[]`. The next boot,
  before production ExecStart, read exactly the same old journal with nonempty
  active allocations. The runtime override was absent after boot. This rules out
  pre-shutdown rollback as the explanation for recovery.
- **Paused:** pause survived boot and new healthy leases. Forwarding stayed
  blocked until an explicit successful resume.
- **Latched:** real alternating edge faults/automatic switches exhausted the
  eight-switch budget, then a formal pause was recorded. New healthy leases after
  boot did not unlock selection. Resume rejected until an explicit acknowledged
  budget reset, followed by resume; old history was not silently aged away.
- **Capacity:** the formal service used an explicitly labelled journal-path
  override on a dedicated 32 MiB ext4 loop image. Actual fill returned ENOSPC 28
  and zero free bytes, and an operator API failed. The same image/journal stayed
  full across reboot. Startup persistence failed, emergency quarantine retained
  the lock/scope contract, worker stayed inactive and retries stopped (one
  automatic restart observed, within the configured three-start limit). Failed
  API/journal state was not relabelled successful. Removing only filler and
  explicitly restarting permitted fresh acquisition/health and new TLS; policy,
  receipts and switch history were retained.

Each new boot was observed with no usable old lease or health. With new DHCP
leases but both edge health paths blocked, LAN traffic remained rejected. A
separate static bypass NIC still reached the same TLS target through B, so the
negative test was not explained merely by an unavailable target. Main routes,
RPDB and a foreign table remained unchanged; wrong-WAN DHCP counters stayed zero.
Old root pause/resume/reset, worker proposal and retired client event requests
rejected before and after fresh forwarding without changing selection or policy.

Native tests exercise the formal core with changed boot identity and failed
persistence. macOS does not execute systemd or Linux routing. Those portable
injections are distinct from the real installed-service VM observations.

## Measurements

| Case | Post-boot driver seconds | Writer RSS KiB | Worker RSS KiB |
|---|---:|---:|---:|
| normal | 19.107 | 25116 | 11808 |
| preserved | 21.642 | 25144 | 11824 |
| paused | 24.959 | 25204 | 11820 |
| latched | 24.000 | 25192 | 11836 |
| capacity | 32.774 | 25196 | 11824 |

Driver time begins when the host can invoke the after-boot checker. It includes
timer wait, negative probes, health waits and explicit repair/policy operations.
It is neither VM boot time, WAN outage duration nor an upper bound. Kernel boot
observation checkpoints and systemd timestamps/trigger receipts are retained
separately. RSS is a Linux VM process snapshot, not peak, host memory or a native
macOS performance comparison. There is no claimed throughput improvement.

## Cleanup and limits

Owned fixture processes/namespaces, installed assets, boot timer/link, state,
loop mount/device and source snapshot were removed. Root-network semantic checks
passed; the VM is Stopped. Individual prior-boot cleanup receipts are retained.

All VM stop/start trials were orderly. SIGKILL/skipped stop cleanup does not
simulate power loss. **Sudden power loss and boot-zero-gap were not tested.**
This boot gate tests ENOSPC, not readonly/SQLite FULL across reboot; the earlier
[storage gate](../dhcp-storage/README.md) covers those separate faults. Arbitrary
corruption/hot-journal repair, physical WAN, general DHCP interoperability,
continuous existing connections and all kernel/I/O interleavings remain outside
qualification. Old-boot budget history is conservatively retained and may require
explicit operator intervention after repeated reboots.

Eight unsuccessful or interrupted development attempts remain failed in the
attempt ledger. Two required separately recorded owned-snapshot cleanup after
strict root-scope failures; their original outcomes are unchanged. Earlier runs
with five successful guest cases but failed report verification are not treated
as qualification or selected as faster measurements. No synthetic diagnostic
receipt is exported as a real observation.


## Review corrections

The review reproduced a fixture cleanup defect: an unowned runtime override
could be removed, and a dangling symlink could be followed during creation.
Creation now uses exclusive, no-follow semantics, with path/device/inode/UID,
boot identity and content hash recorded in an ownership ledger. Unknown, changed
or foreign files are preserved and cause failure. These adversarial file cases
are portable regression tests; the VM run exercises the owned override lifecycle.
A failure to update the ledger after writing the override conservatively refuses
cleanup and needs manual inspection; that partial-I/O window was not injected.

Two additional evidence gaps allowed substituted old final authority/expired
health and a wrong-boot or out-of-range switch charge to pass verification.
The prior raw observations contained fresh authority and correct charges; this
was a validation gap, not observed stale production routing. Guest observations
and report verification now bind current boot, READY epoch/session, allocation
generation, lease/health deadlines and switch charge time. Eight added regression
tests include actual production-core reboot observations and owned-file cases.
Final observation time is sampled with the final snapshot; driver completion is
recorded separately. The five-case VM run above was repeated after these fixes.
The earlier successful run remains historical in the attempt ledger/Git history,
and is not presented as qualification of the revised source.
