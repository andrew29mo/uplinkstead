# DHCP-mode orderly VM restart recovery

This check uses the installed `uplinkstead-dhcp.service`, the formal root socket,
BusyBox client, shipped hook, production `Lifecycle` and Linux backend. It is not
a replay of the static controller's restart result.

## Evidence chain

1. Restore the isolated DHCP server after the expiry/fault cases, start the
   installed service and obtain a real wire lease. Require healthy status, an
   active forwarding route and new LAN TLS traffic through the declared uplink.
2. Freeze the service and its client with SIGSTOP. Read the actual SQLite journal;
   it must still contain the live allocation, session and deadline. The shipped
   unit normally resumes stopped processes for graceful SIGTERM cleanup. To
   prevent that cleanup from invalidating this recovery test, a recorded fixture
   drop-in under `/run/systemd/system` sets `KillSignal=SIGKILL` for this shutdown
   only. It disappears on reboot. This is an explicit forced-process-termination
   fault followed by **orderly VM stop/start**, not unchanged graceful-stop behavior.
3. Enable the exact transformed shipped service for the next boot. A fixture-only
   required/ordered systemd unit recreates the disposable namespaces and TLS peer.
   Before production ExecStart, it reads the journal without opening Lifecycle.
   Full equality with the pre-shutdown journal is required. It neither repairs the
   state nor starts a DHCP server. The new service has no drop-ins. Thus a shutdown-time rollback cannot explain
   the result. Boot IDs must differ.
4. Observe the automatically started service with a different InvocationID and
   session. Before any new DHCP server is started, repeatedly require no current
   allocation, no expiry/healthy state, no DHCP address or owned probe/data routes,
   and all six owned lookup/terminal rules. New LAN TLS attempts must fail. A
   positive control first proves the alternate main default works, then its
   counter is reset: waiting-period attempts must put zero packets on that path.
5. Start a real DHCP server offering a different address. Temporarily blackhole
   probe traffic so LEASED/UNVERIFIED can be observed, with no LAN default. Remove
   that fixture hole, then require fresh quorum and successful LAN TLS traffic on
   the intended WAN. The fixture never sets a healthy flag or production lease.
6. Stall client callbacks while separately injecting an old session, old boot
   identity and old revision through the formal socket. Other authority fields
   remain current. Require the exact retired-session/stale errors and unchanged
   status plus independent address/route/rule readback.

The test-only topology dependency is explicit. It is not a production boot guard
or an unchanged native distribution-package installation. Fixture service paths,
namespace/environment and private directories use the same declared transformation
as the other DHCP scenarios; actual file hashes and active service identity are
checked. Production runtime code is not replaced by a fault wrapper.

## Measurements and failure behavior

The JSON retains pre-shutdown, pre-service and post-start observations, identities,
full source fingerprint, service/fixture hashes, wire reacquisition, stale-event
results and cleanup. HTML is rendered directly from that JSON. Missing evidence,
nonzero exits, timeouts, source changes, false identity/reused journal assertions,
allocation/health reuse, backup packets or failed cleanup cannot pass. Corrupted
report controls challenge those conditions separately from networking tests.

The post-start `seconds` field measures the guest verification routine, including
intentional waiting, test failures and DHCP reacquisition. It excludes host-side
VM stop/start time; those durations are separate driver stages. Neither is a
recovery SLO or continuous outage measurement. Writer RSS is a process snapshot,
not peak RSS, DHCP-client memory, kernel memory or VM overhead. SQLite bytes refer
to the main file in the earlier lifecycle phase, not whole-filesystem disk usage.

## Limits

This establishes recovery for one controlled orderly VM restart with a frozen
service and a valid persisted lease. It does not test sudden power loss, torn
writes, physical disk corruption, live ISP/DHCP infrastructure, or continuity
before the service installs its guards. A stopped/stuck service or exhausted
systemd restart limit can prevent recovery. It does not provide a kernel lease
expiry guarantee, uninterrupted existing connections or DHCP dual-WAN failover.

See [the retained receipt](../reviews/dhcp-reboot/README.md) for actual results and
[DHCP operations](DHCP.md) for ownership and deployment requirements.
