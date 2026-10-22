# DHCP T1/T2 independent review and matching-source evidence

Run `ecdc78be86e0313b`, source fingerprint
`60c1bec34fde86d7da2195f7481a38d6d56a8db3c1460bd13122c714aea2fa99`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [Attempts](attempts.json) ·
[Design and reproduction](../../docs/DHCP_TIMERS.md) ·
[Historical counterexample](historical-counterexample.json) ·
[Post-run offline controls](checks.py)

## Findings and fixes

Independent source review found no demonstrated T1/T2 arithmetic or xid-boundary
fault. It did reproduce a **report false pass** in commit `8bae55a`: moving the
writer's first withdrawn publication roughly 46 seconds early still passed when
the client's normal expiry log occurred later. The original VM data did not show
that early withdrawal; the deliberately corrupted counterexample is labelled
separately. The verifier now binds withdrawal to the writer's conservative
deadline and requires retention observations through that first publication.

The original ACK-race evidence showed successful renewal but did not force the
important receive ordering. SIGSTOP alone would not exclude a pre-enqueued UDP
ACK. A new isolated regression therefore drops the kernel UDP path (wanB,
UDP 67→68, actual prerouting hook/counter), pauses the real client before a delayed
actual server ACK, observes production Capture quarantine and address removal,
then resumes that same PID/session. ACK identity is joined to the formal hook,
new allocation and fresh selected LAN TLS success.

That stricter scenario initially timed out with the prior unfiltered raw client.
The original raw socket accepted all IPv4 traffic. A mandatory narrow cBPF filter
now excludes unrelated traffic before queueing; attach failure exits. The exact
production C attachment also runs in an independent real-socket contrast below.
This demonstrates an overflow mechanism under the selected burst, not direct
forensic drop measurements from the original failed client socket. It does not
protect against DHCP-shaped floods or arbitrary overload.

## Observed results

- **215 matching-source portable tests per platform**, identical IDs, zero
  failures/errors/skips. Both platforms compile the exact C timer functions;
  actual networking, socket filtering and the complete compiled client run only
  in the Linux VM.
- **Eight Linux VM cases passed:** one actual-kernel socket contrast and seven
  formal-service cases. The external BusyBox 1.36.1 archive and transformed source
  are hash-pinned. Config and binary hashes are read back; compiler version is
  recorded as a version string, not a compiler hash or reproducible-build claim.
- Same-burst contrast: **2,000 unrelated UDP frames plus one ACK** sent to two
  simultaneous sockets, each with kernel readback buffer **65,536 bytes**.
  Unfiltered: **1,932 drops, ACK absent**. Production filter: **zero drops, ACK
  present**. These deliberately bounded test sockets are not the actual client's
  default receive-buffer measurement, and this is not a throughput benchmark.
- Real-client forced ordering passed: client stopped before the actual ACK;
  kernel UDP drop counter positive; Capture pending, address absent and selected
  route withdrawn before resume; same actual ACK then admitted by the unchanged
  PID/session, followed by fresh selected B traffic. No simulated lifecycle
  callback or synthetic replacement ACK supplies the new lease.
- Default **T1=60/T2=105** on a 120-second lease, explicit **10/25** with two
  natural renewal rounds, partial option **T1=8/absent T2**, invalid timer rejection,
  natural broadcast rebinding and a real held old ACK all passed again. Signals
  bootstrap profiles only; subsequent natural transitions are unsignalled.
- The silent-server 240-second lease retained its original identity through
  **2,322 observations**; maximum observed gap **0.140 s**
  (acceptance limit two seconds). Third broadcast retry still left **47.360 s**.
  First observed withdrawal publication was at/after the writer deadline; B's
  address/probe/LAN routes were absent and LAN traffic failed despite viable
  forbidden fallback. Changed-address reacquisition, independent A traffic and
  fenced old ACK replay protection passed. This is sampled runtime publication
  evidence, not an exact kernel-removal timestamp or continuous-forwarding proof.
- **44 automated corrupt-evidence controls** passed, including early withdrawal,
  missing retention, wrong rule/hook/scope, missing client rejection, residual
  string/integer route tables and broken source/build/cleanup evidence. Separate
  post-run controls couple an early withdrawal with a consistent shortened trace
  and a later real client expiry log, requiring the precise deadline rejection.
- VM process RSS snapshots: service **25,504 KiB**;
  clients A/B **1,608 /
  1,612 KiB**. Not peaks;
  kernel/fixture/whole-VM overhead excluded. Scenario time includes deliberate
  DHCP waits; no speedup, capacity or recovery SLO is claimed.
- Guest and outer cleanup passed: owned processes/namespaces/source/build artifacts
  removed, root network unchanged, dedicated VM **Stopped**, source unchanged.
  Raw frames/logs, credentials and external source/binary are excluded. Both
  review attempts are retained; the older six-case receipt remains historical.

## Remaining boundaries

The distro client remains the default. This is a selected external, GPL-governed
client adapter in an MIT Python project. Finite 1..86400-second IPv4 leases only;
no full DHCP/RFC/server interoperability qualification, random timer fuzz,
infinite leases, hostile DHCP, arbitrary capture loss/reordering or unbounded
history. Writer deadlines remain conservative and can precede exact client expiry.
Manual selection/fresh health remain required. Automatic dual-DHCP failover,
continuous forwarding, installed adapter recovery, adapter VM reboot recovery,
boot-zero-gap protection, physical WAN and sudden power-loss recovery are **not
qualified** by this review.

Offline checks (separate from the portable test count):

```sh
.venv/bin/python reviews/dhcp-timer-review/checks.py
.venv/bin/python -O reviews/dhcp-timer-review/checks.py
```
