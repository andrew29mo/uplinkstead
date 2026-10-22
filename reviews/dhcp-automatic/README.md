# Automatic dual-DHCP selection: milestone 1

**Historical run; superseded by the [reviewed evidence](../dhcp-automatic-review/README.md).**
The original raw data supports ACK-race recovery with fresh quorum and unchanged
budget, but its verifier accepted missing quorum/old health or an extra budget
record in that recovery case. The new review enforces these conditions and adds
an expired-SUSPECT boundary regression. The original HTML also inherited a sentence
denying any automatic failover claim. Raw receipts/HTML are preserved as generated;
these qualifications and the new report take precedence over that wording.

Accepted run `ef28b81686a296b5`, matching-source fingerprint
`b5a3d5f93525dd3938d8f222881c7a90d618b33aa4a454e84224984161d920cc`.

[JSON](evidence.json) · [HTML](report.html) · [macOS](native-unit.json) ·
[Linux](linux-unit.json) · [All attempts](attempts.json) ·
[Contract/reproduction](../../docs/DHCP_AUTOMATIC.md)

## What is implemented

Opt-in automatic initial selection and sticky failover use the formal runtime,
SQLite lifecycle, real wire intake and pinned TLS health. Initial selection and
cross-WAN/same-generation reselection consume existing authoritative budget;
new-generation same-WAN lease recovery remains free and separately bounded.
Candidate hold, withdrawal grace and no automatic preemption/failback avoid
unnecessary switching. Pause/latch prevents selection, never safety withdrawal.

Selection checks capture/intake stamps before and after actual writes. A new ACK
or loss observed during a write triggers real withdrawal and health invalidation
before publication. Delayed operator tokens and old-generation probe results
cannot authorize a newer selection. Later packets still require the next runtime
step: these checks are not an atomic packet/kernel transaction.

A formal regression found and fixed an existing health transition defect:
HEALTHY→SUSPECT→one successful round previously became UNVERIFIED and withdrew an
already-qualified selected route. The new test failed with `active=None` before
the fix. Fresh success now repairs that still-selected, fresh generation without
withdrawal; backup/new/expired generations do not receive this exception.

## Actual validation

**239 identical-source portable tests pass on each platform**, identical IDs and
zero failures/errors/skips. Thirteen new tests exercise the production runtime
and SQLite lifecycle using controlled time and an IO double. They cover hold,
sticky failover, expiry, pause/latch, restore-rate saturation, ACK/loss write
interleavings, delayed operator/probe results and SUSPECT recovery. They are not
Linux routing or reboot evidence by themselves.

**Eight service/fault VM cases plus one fixture control pass:**

| Case | Observed result | Seconds |
|---|---|---:|
| Automatic initial A | A becomes usable first; real A LAN TLS; one budget record | 4.520 |
| TLS fixture control | Two TCP-only connections do not block concurrent legitimate TLS | 0.071 |
| A upstream blackhole | Automatic fresh B selection and real B LAN TLS; history becomes two | 2.452 |
| Four natural B renewals | New generations/fresh health; four B TLS requests; history stays two | 17.273 |
| Real B release | Actual client deconfig; automatic A; old operator request rejected without mutation | 0.928 |
| SUSPECT recovery/no preemption | One failed A round observed with route retained; successful recovery keeps route and three budget records despite healthy B | 2.401 |
| Both down/budget latch | Both-down withdrawal; fourth charged selection followed by exhausted cross-WAN attempt; fresh healthy B renewal cannot bypass latch | 6.343 |
| ACK during B write | Queued real ACK invalidates written B selection; new-generation health restores B without another budget charge | 2.898 |
| Loss during B write | Actual client release/deconfig invalidates B write; B allocation withdrawn; fresh A recovery and actual A traffic | 3.191 |

The six normal service cases launch the shipped module without a backend override.
A uses a long dnsmasq lease; B uses the deterministic local DHCP server. B replies
are initially withheld to make A eligible first; the fixture does not assume A
wins a response-speed race. Simultaneous eligible preference is portable coverage.
No successful selection is driven by a fixture `choose` call.

The two write-race cases use an explicitly labelled test-only backend wrapper.
It calls the complete production select/write/readback, then pauses before writer
completion. No health, lease acceptance or kernel result is mocked. Real client
SIGUSR1/SIGUSR2 drives ACK-backed renewal/deconfig through the shipped hook. Actual
queued intake precedes release; pauses were **0.100 / 0.058 seconds**. Formal
invalidation records show `current=None, active=None` after real withdrawal. The
ACK recovery joins the subsequent wire transaction/current generation and has new
quorum; its accepted history equals the invalidated attempt's history. These are
bounded delay injections, not crashed-executor or all-interleaving qualification.
Old-generation delayed probe completion is portable coverage; the VM stale
operation case is an old epoch/revision operator request, not a delayed old writer.

The latch case includes a successful independent A/main TLS witness sourced from
`10.77.0.1`, while forwarded LAN traffic fails. It forces a charged cross-WAN
attempt before expecting latch: a full history alone intentionally still permits
free same-WAN renewal. Wrong-WAN DHCP counters remain zero for both links.

**32 corrupted-evidence controls** reject failed/missing/timed-out stages,
source/build/cleanup errors, stale/unhealthy selections, altered history, future
ACKs, wrong endpoint, missing observed failed round, accepted stale requests,
latch bypass, invalid fallback and missing write-race queue/invalidation records.
Normal and optimized Python checks agree; HTML is the exact JSON render, and the
standalone unit receipts equal their embedded copies.

VM process RSS snapshots: service **25,220 KiB**, clients A/B **1,612 / 1,612 KiB**.
They are not peaks and exclude fixture/kernel/whole-VM overhead. All case durations
include setup or deliberate health/lease waits; **none is an outage upper bound,
failover SLO, throughput comparison or same-arrival traffic benchmark**.

Owned children/namespaces/source/build are removed, root network unchanged, VM
stopped and source unchanged. Private keys, logs, frames, journals and external
client archives/binaries are excluded.

## Attempts and limits

All six VM attempts are summarized, including failures and a superseded passing
run. Initial assumptions about acquisition order and full-budget latch were
corrected instead of changing valid product behavior. One run reached seven
service cases before a later B qualification failure; a separately reproduced
TLS accept-loop defect led to bounded worker handshakes and the slow-client
fixture control, but no socket dump conclusively attributes that earlier failure.
Another run failed report verification because service replacement's last-address
removal also removed the fixture main routes. The fixture now reprovisions those
external routes after fresh acquisition; the product does not adopt them.
The earlier passing pulse-only run was superseded after the stronger formal
SUSPECT regression exposed a real route-churn defect.

This completes the foreground **milestone 1**, not the deployed dual-DHCP MVP.
Privilege separation/root recovery API, installed start/stop/reboot, 64-transaction
history longevity and same-schedule application traffic measurements remain.
No general DHCP-server interoperability, arbitrary flood/loss, physical WAN,
connection migration, continuous forwarding, boot-zero-gap or power-loss recovery
is claimed. Kernel address deletion can remove interface routes; dedicated WAN
interfaces remain mandatory. The external BusyBox client is separately
GPL-governed, with no archive/binary bundled in this MIT project.
