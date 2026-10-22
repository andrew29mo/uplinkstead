# P0: renewable dual-DHCP client integration

This is a technical exploration of the formal foreground service, not the
completed DHCP automatic-failover MVP. The existing distro-client mode remains
available with its conservative same-xid deadline. The experimental adapter is
selected explicitly with `--client /path/to/experimental/busybox`.

## Decision and transaction boundary

A hook timestamp is not a lease origin. An observed REQUEST is insufficient to
make a reused xid fresh: an identical delayed ACK can arrive after that REQUEST.
The prior conservative solution therefore could process a legitimate renewal
without extending its deadline. That protects safety but is not a sustainable
renewal strategy on its own.

For this bounded exploration we retain BusyBox's actual DHCP state machine and
change two things in a reproducible external build:

1. `random_xid()` becomes a randomly seeded, nonrepeating 32-bit process-local
   sequence. Exhaustion exits rather than wrapping and reusing an identifier.
2. At `BOUND_for_half_lease`, choose the next xid for the next renewal attempt.
   Retransmissions inside a transaction retain the same xid. A new scheduled
   attempt after an unanswered renewal receives another xid.

The formal packet tracker still requires matching REQUEST/ACK evidence, fixed
client authority and immutable queue timestamps. A new xid can establish a new
conservative REQUEST origin and extend a lease. On the first observation of a new REQUEST xid, the prior transaction is
superseded, even if it never received an ACK. This request watermark does not
withdraw the still-valid allocation. Replayed known-old REQUESTs and late ACKs
cannot reopen that transaction, withdraw a newer allocation or manufacture proof.
Queued older proofs retain their old version and are rejected by the runtime.
Contradictions concerning the latest allocation still invalidate its proof.

This is correlation, not authentication. IDs are predictable after observation;
DHCP is unauthenticated. No hostile DHCP server, crafted future-xid injection,
cross-process xid collision or unlimited delayed-packet guarantee is claimed.
If capture misses a newer REQUEST, the watermark cannot infer that unseen
transaction; this is not a guarantee against capture loss or arbitrary reordering.
The history remains bounded at 64 xids and fails closed on saturation. A fresh
client session is then needed under the existing per-link restart limiter.

## Why this integration, and its cost

Keeping unmodified BusyBox plus packet heuristics cannot remove the same-xid
ambiguity. Replacing the entire client would add a much larger protocol surface.
A narrow, externally built adapter makes the transaction decision observable
while retaining a real client implementation. It also creates maintenance work:
upstream updates, client security review, packaging and deployment qualification
are required before adopting it as a default. BusyBox 1.36.1 was pinned to match
the previously qualified client family, not recommended as a current security
baseline. This experiment is not a security assessment of that release.

The first-party Python project remains MIT. The externally built BusyBox program
remains subject to upstream GPL terms and component notices. Its full upstream
source, transformation and build recipe must accompany any future redistribution
in accordance with those terms. No BusyBox source archive, patched source or
binary is committed or included in the Python wheel.

## What the VM must observe

The isolated fixture launches `uplinkstead.dual_dhcp_service`, its shipped hook
and the actual externally built client. It does not call `DualLifecycle` to
fabricate renewal. Independent AF_PACKET observers retain real REQUEST/ACK
identities and destinations. Raw frames stay private; reports export summaries
and frame hashes. Replaying an ACK means transmitting the originally captured
frame on the isolated B segment, not directly feeding the parser. The runner
requires the receiving observer to see a new matching frame hash, the formal
Capture to record that hash with a newer frame ordinal and drain its queue, and
a subsequent full Runtime step before checking identity, version and pending
state. Capture retains at most 32 diagnostic frame hashes; eviction or delay
fails the check rather than granting a pass.

Required observations:

- Two naturally timed unicast renewals on each link, with distinct xids, extended
  service deadlines and unchanged client PID/session. No SIGUSR1 or clock rewrite
  may produce those extensions.
- Block only B's unicast DHCP REQUESTs. Observe the client naturally transition
  to broadcast renewal/rebinding and accept a real server ACK. A's client
  authority remains independent. The forbidden cross-WAN DHCP counter stays zero.
- During a newer unanswered request, replay an ACK from an earlier transaction
  of that same running B client. Its allocation/deadline/event sequence must not
  change. The new real ACK, not the replay, must explain the next extension.
- Also synthesize a server-shaped delayed reply for an unanswered older
  transaction, using a captured ACK template and that older xid. Deliver it after
  the next REQUEST; require the same production-processing fence and unchanged
  lease. This is labelled packet fault injection, not an original server reply.
- Stop B's DHCP server, observe B lose its allocation, then restart the server
  with a different offered address. A must remain independently usable; B must
  obtain the changed address from real packets and pass new TLS traffic.
- Replay the original B ACK after reacquisition. The newer allocation, deadline
  and selected route must remain unchanged.
- Kill only B's client and verify its replacement does not change A's allocation
  identity. All namespaces/processes/source/build artifacts must be cleaned up.

## Timer qualification is deliberately specific

The pinned BusyBox implementation renews at half the remaining lease and enters
rebinding when little lease time remains. It does not implement arbitrary
server-provided option 58/59 schedules in the code being tested. Consequently,
"natural T1" and "natural rebinding/T2 path" here describe the real client timer
algorithm, not qualification of negotiated T1/T2 options or all RFC timing rules.
That interoperability gap remains open; passing this exploration does not close
that production requirement.

The service still invalidates health on renewal, and selection remains explicit.
Successful TLS checks after explicit fresh selection are not proof of continuous
forwarding, existing-connection preservation or automatic failover. The next
integration stage must handle health/selection convergence and switch budgets.

## Reproduction and evidence

Use a dedicated, provisioned Linux VM with Python 3.12+, gcc/make/libc headers,
bzip2, BusyBox (for baseline checks), dnsmasq, iproute2, nftables and OpenSSL.
Download the [official BusyBox 1.36.1 archive](https://busybox.net/downloads/busybox-1.36.1.tar.bz2)
locally; `tools.dhcp_client_build` rejects any SHA-256 other than
`b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314`.

```sh
.venv/bin/python -m tools.dhcp_p0_validate \
  --archive /path/to/busybox-1.36.1.tar.bz2 \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-p0
```

The runner builds from the verified external archive inside the VM, records
source/config/compiler/binary provenance, runs identical-source portable tests
on macOS/Linux and then the actual service scenarios. Timeouts, source changes,
failed cleanup and contradictory receipts fail the run. JSON/HTML include all
scenario durations; they are single controlled observations, not performance or
recovery-time bounds. RSS is an individual process snapshot in a Linux VM,
excluding kernel/socket buffers, fixture servers, filesystem cache and VM overhead.
No native-versus-VM speed or memory advantage is claimed.

See [retained P0 evidence](../reviews/dhcp-p0/README.md). Earlier stage-one and
exploration receipts remain historical and do not qualify this new client.

References: [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html),
[BusyBox 1.36.1 client source](https://github.com/mirror/busybox/blob/1_36_1/networking/udhcp/dhcpc.c),
[BusyBox license](https://busybox.net/license.html).

## Finding retained from this trial

The initial trial observed BusyBox declare lease loss about 25 seconds
before the service's conservative deadline. The review validation additionally
records the actual lease-loss branch diagnostic (interface, PID, xid, remaining
lease seconds and attempt count), all three broadcast retries, and the deconfig
hook. A positive remaining value with attempts equal to three distinguishes
retry exhaustion from service deadline expiry. That is safe withdrawal but reduces
availability. It is not an independent service-expiry test, and it remains an
operational adoption gate together with option 58/59 timing interoperability.
This exploration establishes a workable process-local transaction boundary and
actual renewal/reacquisition, not a final default client/deployment decision.

The experimental build's diagnostic marker does not change timer decisions.
`runtime.client_diagnostics: true` optionally inherits the service's standard
output/error streams for client diagnostics (default false). Operators own log
retention; no journal/file size bound is implied. Raw logs remain private to the
VM fixture; only the parsed bounded loss event is exported.
