# REQUEST-origin DHCP T1/T2 timer integration

This is a bounded extension of the formal foreground dual-DHCP service, using an
explicitly selected external BusyBox client. It fixes retry-count-driven early
lease loss in that adapter. It does not change the distro-client default, the
installed static service or the single-DHCP service.

## Timer and transaction decisions

The previous [P0 receipt](../reviews/dhcp-p0/README.md) demonstrated the actual
BusyBox lease-loss branch with three broadcast attempts and 26 seconds remaining.
Withdrawal was safe but unnecessarily early. Its source and receipts remain
historical; they do not describe the new timer implementation.

The external build now embeds the exact first-party C functions from
`tools/dhcp_timer_patch.py`. Portable tests compile those functions on macOS and
Linux; the VM additionally compiles and runs the complete patched BusyBox program.
No separately maintained Python timer simulator stands in for that client.

- Option 51 is a finite 1..86400 second lease. Options 58/59, when present, must
  each be four-byte unsigned network-order seconds and satisfy `0 < T1 < T2 < lease`.
- Missing T1 defaults to half the lease; missing T2 defaults to seven eighths.
  Each default is calculated independently, including fractional seconds for short
  leases. A supplied value conflicting with the other default is rejected.
- Deadlines use Linux `CLOCK_BOOTTIME` nanoseconds and the first REQUEST send
  origin in a transaction, not ACK, hook or queue processing time. Retransmissions
  retain that origin; delayed replies cannot reset the full lease period.
- At T1 the client sends unicast renewal. At T2 it switches to broadcast rebinding.
  Each phase begins a new process-local nonrepeating xid, retiring the unanswered
  previous transaction. Retries within that phase retain the same xid and origin.
- Retry intervals use half the time to the next boundary, with a 60-second
  minimum clipped to T2/expiry. Retry count never ends an otherwise valid lease.
  At absolute expiry the client deconfigures; the writer also independently
  expires the admitted allocation and withdraws its owned address/route.
- Invalid, malformed or already expired timer ACKs are ignored, preserving an
  existing valid lease only until its original deadline. This is a conservative
  supported-profile decision, not a claim that every DHCP server behaves alike.

The hook carries the client's fixed origin and xid under existing root-owned
client/session/boot authority. The writer still requires independently captured
matching REQUEST/ACK proof. It uses the **earlier** of client origin and capture
queue lower bound; client metadata can shorten a deadline, never extend it. The conservative capture
bound can therefore withdraw slightly before the client's exact expiry; eliminating
retry-count loss does not promise identical nanosecond withdrawal times. Missing
metadata preserves the conservative distro-client path. Wrong xid or invalid
metadata revokes only the affected current authority.

The packet tracker validates the same option policy. The independent fixture
observer may decode rejected timer options for diagnostics; that mode grants no
lease authority. A bounded frame hash/ordinal, drained capture queue and subsequent
complete writer publication are required before saying a rejected ACK had no effect.

## ACK intake and quarantine ordering

Wire capture deliberately invalidates the prior allocation/health before a new
ACK hook authorizes its replacement. An ordinary UDP receive socket could lose
that ACK if the writer removed its local destination address first. The client
therefore uses its existing raw DHCP receive path during both renewal and
rebinding. A mandatory classic BPF filter admits only the supported IPv4/IHL5,
unfragmented UDP 67→68 receive profile, preventing unrelated IPv4 traffic from
consuming this raw socket's queue. Attachment failure exits the client; it does
not silently fall back to unfiltered receipt. A same-burst Linux socket contrast
uses the exact production attachment code, equal buffers and kernel packet-drop
statistics. The formal-client regression separately blocks kernel UDP delivery,
stops the real client before a delayed actual ACK, observes address quarantine,
then resumes that same process and checks the same frame's admission. SIGSTOP
alone would not rule out a pre-enqueued UDP ACK.

This supports the tested receipt ordering; it does not bypass the
matching wire proof, session authority or fresh-health requirements. DHCP unicast
transmission is still addressed to the selected link's server; T2 is broadcast.

## Reproduction

Use a dedicated, provisioned Colima `relay` VM, Python 3.12+, gcc/make/libc headers,
bzip2, dnsmasq, iproute2, nftables and OpenSSL. Native portable tests require `cc`.
Provide the official BusyBox 1.36.1 archive separately; its fixed SHA-256 and the
full transformed source hash are checked before compilation.

```sh
.venv/bin/python -m tools.dhcp_timer_validate \
  --archive /path/to/busybox-1.36.1.tar.bz2 \
  --colima-home /path/to/dedicated-colima-home \
  --toolchain /path/to/colima-and-lima/bin \
  --output results/fresh-dhcp-timers
```

The same manifest is tested on native macOS and Linux. The formal service launches
its own real clients. A uses dnsmasq; B uses a deterministic isolated raw-packet
DHCP fixture, permitting genuinely absent or malformed 58/59 options and a held
reply to an actual unanswered REQUEST. The fixture's UDP-port drop suppresses the
B server namespace's kernel ICMP rejection; it does not drop raw captured requests
or modify the product's routing policy.

SIGUSR1 is used only to bootstrap each new server profile. Natural T1/T2 evidence
comes from subsequent unsignalled client timer transitions. The 240-second silent
server test deliberately passes three broadcast retries while time remains, then
samples the original allocation from before T1 through the first withdrawal
publication (maximum accepted observation gap: two seconds). A withdrawal
publication before the writer's conservative deadline fails immediately; a later
client expiry log cannot excuse it. This is sampled runtime evidence, not an
exact kernel-removal timestamp or a zero-gap guarantee. Reacquisition uses a changed address. Old ACKs are
transmitted on the isolated segment, not fed directly into a test parser.

[Retained JSON/HTML and results](../reviews/dhcp-timer-review/README.md).
The runner fails on nonzero exit, timeout, source drift, missing observations or
cleanup failure. Raw frames, generated certificates, external source and binary
stay private/ignored; only sanitized summaries and hashes are exported.

## Scope and remaining gaps

These are controlled Ethernet IPv4 observations with finite leases, not complete
RFC 2131/2132 or DHCP server interoperability certification. Random timer fuzz,
infinite leases, option overload, alternate L2 encapsulations, hostile servers,
capture loss and arbitrary packet reordering are not qualified. The receive
filter does not prevent DHCP-shaped floods or guarantee loss-free receipt under
arbitrary CPU/network load. Xids correlate
transactions; they do not authenticate DHCP. The bounded 64-xid history still
requires session replacement on saturation under the restart limiter.

The experiment retains explicit selection and fresh-health requirements. It does
not establish automatic dual-DHCP failover, continuous forwarding, installed
service recovery, VM reboot recovery for this adapter, boot-zero-gap protection,
physical uplink behavior or sudden power-loss recovery. There is no performance
advantage or recovery SLO claim. Scenario durations include deliberate timer waits;
RSS is a Linux VM process snapshot, not a peak, and excludes VM/kernel/fixture costs.

The MIT project does not bundle the externally built GPL BusyBox program. See
[third-party scope](THIRD_PARTY.md). The pinned version is an experimental baseline,
not a recommendation of its present security suitability.

References: [RFC 2131 §4.4.5](https://www.rfc-editor.org/rfc/rfc2131.html#section-4.4.5),
[RFC 2132 §9.11–9.12](https://www.rfc-editor.org/rfc/rfc2132.html#section-9.11),
[upstream client](https://github.com/mirror/busybox/blob/1_36_1/networking/udhcp/dhcpc.c).
