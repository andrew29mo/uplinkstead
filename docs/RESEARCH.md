# Technical materials and scope

The following primary sources support the mechanisms, not Uplinkstead test claims:

- [Linux ip-rule](https://man7.org/linux/man-pages/man8/ip-rule.8.html): ordered RPDB,
  ingress selectors, marks and terminal prohibit rules. A lookup miss can continue.
- [Linux ip-route](https://man7.org/linux/man-pages/man8/ip-route.8.html): route
  replacement, readback and the distinction between throw and terminal failures.
- [Linux socket](https://man7.org/linux/man-pages/man7/socket.7.html): device binding
  and marks, with separately validated privilege requirements.
- [Kernel IP sysctl](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html):
  forwarding, effective rp_filter and src_valid_mark; asymmetric return paths need
  explicit qualification. No global sysctl repair is performed by the service.
- [nftables NAT](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)):
  a flow's NAT binding is established on its first packet; route replacement is
  not migration of existing NAT/TCP state.
- [flock](https://man7.org/linux/man-pages/man2/flock.2.html): inherited descriptors
  share an open-file-description lock. Lock files are never unlinked for takeover.
- [Linux clocks](https://man7.org/linux/man-pages/man2/clock_gettime.2.html):
  boot-relative clocks and wall-clock changes require distinct treatment.
- [systemd kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)
  and [unit limits](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html):
  process-tree cleanup and bounded restart semantics.
- [OpenWrt multi-WAN](https://openwrt.org/docs/guide-user/network/wan/multiwan/mwan3):
  policy/stickiness reference, not a backend copied or bundled here. The documented
  iptables compatibility limitations argue against treating its setup as portable.

The installed VM versions and actual observations are recorded in the receipts.
Documentation for newer software is not a substitute for those observations.
Runtime Python imports are first-party/standard library. No external system binary,
VM image or TLS private key is distributed. First-party project files are covered
by the [MIT License](../LICENSE); separately installed dependencies retain their
own terms as recorded in [THIRD_PARTY.md](THIRD_PARTY.md).

## DHCP dual-exit exploration materials

- [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html): natural renewing and
  rebinding are distinct paths; callback time is not automatically the protocol's
  lease origin. Testing SIGUSR1 alone cannot qualify natural T1/T2 behavior.
- [RFC 3442](https://www.rfc-editor.org/rfc/rfc3442.html): option 121 changes route
  interpretation; forwarding only option 3 is not proof of rejecting other route
  semantics. Actual hook export must be checked on the installed client build.
- [BusyBox 1.36.1 DHCP client source](https://github.com/mirror/busybox/blob/1_36_1/networking/udhcp/dhcpc.c)
  and [packet path](https://github.com/mirror/busybox/blob/1_36_1/networking/udhcp/packet.c):
  interface-bound kernel unicast differs from raw broadcast, and synchronous hook
  execution affects client timing. The VM records its actual distro version;
  source inspection is a hypothesis to challenge on the wire, not proof of that
  distro's behavior or of all DHCP implementations.

These materials support the bounded explorations, not a conclusion that the
production queue, natural T2, exact lease timing or installed dual service is
already qualified. See [dual-DHCP scope and remaining gates](DUAL_DHCP.md).
