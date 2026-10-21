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
VM image or TLS private key is distributed. No project license has been selected.
