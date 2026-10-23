# License and third-party scope

Uplinkstead's first-party code, configuration, tests, documentation and generated
project reports are provided under the [MIT License](../LICENSE), copyright 2026
Andrew Yuan. Package metadata declares the SPDX expression `MIT` and includes the
same LICENSE text in distributions. The repository is public.

## Distribution checked

The Python project declares no runtime package dependencies. An AST import review
found only project modules and Python standard-library imports. The wheel contains
first-party modules, metadata and the project license; it does not vendor Python,
SQLite, networking commands, VM tools, third-party models or datasets. The service
invokes separately installed iproute2 commands; the fixture additionally invokes
systemd, nftables/iptables, OpenSSL and Colima/Lima. No dependency source or binary
is copied into this repository or wheel.

The dual-DHCP control fixture additionally invokes separately installed util-linux
`setpriv` to launch real numeric UID/GID workers with dropped capabilities and
NoNewPrivs. That executable is not vendored or redistributed; the installed
package's component notices remain authoritative.

MIT covers the project's own files. It does not relicense the programs below or
claim that a complete OS/VM image can be redistributed under MIT. Their component
notices remain authoritative, including exceptions and bundled subcomponents.

## Upstream notices checked

| Component | How used | Upstream terms / primary reference |
|---|---|---|
| Python 3.12 and standard library | Separately installed interpreter/runtime | [PSF license and component notices](https://docs.python.org/3.12/license.html) |
| SQLite | Accessed through Python's sqlite3 module; not bundled in the wheel | [Public-domain dedication for deliverable library](https://www.sqlite.org/copyright.html) |
| setuptools | Isolated build dependency; not shipped as runtime code | [MIT permission text, observed builder 84.2.1](https://github.com/pypa/setuptools/blob/v84.2.1/LICENSE) |
| iproute2 | External `/usr/sbin/ip` process | [GPLv2 COPYING](https://github.com/iproute2/iproute2/blob/main/COPYING); individual source/package notices govern details |
| systemd 255 | External service manager and fixture commands | [LGPL-2.1-or-later with noted exceptions](https://github.com/systemd/systemd/blob/v255/README) |
| nftables / iptables | External isolated-fixture firewall setup and preservation checks | [Netfilter GPL-family licensing statement](https://netfilter.org/about.html#license); installed package notices govern exact components |
| OpenSSL 3 | External fixture certificate command; runtime ssl support belongs to the interpreter distribution | [Apache-2.0 text](https://github.com/openssl/openssl/blob/openssl-3.0/LICENSE.txt) |
| BusyBox udhcpc | Separately installed DHCP client for the optional lifecycle service | [GPLv2, component exceptions apply](https://busybox.net/license.html) |
| dnsmasq | Separately installed DHCP server used only in isolated validation | [GPLv2 or GPLv3](https://thekelleys.org.uk/dnsmasq/doc.html) |
| Colima | External validation VM manager | [MIT](https://github.com/abiosoft/colima/blob/main/LICENSE) |
| Lima | External Colima infrastructure | [Apache-2.0 and notices](https://github.com/lima-vm/lima/blob/master/LICENSE) |

The inventory describes the current source/wheel and separately installed tools;
it is not a complete license audit of a Linux distribution, interpreter bundle,
Docker runtime, transitive build environment or VM image. Those artifacts are not
redistributed here. Research links are references, not bundled implementation code.

## Verification and preserved history

The retained licensing receipt checks that wheel metadata says MIT, that its
license file exactly equals the repository LICENSE, that product modules equal the
reviewed source and that no runtime Requires-Dist dependency was introduced. It
also checks the sdist includes the project license. Existing pre-license receipts
remain unchanged and are explicitly historical; they do not override the current
LICENSE. See [licensing verification](../reviews/licensing/README.md).

## Experimental P0 client build

The P0 runner downloads no executable. It accepts a separately obtained, pinned
BusyBox 1.36.1 source archive, verifies SHA-256 and builds a bounded xid/absolute-T1/T2 adapter
inside the isolated VM. The resulting BusyBox source/binary retains upstream GPL
terms and component notices, independently of this Python project's MIT license.
The transformation and reproduction command are in `tools/dhcp_client_build.py`
and [DHCP_TIMERS.md](DHCP_TIMERS.md). The earlier [P0 workflow](DHCP_P0.md)
is preserved as historical evidence. No external source, archive or executable is included
in this repository or Python distribution. Future binary redistribution requires
separate compliance with BusyBox's source and notice requirements.
