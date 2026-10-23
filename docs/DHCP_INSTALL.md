# Dual-DHCP MVP: clean installation and operator handoff

This is the current opt-in dual-DHCP IPv4 service, separate from the static and
single-DHCP services. Never run multiple writers on the same interfaces. It is a
bounded MVP, not general router or production qualification.

## Prerequisites

The exercised distribution is Ubuntu 24.04 aarch64, Python 3.12 and systemd.
Provide two dedicated DHCP interfaces and one routed LAN, forwarding enabled,
reverse-path settings compatible with policy routing, correct upstream NAT/return
routes and three reachable TLS targets with a trusted CA. Other network managers
must leave the dedicated interfaces and reserved rules/tables alone. See
[configuration](DUAL_DHCP.md) and [supervision](DHCP_SYSTEMD.md).

For that distribution, system dependencies are `python3`, `python3-pip`,
`iproute2` and systemd. Build dependencies for the qualified external BusyBox
adapter include `gcc`, `make`, `libc6-dev` and `bzip2`. Obtain the hash-qualified
BusyBox archive from the URL in `tools/dhcp_client_build.py`, then run
`python3 tools/dhcp_client_build.py --archive /path/to/busybox-1.36.1.tar.bz2
--directory /path/to/fresh-client-build` as a single command. Its GPL source,
transformation and build receipt must remain available; the binary is not bundled.
Build the Python wheel with `python3 -m pip wheel --no-deps --wheel-dir dist .`.
Do not replace the qualified client with an untested distro binary.

The following **fresh-host** commands are executed verbatim by the closure check.
Set `WHEEL` to the built wheel, `CLIENT` to the compiled BusyBox executable,
`SOURCE` to the release checkout, and `CONFIG` to a validated deployment JSON with
`runtime.automatic_selection: true`. All inputs must be trusted and root-controlled.
This recipe refuses existing product paths/package/account; it is not an upgrade
or an unattended installer. Ubuntu's system-Python pip override is explicit:
use only a dedicated host whose Python package ownership you control.

```sh
set -eu
/usr/bin/python3 -I -c 'import sys,importlib.util; assert sys.version_info >= (3,12); assert importlib.util.find_spec("uplinkstead") is None'
! getent passwd uplinkstead
for p in /etc/uplinkstead/dual-dhcp.json /var/lib/uplinkstead-dual /run/uplinkstead-dual /etc/systemd/system/uplinkstead-dual.service /etc/systemd/system/uplinkstead-dual-policy.service /usr/libexec/uplinkstead-busybox /usr/libexec/uplinkstead-dual-hook.py /usr/libexec/uplinkstead-dual-worker.py; do
    test ! -e "$p" && test ! -L "$p"
done
useradd --system --no-create-home --shell /usr/sbin/nologin uplinkstead
/usr/bin/python3 -m pip install --break-system-packages --no-deps --no-index "$WHEEL"
install -d -m 0755 /etc/uplinkstead /usr/libexec
install -m 0600 "$CONFIG" /etc/uplinkstead/dual-dhcp.json
install -m 0755 "$CLIENT" /usr/libexec/uplinkstead-busybox
install -m 0755 "$SOURCE/deploy/uplinkstead-dual-hook.py" /usr/libexec/uplinkstead-dual-hook.py
install -m 0644 "$SOURCE/uplinkstead/dual_dhcp_worker.py" /usr/libexec/uplinkstead-dual-worker.py
install -m 0644 "$SOURCE/deploy/uplinkstead-dual.service" /etc/systemd/system/uplinkstead-dual.service
install -m 0644 "$SOURCE/deploy/uplinkstead-dual-policy.service" /etc/systemd/system/uplinkstead-dual-policy.service
systemctl daemon-reload
```

Start only after interfaces and the declared prerequisites are ready:
`systemctl enable --now uplinkstead-dual.service`. Inspect both units and run
`python3 -m uplinkstead.dual_dhcp_cli --socket /run/uplinkstead-dual/control.sock status`.
READY means intake readiness, not usable WAN. New leases and fresh TLS quorum
must precede forwarding. A namespace-only systemd drop-in in the isolated check
supplies dedicated interfaces; no PYTHONPATH, ExecStart replacement or startup
timer is used in that check. Host boot ordering is still a deployment responsibility.

## Operator workflow

Use the same CLI with `pause`, `resume`, or `reset-budget --ack-reset-budget`.
Pause preserves a still-safe selected path but permits safety withdrawal.
Reset requires paused state and explicit acknowledgement; it neither resumes
nor reinstalls a route. Resume cannot clear a switching latch. The CLI normally
reads the current epoch/revision; supplying old `--epoch` and `--revision` must
reject. A lost reply requires status inspection rather than blind retry.

`systemctl stop uplinkstead-dual.service` stops the worker/clients and withdraws
owned allocations under the writer lock. Terminal guards remain: this does not
hand the LAN to main's default. Restart requires fresh authority, leases and
health. After a diagnosed startup fault is repaired, explicitly reset systemd's
failed writer limiter and start it. Do not delete the journal or reset application
budgets to conceal a failed recovery. See [storage repair](DHCP_STORAGE.md).

## Scope and evidence

[Closure evidence](../reviews/closure/README.md) records the fresh VM identity,
package/module/unit/client hashes, actual commands, operator results and bounded
resource series. The fixture supplies isolated DHCP servers, TLS targets,
forwarding/NAT/return paths and a positive forbidden-main fallback. Product
selection and recovery are performed only by installed formal services.

This is not a qualification of arbitrary distributions, package upgrades,
physical ISP equipment, long-term memory safety, power loss or boot-zero-gap.
The older [VM reboot gate](DHCP_BOOT.md) uses a labelled 25-second fixture timer;
that timer's evidence is separate from this clean-install/manual-start check.
