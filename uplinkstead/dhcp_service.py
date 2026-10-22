"""Root-local event service and supervised BusyBox udhcpc adapter."""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import signal

from .control import decode
from .dhcp import Lifecycle, config
from .writer import boot_id, now


def request(path, q):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.settimeout(2)
        s.connect(str(path))
        s.sendall(json.dumps(q, allow_nan=False).encode())
        answer = decode(s.recv(4097))
        if not answer['ok']:
            raise RuntimeError(answer['error'])
        return answer['result']


def hook():
    # udhcpc calls scripts synchronously. Fixed session is inherited from its
    # supervisor, never fetched from the currently running replacement writer.
    reason = __import__('sys').argv[1]
    if reason not in ('bound', 'renew', 'deconfig', 'nak', 'leasefail'):
        return
    at = now()
    path = os.environ['UPLINKSTEAD_SOCKET']
    status = request(path, {'op': 'status'})
    value = {k: os.environ.get(k, '') for k in ('ip', 'subnet', 'router', 'lease')} if reason in ('bound', 'renew') else None
    result = request(path, dict(session=os.environ['UPLINKSTEAD_SESSION'], boot=os.environ['UPLINKSTEAD_BOOT'],
                               revision=status['revision'], at=at, reason=reason, lease=value))
    if result.get('lease_rejected') or result.get('event_expired'):
        print('Uplinkstead: rejected DHCP allocation withdrawn; waiting for a valid lease',
              file=__import__('sys').stderr)


def startup(w):
    """Read-only admission before the first client callback can run."""
    from .linux import Blocked
    snapshot = w.snapshot()
    if snapshot['current'] is not None or snapshot['expires'] != 0 or snapshot['healthy']:
        raise Blocked('DHCP startup allocation was not quarantined')
    w.backend.check([None])  # Actual rules/addresses/routes, not a cached flag.
    return dict(event='dhcp_startup_ready', state=snapshot,
                backend_empty_verified=True, boottime=now())


def serve(c, state, path, executable, hook_path):
    if os.geteuid() != 0:
        raise PermissionError('DHCP service requires root')
    def stop(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.parent.lstat()
    import stat
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise PermissionError('Private root socket directory required')
    with Lifecycle(c, state) as w, socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        if path.exists():
            if not stat.S_ISSOCK(path.lstat().st_mode):
                raise RuntimeError('Refusing non-socket path')
            path.unlink()  # Writer lock excludes a live previous owner.
        listener.bind(str(path));path.chmod(0o600)
        listener.listen(4);listener.settimeout(.1)
        print(json.dumps(startup(w), allow_nan=False), flush=True)
        env = dict(os.environ, UPLINKSTEAD_SESSION=w.s['session'], UPLINKSTEAD_BOOT=boot_id(), UPLINKSTEAD_SOCKET=str(path))
        child = subprocess.Popen([executable, 'udhcpc', '-f', '-i', c['interface'], '-s', str(hook_path),
                                  '-t', '3', '-T', '1', '-A', '2', '-O', 'lease'], env=env)
        try:
            last = 0
            while True:
                if child.poll() is not None:
                    raise RuntimeError('DHCP client exited')
                if now()-last >= 1:
                    w.tick();last = now()
                if w.s['current'] and now() >= w.s['expires']:
                    w.transition(None, 0)
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                with peer:
                    peer.settimeout(.2)
                    uid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                    revision = w.s['revision']
                    try:
                        if uid != 0:
                            raise PermissionError('Root-only DHCP adapter')
                        q = decode(peer.recv(4097))
                        # Receiving a packet may straddle the lease deadline.
                        # Expire before answering status or admitting an event.
                        if w.s['current'] and now() >= w.s['expires']:
                            w.transition(None, 0)
                        revision = w.s['revision']
                        if q == {'op': 'status'}:
                            result = w.snapshot()
                        else:
                            result = w.event(q)
                        answer = dict(ok=True, result=result)
                    except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
                        if w.s['revision'] != revision:
                            raise  # A partial mutation retires this writer.
                        answer = dict(ok=False, error=type(exc).__name__)
                    try:
                        peer.sendall(json.dumps(answer, allow_nan=False).encode())
                    except OSError:
                        pass  # Caller disconnect never rolls back completed work.
        finally:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=2)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=2)
            # Never overwrite an incomplete old/new intent: recovery needs both
            # addresses to clean up a command that might already have executed.
            if w.s['intent'] is None:
                w.transition(None, 0)
            path.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--socket', type=Path, required=True)
    p.add_argument('--client', default='/usr/bin/busybox')
    p.add_argument('--hook', type=Path, default=Path('/usr/libexec/uplinkstead-udhcpc.py'))
    a = p.parse_args()
    serve(config(a.config), a.state, a.socket, a.client, a.hook)


if __name__ == '__main__':
    main()
