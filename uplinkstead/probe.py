"""Fresh TLS sockets only; no HTTP library proxy, redirects, or DNS fallback."""
from concurrent.futures import ThreadPoolExecutor
import json
import secrets
import socket
import ssl
import time

MARK = {'A': 0x5101, 'B': 0x5102}


def one(config, link, target, timeout=0.5):
    v = config['links'][link]
    began = time.monotonic()
    nonce = secrets.token_hex(12)
    phase = 'binding'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            deadline = began + timeout
            raw.settimeout(timeout)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (v['interface']+'\0').encode())
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARK[link])
            raw.bind((v['source'], 0))
            # Local source absence and socket-option errors are infrastructure
            # failures, never a successful fallback to an unbound socket.
            phase = 'connect'
            raw.connect((target['ip'], target['port']))
            ctx = ssl.create_default_context(cafile=config['ca'])
            raw.settimeout(max(0.001, deadline-time.monotonic()))
            with ctx.wrap_socket(raw, server_hostname=config['server_name']) as tls:
                tls.settimeout(max(0.001, deadline-time.monotonic()))
                tls.sendall(('GET /'+nonce+' HTTP/1.0\r\nHost: '+config['server_name']+'\r\n\r\n').encode())
                data = b''
                while True:
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    tls.settimeout(remaining)
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 16384:
                        raise ValueError('Oversized probe response')
                head, body = data.split(b'\r\n\r\n', 1)
                try:
                    result = json.loads(body, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON constant')))
                except RecursionError as exc:
                    raise ValueError('Excessive JSON nesting') from exc
                if not isinstance(result,dict):
                    raise ValueError('Probe JSON must be an object')
                if result.get('peer') is not None and not isinstance(result['peer'],str):
                    raise ValueError('Invalid peer observation')
                if not head.startswith(b'HTTP/1.0 200 ') or result.get('nonce') != nonce or result.get('ok') is not True:
                    raise ValueError('Invalid probe response')
                return {'ok': True, 'infrastructure': False, 'seconds': time.monotonic()-began,
                        'peer_observed': result.get('peer'), 'link': link}
    except (OSError, ValueError, ssl.SSLError) as exc:
        return {'ok': False, 'infrastructure': phase == 'binding' or isinstance(exc, FileNotFoundError),
                'error': type(exc).__name__, 'seconds': time.monotonic()-began, 'link': link}


def round(config, link):
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(lambda t: one(config, link, t), config['targets']))
    return None if any(r['infrastructure'] for r in rows) else sum(r['ok'] for r in rows), rows
