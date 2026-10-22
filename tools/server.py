"""Fixture TLS application: observed source is independent of the router's claims."""
import argparse
import http.server
import json
from pathlib import Path
import ssl
import threading

p=argparse.ArgumentParser();p.add_argument('cert');p.add_argument('key');p.add_argument('--address',default='203.0.113.2');p.add_argument('--ports',type=int,nargs='+',default=[8443,8444,8445]);a=p.parse_args()
class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        # Handshake belongs to this bounded worker, never the accept loop.
        # A path lost mid-handshake must not stall probes on the healthy WAN.
        self.request.settimeout(1.)
        self.request.do_handshake()
        super().setup()
    def do_GET(self):
        data=json.dumps(dict(ok=True,nonce=self.path[1:],peer=self.client_address[0],server=a.address)).encode()
        bad=Path('/opt/uplinkstead/bad-body')
        if a.address=='203.0.113.2' and self.server.server_port==8443 and bad.exists():
            data=(json.dumps(dict(ok=True,nonce=self.path[1:],peer='中'*4000),ensure_ascii=False).encode()
                  if bad.read_text()=='large-peer' else b'null')
        self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*_):pass
servers=[]
for port in a.ports:
    s=http.server.ThreadingHTTPServer((a.address,port),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(a.cert,a.key)
    s.socket=ctx.wrap_socket(s.socket,server_side=True,do_handshake_on_connect=False);servers.append(s)
    threading.Thread(target=s.serve_forever,daemon=True).start()
threading.Event().wait()
