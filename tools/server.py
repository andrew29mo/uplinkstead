"""Fixture TLS application: observed source is independent of the router's claims."""
import argparse
import http.server
import json
import ssl
import threading

p=argparse.ArgumentParser();p.add_argument('cert');p.add_argument('key');a=p.parse_args()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data=json.dumps(dict(ok=True,nonce=self.path[1:],peer=self.client_address[0])).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*_):pass
servers=[]
for port in (8443,8444,8445):
    s=http.server.ThreadingHTTPServer(('203.0.113.2',port),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(a.cert,a.key)
    s.socket=ctx.wrap_socket(s.socket,server_side=True);servers.append(s)
    threading.Thread(target=s.serve_forever,daemon=True).start()
threading.Event().wait()
