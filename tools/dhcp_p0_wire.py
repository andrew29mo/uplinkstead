"""Isolated-VM wire observer/replay helper; raw frames remain private fixture data."""
import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from uplinkstead.dhcp_wire import parse_frame
from uplinkstead.writer import now


def observe(interface, output):
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as s:
        s.bind((interface,0));s.settimeout(1)
        output.with_suffix('.ready').write_text('ready')
        with output.open('a') as f:
            while True:
                try:frame=s.recv(65535)
                except socket.timeout:continue
                try:p=parse_frame(frame)
                except ValueError:continue
                p['chaddr']=p['chaddr'].hex()
                p.update(at=now(),destination=str(ipaddress.IPv4Address(frame[30:34])),
                         frame_sha256=hashlib.sha256(frame).hexdigest(),frame=base64.b64encode(frame).decode())
                f.write(json.dumps(p)+'\n');f.flush()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--interface',required=True);p.add_argument('--output',type=Path)
    p.add_argument('--replay',type=Path);a=p.parse_args()
    if a.replay:
        v=json.loads(a.replay.read_text())
        with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as s:
            s.bind((a.interface,0));s.send(base64.b64decode(v['frame']))
    else:observe(a.interface,a.output)
