"""Deterministic isolated-VM DHCP fault server, not a product DHCP server.

Only answers DISCOVER/REQUEST on the owned B segment. Real packets exercise the
formal client; dnsmasq independently serves A. Profiles never alter host routing.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from uplinkstead.writer import now


def checksum(b):
    if len(b)%2:b+=b'\0'
    n=sum(struct.unpack('!'+str(len(b)//2)+'H',b))
    while n>>16:n=(n&65535)+(n>>16)
    return (~n)&65535


def response(request,kind,profile,mac):
    ip=14+(request[14]&15)*4;body=request[ip+8:]
    out=bytearray(240);out[:3]=b'\x02\x01\x06';out[4:8]=body[4:8];out[10:16]=body[10:16]
    address=socket.inet_aton(profile.get('address','198.51.100.2'));gateway=socket.inet_aton('198.51.100.1')
    out[16:20]=address;out[20:24]=gateway;out[28:34]=body[28:34];out[236:240]=b'\x63\x82\x53\x63'
    options={53:bytes([kind]),54:gateway,51:int(profile.get('lease',120)).to_bytes(4,'big'),1:b'\xff\xff\xff\0',3:gateway}
    for code in (58,59):
        key=str(code)
        if key in profile:
            value=profile[key];options[code]=bytes.fromhex(value['hex']) if isinstance(value,dict) else int(value).to_bytes(4,'big')
    for code,value in options.items():out+=bytes([code,len(value)])+value
    out+=b'\xff'
    udp=struct.pack('!HHHH',67,68,len(out)+8,0)+out
    destination=body[12:16] if body[12:16]!=b'\0'*4 else b'\xff'*4
    header=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0,0,64,17,0,gateway,destination))
    header[10:12]=checksum(bytes(header)).to_bytes(2,'big')
    destmac=body[28:34] if destination!=b'\xff'*4 else b'\xff'*6
    return destmac+mac+b'\x08\x00'+header+udp


def serve(interface,profile_path,log_path):
    mac=bytes.fromhex(Path('/sys/class/net',interface,'address').read_text().strip().replace(':',''))
    held=None;count=0
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as s,log_path.open('a') as log:
        s.bind((interface,0));s.settimeout(1);profile_path.with_suffix('.ready').write_text('ready')
        def emit(frame,request_at,delayed=False):
            nonlocal count
            s.send(frame);count+=1
            if count>512:raise RuntimeError('Fixture response bound exceeded')
            log.write(json.dumps(dict(at=now(),request_at=request_at,delayed=delayed,xid=int.from_bytes(frame[46:50],'big'),frame_sha256=hashlib.sha256(frame).hexdigest()))+'\n');log.flush()
        while True:
            try:frame=s.recv(4096)
            except socket.timeout:continue
            if len(frame)<282 or frame[12:14]!=b'\x08\x00' or frame[23]!=17:continue
            udp=14+(frame[14]&15)*4
            if frame[udp:udp+4]!=b'\x00D\x00C':continue
            body=frame[udp+8:]
            if len(body)<240 or body[:3]!=b'\x01\x01\x06' or body[236:240]!=b'\x63\x82\x53\x63':continue
            opts={};pos=240
            while pos<len(body):
                code=body[pos];pos+=1
                if code==255:break
                if code==0:continue
                if pos>=len(body):break
                size=body[pos];pos+=1
                if pos+size>len(body):break
                opts[code]=body[pos:pos+size];pos+=size
            kind=opts.get(53)
            if kind not in (b'\1',b'\3'):continue
            profile=json.loads(profile_path.read_text());at=now()
            if not profile.get('reply',True):continue
            reply=response(frame,2 if kind==b'\1' else 5,profile,mac)
            renewing=kind==b'\3' and body[12:16]!=b'\0'*4
            broadcast=frame[30:34]==b'\xff'*4
            if renewing and not broadcast and profile.get('hold_unicast',False):
                held=(reply,at);continue
            if renewing and broadcast and held and profile.get('release_held',False):
                emit(held[0],held[1],True);held=None;time.sleep(2)
            emit(reply,at)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--interface',required=True);p.add_argument('--profile',type=Path,required=True);p.add_argument('--log',type=Path,required=True);a=p.parse_args()
    serve(a.interface,a.profile,a.log)
