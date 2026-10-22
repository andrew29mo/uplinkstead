"""Linux socket contrast using the exact mandatory production cBPF attachment.

Test fixture only: before clients/capture start, send one identical bounded burst
at two simultaneous sockets with equal buffers. Never authorizes any lease.
"""
import base64,ctypes,hashlib,json,socket,struct,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dhcp_timer_patch import C_FILTER
from tools.dhcp_timer_server import response,checksum
from tests.test_dhcp_wire import packet


def run(root):
    code='''#include <linux/filter.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
static void bb_simple_perror_msg_and_die(const char*s){perror(s);exit(1);}
'''+C_FILTER+'\nvoid attach(int fd){ul_attach_filter(fd);}\n'
    source=root/'filter-test.c';source.write_text(code);lib=root/'filter-test.so'
    subprocess.run(['cc','-shared','-fPIC','-Wall','-Werror',str(source),'-o',str(lib)],check=True,timeout=30)
    c=ctypes.CDLL(str(lib));c.attach.argtypes=[ctypes.c_int]
    client_mac=bytes.fromhex(Path('/sys/class/net/wanB/address').read_text().strip().replace(':',''))
    request=packet(3,xid=0x12345678,mac=client_mac)
    ack=response(request,5,{},b'\x02\x00\x00\x00\x00\x77')
    noise=bytearray(ack);noise[34:38]=struct.pack('!HH',9999,9998)
    encoded=json.dumps(dict(noise=base64.b64encode(noise).decode(),ack=base64.b64encode(ack).decode()))
    sender="""import sys,json,socket,base64
v=json.load(sys.stdin)
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as s:
 s.bind(('edge',0))
 for _ in range(2000):s.send(base64.b64decode(v['noise']))
 s.send(base64.b64decode(v['ack']))
"""
    with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x800)) as filtered,socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x800)) as plain:
        for s in (filtered,plain):s.bind(('wanB',0));s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,32768);s.setblocking(False)
        c.attach(filtered.fileno())
        subprocess.run(['ip','netns','exec','dd_b','python3','-c',sender],input=encoded,text=True,check=True,timeout=10)
        time.sleep(.1);rows={}
        for name,s in (('filtered',filtered),('unfiltered',plain)):
            packets,drops=struct.unpack('II',s.getsockopt(263,6,8)) # SOL_PACKET/PACKET_STATISTICS
            received=[]
            while len(received)<4096:
                try:received.append(hashlib.sha256(s.recv(65535)).hexdigest())
                except BlockingIOError:break
            else:raise RuntimeError('Probe receive bound exceeded')
            rows[name]=dict(packets=packets,drops=drops,received=len(received),ack_received=hashlib.sha256(ack[14:]).hexdigest() in received,rcvbuf=s.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF))
    assert rows['filtered']['ack_received'] and not rows['unfiltered']['ack_received'] and rows['unfiltered']['drops']>0
    assert rows['filtered']['rcvbuf']==rows['unfiltered']['rcvbuf'] and rows['filtered']['drops']==0
    return dict(noise_frames=2000,ack_frames=1,ack_sha256=hashlib.sha256(ack).hexdigest(),filter_source_sha256=hashlib.sha256(C_FILTER.encode()).hexdigest(),sockets=rows)

if __name__=='__main__':print(json.dumps(run(Path(sys.argv[1]))))
