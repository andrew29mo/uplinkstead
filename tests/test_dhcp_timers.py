"""Compile the exact C timer implementation embedded in the formal client."""
import ctypes as C
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from tools.dhcp_timer_patch import C_TIMERS
from uplinkstead.dhcp_timing import timer_values
from uplinkstead.dhcp_wire import parse_frame
from tests.test_dhcp_wire import packet

SECOND=1_000_000_000
class Timer(C.Structure):
    _fields_=[(k,C.c_uint64) for k in ('origin','t1','t2','expiry','next')]+[(k,C.c_uint) for k in ('active','phase','attempts')]


class FormalTimerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();root=Path(cls.tmp.name)
        (root/'timer.c').write_text(C_TIMERS+'''
int schedule(struct ul_timers*s,uint64_t o,uint64_t n,const unsigned char*l,size_t ln,const unsigned char*a,size_t an,const unsigned char*b,size_t bn){return ul_schedule(s,o,n,l,ln,a,an,b,bn);}
unsigned action(struct ul_timers*s,uint64_t n){return ul_action(s,n);}
void sent(struct ul_timers*s,uint64_t n){ul_sent(s,n);}
int waiting(struct ul_timers*s,uint64_t n){return ul_wait_ms(s,n);}
''')
        lib=root/'timer.so';subprocess.run(['cc','-dynamiclib' if platform.system()=='Darwin' else '-shared','-fPIC','-Wall','-Werror',str(root/'timer.c'),'-o',str(lib)],check=True,capture_output=True,timeout=30)
        cls.lib=C.CDLL(str(lib));cls.lib.schedule.argtypes=[C.POINTER(Timer),C.c_uint64,C.c_uint64,C.c_char_p,C.c_size_t,C.c_char_p,C.c_size_t,C.c_char_p,C.c_size_t]
        for name in ('action','sent','waiting'):getattr(cls.lib,name).argtypes=[C.POINTER(Timer),C.c_uint64]
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def schedule(self,lease=120,t1=None,t2=None,origin=SECOND,received=None):
        s=Timer();enc=lambda v:None if v is None else v.to_bytes(4,'big')
        a,b=enc(t1),enc(t2)
        ok=self.lib.schedule(C.byref(s),origin,origin if received is None else received,enc(lease),4,a,0 if a is None else 4,b,0 if b is None else 4)
        return s,ok
    def test_defaults_partial_and_explicit_options_match_wire_policy(self):
        for lease,t1,t2 in ((120,None,None),(120,20,50),(120,20,None),(120,None,100),(1,None,None),(86400,None,None)):
            with self.subTest(lease=lease,t1=t1,t2=t2):
                s,ok=self.schedule(lease,t1,t2);self.assertEqual(ok,1)
                a,b=timer_values(lease,t1,t2)
                self.assertEqual((s.t1-s.origin,s.t2-s.origin,s.expiry-s.origin),(a,b,lease*SECOND))
    def test_invalid_and_expired_ACK_never_overwrite_existing_schedule(self):
        s,_=self.schedule();original=C.string_at(C.byref(s),C.sizeof(s))
        for lease,t1,t2 in ((0,None,None),(86401,None,None),(120,0,50),(120,50,50),(120,60,50),(120,20,120),(120,0xffffffff,50)):
            a=None if t1 is None else t1.to_bytes(4,'big');b=None if t2 is None else t2.to_bytes(4,'big')
            self.assertEqual(self.lib.schedule(C.byref(s),SECOND,SECOND,lease.to_bytes(4,'big'),4,a,0 if a is None else 4,b,0 if b is None else 4),0)
            self.assertEqual(C.string_at(C.byref(s),C.sizeof(s)),original)
        for value in (b'',b'\1',b'\0'*3,b'\0'*5):
            self.assertEqual(self.lib.schedule(C.byref(s),SECOND,SECOND,(120).to_bytes(4,'big'),4,value,len(value),None,0),0)
        self.assertEqual(self.schedule(received=121*SECOND)[1],0)
        self.assertEqual(self.schedule(origin=2**64-SECOND)[1],0)
    def test_natural_boundaries_retries_do_not_expire_early(self):
        s,_=self.schedule(120,10,25);p=C.byref(s)
        self.assertEqual(self.lib.action(p,s.t1-1),0)
        self.assertEqual(self.lib.action(p,s.t1),1);self.lib.sent(p,s.t1)
        self.assertEqual(s.next,s.t2)
        self.assertEqual(self.lib.action(p,s.t2-1),0)
        self.assertEqual(self.lib.action(p,s.t2),2);self.lib.sent(p,s.t2)
        self.assertEqual(self.lib.action(p,86*SECOND),2);self.lib.sent(p,86*SECOND)
        self.assertEqual(self.lib.action(p,s.expiry-1),0)
        self.assertEqual(self.lib.action(p,s.expiry),3)
        self.assertEqual(self.lib.waiting(p,s.expiry),0)
    def test_delayed_ACK_uses_request_origin_not_receipt(self):
        s,ok=self.schedule(120,20,50,origin=SECOND,received=30*SECOND)
        self.assertEqual(ok,1);self.assertEqual(s.expiry,121*SECOND)
        self.assertEqual(self.lib.action(C.byref(s),30*SECOND),1)
    def test_wire_rejects_bad_timer_lengths_and_order(self):
        for extra in (b'\x3a\x01\x01',b'\x3a\x04\0\0\0\0',b'\x3a\x04\0\0\0\x32\x3b\x04\0\0\0\x28'):
            with self.assertRaises(ValueError):parse_frame(packet(5,extra=extra))
    def test_three_broadcast_attempts_retain_unexpired_lease(self):
        s,_=self.schedule(240,10,25);p=C.byref(s)
        for at in (26*SECOND,133500000000,193500000000):
            self.assertEqual(self.lib.action(p,at),2);self.lib.sent(p,at)
        self.assertEqual(s.attempts,3)
        self.assertLess(193500000000,s.expiry)
        self.assertEqual(self.lib.action(p,s.expiry-1),0)
        self.assertEqual(self.lib.action(p,s.expiry),3)
    def test_fault_server_packets_and_observer_cannot_authorize_invalid_timers(self):
        from tools.dhcp_timer_server import response,checksum
        from uplinkstead.dhcp_wire import DHCPTracker,dhcp_envelope
        from tests.test_dhcp_wire import MAC
        request=packet(3,xid=37)
        for opts in ({},{'58':10,'59':25},{'58':8}):
            frame=response(request,5,dict(lease=120,**opts),b'\2'*6)
            parsed=parse_frame(frame);self.assertEqual(parsed['xid'],37)
            self.assertEqual(checksum(frame[14:34]),0)
            self.assertTrue(dhcp_envelope(frame))
        frame=response(request,5,{'58':{'hex':'000001'}},b'\2'*6)
        self.assertTrue(parse_frame(frame,validate_timers=False)['timer_error'])
        tracker=DHCPTracker(MAC);tracker.feed(request,1.)
        with self.assertRaises(ValueError):tracker.feed(frame,2.)
        self.assertEqual(tracker.acks,{})
