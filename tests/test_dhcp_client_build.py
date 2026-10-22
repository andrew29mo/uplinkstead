import unittest
from tools.dhcp_client_build import transform, OLD, RENEW, LOST
from tests.test_dhcp_wire import MAC, LEASE, packet
from uplinkstead.dhcp_wire import DHCPTracker


class ClientBoundaryTests(unittest.TestCase):
    def test_exact_upstream_boundary_patch_and_no_silent_reapplication(self):
        source=OLD+'\n'+RENEW+'\n'+LOST
        result=transform(source)
        self.assertIn('issued >= 0x100000000ULL',result)
        self.assertIn('return next++;',result)
        self.assertIn('client_data.xid = random_xid(); /* Uplinkstead',result)
        for unsupported in (result,source+OLD,source.replace(RENEW,'')):
            with self.assertRaises(ValueError):transform(unsupported)

    def test_new_xid_extends_but_replayed_old_ACK_cannot_replace_it(self):
        t=DHCPTracker(MAC);t.feed(packet(3,xid=10),1.);t.feed(packet(5,xid=10),2.)
        first=t.claim(LEASE,3.)
        t.feed(packet(3,xid=11),30.)
        t.feed(packet(5,xid=10),31.)
        with self.assertRaises(ValueError):t.claim(LEASE,31.)
        t.feed(packet(5,xid=11),32.);second=t.claim(LEASE,33.)
        self.assertGreater(second['request_at'],first['request_at'])
        changed=packet(5,xid=10).replace(b'\x03\x04\xc0\x00\x02\x01',b'\x03\x04\xc0\x00\x02\x03')
        t.feed(changed,34.)
        self.assertEqual(t.invalidations,0) # Superseded transaction cannot withdraw the new one.
        t.feed(packet(3,xid=10),35.);t.feed(packet(5,xid=10),36.)
        with self.assertRaises(ValueError):t.claim(LEASE,37.)

    def test_unanswered_old_transaction_cannot_roll_back_newer_ACK(self):
        t=DHCPTracker(MAC)
        for xid,at in ((10,1.),(12,5.)):
            if xid==12:
                t.feed(packet(3,xid=11),4.)
            t.feed(packet(3,xid=xid),at);t.feed(packet(5,xid=xid),at+1)
            t.claim(LEASE,at+2)
        t.feed(packet(5,xid=11),8.)
        t.feed(packet(3,xid=11),9.);t.feed(packet(5,xid=11),10.)
        self.assertEqual(t.latest_xid,12);self.assertFalse(t.acks);self.assertEqual(t.invalidations,0)
        t.feed(packet(3,xid=13),11.);t.feed(packet(5,xid=13),12.)
        self.assertEqual(t.claim(LEASE,13.)['xid'],13)

    def test_request_watermark_retires_unanswered_attempt_before_next_ACK(self):
        t=DHCPTracker(MAC)
        t.feed(packet(3,xid=11),1.);t.feed(packet(3,xid=12),2.)
        t.feed(packet(5,xid=11),3.)
        self.assertFalse(t.acks);self.assertEqual(t.invalidations,0)
        t.feed(packet(5,xid=12),4.)
        self.assertEqual(t.claim(LEASE,5.)['xid'],12)

    def test_request_watermark_uses_order_not_numeric_xid(self):
        t=DHCPTracker(MAC)
        t.feed(packet(3,xid=0xffffffff),1.)
        t.feed(packet(3,xid=0),2.);t.feed(packet(5,xid=0xffffffff),3.)
        t.feed(packet(5,xid=0),4.)
        self.assertEqual(t.claim(LEASE,5.)['xid'],0)

    def test_loss_diagnostic_and_synthetic_delayed_ACK_preserve_allocation(self):
        import base64,hashlib
        from tools.dhcp_p0_wire import delayed_ack
        from tools.dhcp_p0_contract import loss_diagnostics
        from uplinkstead.dhcp_wire import parse_frame
        frame=packet(5,xid=11)
        template=dict(frame=base64.b64encode(frame).decode(),frame_sha256=hashlib.sha256(frame).hexdigest(),xid=11)
        changed=delayed_ack(template,12);parsed=parse_frame(base64.b64decode(changed['frame']))
        self.assertEqual(parsed['xid'],12);self.assertEqual(parsed['ip'],LEASE['ip'])
        self.assertNotEqual(changed['frame_sha256'],template['frame_sha256'])
        rows=loss_diagnostics('udhcpc: uplinkstead_loss if=wanB pid=321 xid=12 remaining=25 attempts=3\n')
        self.assertEqual(rows,[dict(interface='wanB',pid=321,xid=12,remaining=25,attempts=3)])
        self.assertFalse(loss_diagnostics('uplinkstead_loss if=other pid=321 xid=12 remaining=25 attempts=3'))

    def test_unverified_archive_never_creates_build_directory(self):
        import tempfile
        from pathlib import Path
        from tools.dhcp_client_build import build
        with tempfile.TemporaryDirectory() as d:
            archive=Path(d)/'bad';archive.write_bytes(b'not upstream source');directory=Path(d)/'build'
            with self.assertRaises(ValueError):build(archive,directory)
            self.assertFalse(directory.exists())
