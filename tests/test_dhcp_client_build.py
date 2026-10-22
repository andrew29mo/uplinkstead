import unittest
from tools.dhcp_client_build import transform, OLD, RENEW
from tests.test_dhcp_wire import MAC, LEASE, packet
from uplinkstead.dhcp_wire import DHCPTracker


class ClientBoundaryTests(unittest.TestCase):
    def test_exact_upstream_boundary_patch_and_no_silent_reapplication(self):
        source=OLD+'\n'+RENEW
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
