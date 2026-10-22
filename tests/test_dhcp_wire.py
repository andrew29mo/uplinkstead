"""Wire evidence tests exercise the parser used by the Linux capture owner."""
import struct
import unittest
from uplinkstead.dhcp_wire import DHCPTracker, parse_frame

MAC = b'\x02\x00\x00\x00\x00\x01'
LEASE = dict(ip='192.0.2.2', subnet='24', router='192.0.2.1', lease='60')


def packet(kind, xid=1, mac=MAC, extra=b'', server=b'\xc0\x00\x02\x01'):
    body = bytearray(240)
    body[:3] = bytes((1 if kind == 3 else 2, 1, 6))
    body[4:8] = xid.to_bytes(4, 'big')
    body[28:34] = mac
    body[236:240] = b'\x63\x82\x53\x63'
    opts = bytes((53, 1, kind)) + bytes((54, 4)) + server
    if kind == 3:
        opts += b'\x32\x04\xc0\x00\x02\x02'
    else:
        body[16:20] = b'\xc0\x00\x02\x02'
        opts += b'\x01\x04\xff\xff\xff\x00\x03\x04\xc0\x00\x02\x01\x33\x04\x00\x00\x00\x3c'
    body += opts + extra + b'\xff'
    ports = (68, 67) if kind == 3 else (67, 68)
    udp = struct.pack('!HHHH', *ports, len(body)+8, 0) + body
    ip = bytearray(20)
    ip[0], ip[9] = 0x45, 17
    ip[2:4] = (len(udp)+20).to_bytes(2, 'big')
    return b'\x00'*12 + b'\x08\x00' + ip + udp


class WireTests(unittest.TestCase):
    def tracker(self):
        return DHCPTracker(MAC)

    def test_retransmission_keeps_earliest_conservative_request_bound(self):
        t = self.tracker()
        t.feed(packet(3), 10.)
        t.feed(packet(3), 20.)
        t.feed(packet(5), 21.)
        self.assertEqual(t.claim(LEASE, 25.), dict(request_at=10., observed_at=21., options=[]))
        with self.assertRaises(ValueError): t.claim(LEASE, 25.)
        t.feed(packet(5), 26.)
        with self.assertRaises(ValueError): t.claim(LEASE, 26.)

    def test_busybox_xid_reuse_requires_a_new_observed_request(self):
        t = self.tracker(); t.feed(packet(3),1.); t.feed(packet(5),2.)
        t.claim(LEASE,3.)
        t.feed(packet(5),4.)
        with self.assertRaises(ValueError): t.claim(LEASE,4.)
        t.feed(packet(3),30.); t.feed(packet(5),31.)
        self.assertEqual(t.claim(LEASE,32.)['request_at'],30.)

    def test_backlogged_capture_lower_bound_never_starts_at_hook(self):
        t = self.tracker()
        t.feed(packet(3), 10.)
        t.feed(packet(5), 10.)
        proof = t.claim(LEASE, 100.)
        self.assertEqual(proof['request_at'] + int(LEASE['lease']), 70.)
        self.assertLess(proof['request_at'] + 60, 100.)

    def test_missing_request_wrong_mac_xid_and_server_cannot_authorize(self):
        for request, ack in ((None, packet(5)), (packet(3),packet(5,xid=2)), (packet(3),packet(5,mac=b'123456')), (packet(3),packet(5,server=b'\xc0\x00\x02\x03'))):
            t = self.tracker()
            if request: t.feed(request, 1.)
            t.feed(ack, 2.)
            with self.assertRaises(ValueError): t.claim(LEASE, 3.)

    def test_hook_fields_must_exactly_match_wire(self):
        for field, value in (('ip','192.0.2.3'),('subnet','25'),('router','192.0.2.3'),('lease','61')):
            t = self.tracker(); t.feed(packet(3),1.); t.feed(packet(5),2.)
            with self.assertRaises(ValueError): t.claim(dict(LEASE,**{field:value}),3.)

    def test_route_option_presence_is_preserved(self):
        for code in (33,121,249):
            t = self.tracker(); t.feed(packet(3),1.)
            t.feed(packet(5,extra=bytes((code,1,0))),2.)
            self.assertEqual(t.claim(LEASE,3.)['options'], [str(code)])

    def test_malformed_headers_options_and_fragmentation_rejected(self):
        good = packet(5)
        malformed = [good[:100], good[:-1], packet(5,extra=b'\x35\x01\x05'), packet(5,extra=b'\x34\x01\x01')]
        frame = bytearray(good); frame[20] = 0x20; malformed.append(bytes(frame))
        frame = bytearray(good); frame[14] = 0x4f; malformed.append(bytes(frame))
        frame = bytearray(good); frame[43] = 2; malformed.append(bytes(frame))
        for frame in malformed:
            with self.assertRaises(ValueError): parse_frame(frame)

    def test_capacity_and_age_are_bounded_fail_closed(self):
        t = DHCPTracker(MAC,capacity=2,max_age=10.)
        for xid in (1,2,3): t.feed(packet(3,xid=xid),float(xid))
        self.assertLessEqual(len(t.requests),2)
        t.feed(packet(5,xid=1),4.)
        with self.assertRaises(ValueError): t.claim(LEASE,4.)
        t.feed(packet(5,xid=2),20.)
        with self.assertRaises(ValueError): t.claim(LEASE,20.)

    def test_ambiguous_xid_and_multiple_matching_acks_are_rejected(self):
        t = self.tracker(); t.feed(packet(3),1.)
        t.feed(packet(3,server=b'\xc0\x00\x02\x03'),2.)
        t.feed(packet(5),3.)
        with self.assertRaises(ValueError): t.claim(LEASE,3.)
        t = self.tracker()
        for xid in (1,2): t.feed(packet(3,xid=xid),float(xid*2)); t.feed(packet(5,xid=xid),float(xid*2+1))
        with self.assertRaises(ValueError): t.claim(LEASE,6.)

    def test_time_reversal_cannot_rebase_request(self):
        t = self.tracker(); t.feed(packet(3),10.)
        with self.assertRaises(ValueError): t.feed(packet(3),9.)
        with self.assertRaises(ValueError): t.claim(LEASE,9.)
