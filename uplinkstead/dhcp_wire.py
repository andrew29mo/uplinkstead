"""Bounded DHCP wire evidence. No clock, network or routing side effects.

The capture owner supplies CLOCK_BOOTTIME receive timestamps on the dedicated
interface. Timestamps are conservative lower bounds established before draining
the capture queue, not user-space packet receive times. A lease starts at the
first matching REQUEST lower bound, never at hook
execution. Missing, truncated or ambiguous evidence cannot authorize a lease.
"""
import ipaddress
import math
import struct


def _time(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def parse_frame(frame):
    """Parse an unfragmented Ethernet/IPv4/UDP DHCP packet, or raise ValueError."""
    if not isinstance(frame, bytes) or not 14 + 20 + 8 + 240 <= len(frame) <= 65535:
        raise ValueError('Invalid frame size')
    if frame[12:14] != b'\x08\x00':
        raise ValueError('Only untagged IPv4 supported')
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], 'big')
    if ip[0] >> 4 != 4 or ihl < 20 or total < ihl + 8 + 240 or total > len(ip) or ip[9] != 17 or int.from_bytes(ip[6:8], 'big') & 0x3fff:
        raise ValueError('Invalid IPv4 UDP datagram')
    udp = ip[ihl:total]
    src, dst, size = struct.unpack('!HHH', udp[:6])
    if (src, dst) not in ((68, 67), (67, 68)) or size != len(udp):
        raise ValueError('Invalid DHCP UDP envelope')
    body = udp[8:]
    if body[0] != (1 if src == 68 else 2) or body[1:3] != b'\x01\x06' or body[236:240] != b'\x63\x82\x53\x63':
        raise ValueError('Invalid BOOTP header')
    opts, pos, ended = {}, 240, False
    while pos < len(body):
        code = body[pos]; pos += 1
        if code == 0:
            continue
        if code == 255:
            ended = True
            break
        if pos >= len(body):
            raise ValueError('Missing option length')
        length = body[pos]; pos += 1
        if pos + length > len(body) or code in opts:
            raise ValueError('Truncated or duplicate option')
        opts[code] = body[pos:pos+length]; pos += length
    if not ended or opts.get(53) not in (b'\x03', b'\x05') or 52 in opts:
        raise ValueError('Unsupported DHCP message/option overload')
    kind = opts[53][0]
    if kind != (3 if src == 68 else 5):
        raise ValueError('Message direction mismatch')
    for code in (1, 50, 51, 54):
        if code in opts and len(opts[code]) != 4:
            raise ValueError('Invalid fixed option')
    if 3 in opts and len(opts[3]) != 4:
        raise ValueError('Exactly one router required')
    addr = lambda b: str(ipaddress.IPv4Address(b))
    result = dict(type=kind, xid=int.from_bytes(body[4:8], 'big'), chaddr=body[28:34],
                  ip=addr(body[16:20]), ciaddr=addr(body[12:16]),
                  requested=addr(opts[50]) if 50 in opts else None,
                  server=addr(opts[54]) if 54 in opts else None,
                  options=[str(c) for c in (33, 121, 249) if c in opts])
    if kind == 5:
        if not all(c in opts for c in (1, 3, 51, 54)):
            raise ValueError('Incomplete ACK')
        result.update(lease=str(int.from_bytes(opts[51], 'big')), subnet=addr(opts[1]), router=addr(opts[3]))
    return result


class DHCPTracker:
    def __init__(self, mac, capacity=64, max_age=86400):
        if not isinstance(mac, bytes) or len(mac) != 6 or type(capacity) is not int or not 1 <= capacity <= 256 or not _time(max_age) or max_age <= 0:
            raise ValueError('Invalid tracker limits')
        self.mac, self.capacity, self.max_age = mac, capacity, max_age
        self.requests, self.acks, self.used = {}, {}, {}
        # Session-long history is never aged/evicted: DHCP carries no renewal
        # sequence, and BusyBox reuses xid. An identical delayed ACK cannot be
        # distinguished from a fresh reply. Cap it at the first proven deadline.
        self.history, self.exhausted, self.invalidations = {}, False, 0
        self.latest_xid = None
        self.latest_request = None
        self.last_at = 0.

    def invalidate(self, key):
        history = self.history[key]
        if not history.get('invalid'):
            history['invalid'] = True
            if key == self.latest_xid: self.invalidations += 1
        self.requests.pop(key, None)
        self.acks.pop(key, None)

    def feed(self, frame, at):
        if not _time(at) or at < self.last_at:
            raise ValueError('Invalid capture time')
        self.last_at = at
        for store in (self.requests, self.acks, self.used):
            for key, value in list(store.items()):
                if at - value['at'] > self.max_age:
                    del store[key]
        packet = parse_frame(frame)
        if packet['chaddr'] != self.mac:
            return None
        if self.exhausted:
            raise ValueError('Wire session history exhausted; fresh client required')
        key = packet['xid']
        if packet['type'] == 3:
            requested = packet['requested'] or packet['ciaddr']
            if requested == '0.0.0.0':
                raise ValueError('REQUEST has no address identity')
            if key not in self.history:
                if len(self.history) >= self.capacity:
                    self.exhausted = True
                    self.invalidations += 1
                    self.requests.clear(); self.acks.clear()
                    raise ValueError('Wire session history exhausted; fresh client required')
                self.history[key] = dict(at=at, address=requested, packet=None)
                # Only a first-seen REQUEST advances transaction authority.
                # An unanswered attempt is retired too; a late ACK must not
                # roll back the watermark after a newer successful transaction.
                if self.latest_request is not None:
                    self.history[self.latest_request]['superseded'] = True
                    self.requests.pop(self.latest_request,None)
                    self.acks.pop(self.latest_request,None)
                self.latest_request = key
            history = self.history[key]
            if history.get('superseded'): return packet['type']
            canonical = history['packet']
            if history.get('invalid') or requested != history['address'] or (canonical and packet['server'] is not None and packet['server'] != canonical['server']):
                self.invalidate(key)
                return packet['type']
            if key in self.used:
                del self.used[key]
            identity = (requested, packet['server'])
            previous = self.requests.get(key)
            # Same xid with differing address/server is ambiguous, never rebased.
            if previous and previous['identity'] != identity:
                self.invalidate(key)
            elif not previous and key not in self.used:
                self.requests[key] = dict(at=at, origin=history['at'], identity=identity, ambiguous=False)
        else:
            history = self.history.get(key)
            if history and history.get('superseded'): return packet['type']
            # ciaddr is zero during selection and populated during renewal;
            # it is not a change in the offered allocation. Compare all parsed
            # allocation semantics, not incidental BOOTP transport fields.
            allocation = {k:packet[k] for k in ('ip','subnet','router','lease','server','options')}
            if history and history['packet'] is not None and allocation != history['packet']:
                self.invalidate(key)
            if history and history.get('invalid'):
                return packet['type']
            request = self.requests.get(key)
            if request and not request['ambiguous'] and key not in self.used and request['identity'][0] == packet['ip'] and (request['identity'][1] is None or request['identity'][1] == packet['server']):
                if history['packet'] is None: history['packet'] = allocation
                if key not in self.acks:
                    if self.latest_xid is not None and self.latest_xid != key:
                        self.history[self.latest_xid]['superseded'] = True
                    self.latest_xid = key
                self.acks.setdefault(key, dict(at=at, request_at=request['origin'], packet=packet))
        for store in (self.requests, self.acks, self.used):
            while len(store) > self.capacity:
                del store[next(iter(store))]
        return packet['type']

    def claim(self, lease, at):
        if not _time(at) or at < self.last_at:
            raise ValueError('Invalid claim time')
        matches = []
        for key, ack in self.acks.items():
            p = ack['packet']
            expected = dict(ip=p['ip'], subnet=p['subnet'], router=p['router'], lease=p['lease'])
            # Hook may represent a contiguous mask as its prefix length.
            try:
                same_mask = ipaddress.IPv4Network('0.0.0.0/' + str(lease['subnet'])).netmask == ipaddress.IPv4Address(p['subnet'])
                matches_lease = set(lease) == set(expected) and all(str(lease[k]) == expected[k] for k in ('ip', 'router', 'lease')) and same_mask
            except (KeyError, TypeError, ValueError):
                matches_lease = False
            request = self.requests.get(key)
            if matches_lease and request and not request['ambiguous'] and at - ack['at'] <= self.max_age and key not in self.used:
                matches.append((key, ack))
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous wire ACK proof')
        key, ack = matches[0]
        self.used[key] = dict(at=at)
        del self.acks[key]
        self.requests.pop(key, None)
        return dict(request_at=ack['request_at'], observed_at=ack['at'], options=ack['packet']['options'], xid=key)
