import json
import unittest
from tools.netproof import nft_semantics,xt_semantics


class NetworkProofTests(unittest.TestCase):
    def test_only_nft_counter_values_and_handles_ignored(self):
        a={'rule':{'handle':1,'expr':[{'counter':{'packets':2,'bytes':20}},{'accept':None}]}}
        b={'rule':{'handle':7,'expr':[{'counter':{'packets':8,'bytes':80}},{'accept':None}]}}
        self.assertEqual(nft_semantics(a),nft_semantics(b))
        b['rule']['expr'][1]={'drop':None}
        self.assertNotEqual(nft_semantics(a),nft_semantics(b))
    def test_meaningful_bytes_operand_not_ignored(self):
        self.assertNotEqual(nft_semantics({'limit':{'bytes':100}}),nft_semantics({'limit':{'bytes':200}}))
    def test_xt_rule_comment_not_mistaken_for_counter(self):
        self.assertNotEqual(xt_semantics('-A INPUT -m comment --comment [1:20] -j ACCEPT'),xt_semantics('-A INPUT -m comment --comment [3:40] -j ACCEPT'))

    def test_rule_order_preserved(self):
        self.assertNotEqual(nft_semantics([{'accept':None},{'drop':None}]),nft_semantics([{'drop':None},{'accept':None}]))
    def test_xt_counters_and_timestamp_comments_only(self):
        self.assertEqual(xt_semantics('# Generated at x\n:INPUT ACCEPT [1:20]\n-A INPUT -s 1.2.3.4 -j ACCEPT\n'),xt_semantics('# Generated at y\n:INPUT ACCEPT [3:40]\n-A INPUT -s 1.2.3.4 -j ACCEPT\n'))
        self.assertNotEqual(xt_semantics('-A INPUT -j ACCEPT'),xt_semantics('-A INPUT -j DROP'))
