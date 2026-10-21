import unittest
from uplinkstead.policy import Policy, Settings


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.p = Policy(Settings(stable=4), 'cfg', 'boot')
        self.round = 0

    def feed(self, a, b, t):
        for k, value in [('A',a),('B',b)]:
            self.p.observe(k,self.round,t,t,t,value,'cfg','boot')
        self.round += 1

    def test_initial_success_requires_multiple_rounds(self):
        self.feed(3,3,1)
        self.assertEqual(self.p.candidate(None,1)[0],None)
        self.feed(3,3,2);self.feed(3,3,3)
        self.assertEqual(self.p.candidate(None,3)[0],'A')

    def test_failover_threshold(self):
        for t in (1,2,3): self.feed(3,3,t)
        for t in (4,5):
            self.feed(0,3,t);self.assertIsNone(self.p.candidate('A',t)[0])
        self.feed(0,3,6)
        self.assertEqual(self.p.candidate('A',6)[0],'B')

    def test_one_target_failure_not_link_failure(self):
        for t in (1,2,3):self.feed(2,3,t)
        self.assertEqual(self.p.links['A'].state,'HEALTHY')

    def test_unknown_not_destination(self):
        for t in (1,2,3):self.feed(0,None,t)
        self.assertIsNone(self.p.candidate('A',3)[0])

    def test_unknown_current_does_not_trigger_speculative_switch(self):
        for t in (1,2,3):self.feed(None,3,t)
        self.assertIsNone(self.p.candidate('A',3)[0])

    def test_default_never_preference_failback(self):
        for t in (1,2,3,10,20):self.feed(3,3,t)
        self.assertIsNone(self.p.candidate('B',20)[0])

    def test_auto_failback_requires_continuous_stability(self):
        self.p = Policy(Settings(stable=4,auto_failback=True),'cfg','boot')
        for t in range(1,5):self.feed(3,3,t)
        self.assertIsNone(self.p.candidate('B',4)[0])
        self.feed(3,3,5)
        self.assertEqual(self.p.candidate('B',5)[0],'A')

    def test_stability_gap_resets_recovery(self):
        self.p = Policy(Settings(stable=4,auto_failback=True),'cfg','boot')
        for t in (1,2,3):self.feed(3,3,t)
        self.feed(3,3,20)
        self.assertIsNone(self.p.candidate('B',20)[0])
        self.assertEqual(self.p.links['A'].good,1)

    def test_stale_wrong_boot_and_wrong_config_rejected(self):
        for kwargs in [dict(config_hash='old',boot='boot'),dict(config_hash='cfg',boot='old')]:
            self.assertFalse(self.p.observe('A',0,0,0,0,3,**kwargs))
        self.assertEqual(self.p.links['A'].good,0)

    def test_reordered_round_rejected(self):
        self.feed(0,3,1)
        self.assertFalse(self.p.observe('A',0,1,1,1,3,'cfg','boot'))
        self.assertEqual(self.p.links['A'].bad,1)

    def test_expired_result_breaks_streak(self):
        self.feed(3,3,1)
        self.assertFalse(self.p.observe('A',1,2,2,5,3,'cfg','boot'))
        self.assertEqual(self.p.links['A'].state,'UNKNOWN')
        self.assertEqual(self.p.links['A'].good,0)

    def test_missing_round_expires_health(self):
        for t in (1,2,3):self.feed(3,3,t)
        self.assertEqual(self.p.candidate('A',6)[1],'NO_HEALTHY_UPLINK')

    def test_budget_latches_and_restart_retains_latch(self):
        self.p.history=[dict(boot='boot',at=t) for t in (1,2,3)]
        for t in (4,5,6):self.feed(0,3,t)
        self.assertEqual(self.p.candidate('A',6)[1],'DEGRADED_LATCHED')
        p=Policy(self.p.s,'cfg','boot',self.p.history,self.p.latched)
        self.assertEqual(p.candidate('A',10)[1],'DEGRADED_LATCHED')

    def test_cross_boot_budget_not_replenished_by_reboot(self):
        self.p.history=[dict(boot='previous',at=9999) for _ in range(3)]
        for t in (1,2,3):self.feed(0,3,t)
        self.assertEqual(self.p.candidate('A',3)[1],'DEGRADED_LATCHED')

    def test_history_expires_same_boot_without_process_reset(self):
        self.p.history=[dict(boot='boot',at=t) for t in (1,2,3)]
        for t in (70,71,72):self.feed(0,3,t)
        self.assertEqual(self.p.candidate('A',72)[0],'B')

    def test_invalid_settings(self):
        for options in (dict(failures=0),dict(stable=float('nan')),dict(auto_failback=1)):
            with self.assertRaises(ValueError): Settings(**options)
