import unittest

from sim.synthetic_simulator import DefensivePolicyEngine, Event, Policy, TCP_SYN, UDP, ICMP


class TestSyntheticPolicy(unittest.TestCase):
    def test_allowlist_overrides_blocklist(self):
        engine = DefensivePolicyEngine(
            Policy(), allowlist={"198.51.100.1"}, blocklist={"198.51.100.1"}
        )
        self.assertEqual(engine.evaluate(Event(0, "198.51.100.1", TCP_SYN, 443)), "PASS")

    def test_blocklist_drops(self):
        engine = DefensivePolicyEngine(Policy(), blocklist={"198.51.100.2"})
        self.assertEqual(engine.evaluate(Event(0, "198.51.100.2", UDP, 53)), "DROP:blocklist")

    def test_reputation_drops(self):
        engine = DefensivePolicyEngine(Policy(reputation_drop_score=80), reputation={"198.51.100.3": 90})
        self.assertEqual(engine.evaluate(Event(0, "198.51.100.3", ICMP, 0)), "DROP:reputation")

    def test_syn_rate_limit(self):
        engine = DefensivePolicyEngine(Policy(syn_pps_limit=2))
        self.assertEqual(engine.evaluate(Event(0, "198.51.100.4", TCP_SYN, 443)), "PASS")
        self.assertEqual(engine.evaluate(Event(100, "198.51.100.4", TCP_SYN, 443)), "PASS")
        self.assertEqual(engine.evaluate(Event(200, "198.51.100.4", TCP_SYN, 443)), "DROP:tcp_syn_rate")

    def test_window_resets(self):
        engine = DefensivePolicyEngine(Policy(icmp_pps_limit=1))
        self.assertEqual(engine.evaluate(Event(0, "198.51.100.5", ICMP, 0)), "PASS")
        self.assertEqual(engine.evaluate(Event(999, "198.51.100.5", ICMP, 0)), "DROP:icmp_rate")
        self.assertEqual(engine.evaluate(Event(1000, "198.51.100.5", ICMP, 0)), "PASS")

    def test_audit_only(self):
        engine = DefensivePolicyEngine(Policy(audit_only=True), blocklist={"198.51.100.6"})
        self.assertEqual(engine.evaluate(Event(0, "198.51.100.6", UDP, 53)), "AUDIT:blocklist")


if __name__ == "__main__":
    unittest.main()
