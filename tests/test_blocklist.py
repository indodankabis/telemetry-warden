"""
Unit tests for BlocklistGenerator.
"""

import unittest
from telemetry_warden.engine.blocklist import BlocklistGenerator
from telemetry_warden.models import DeviceCategory, LeakAssessment, ThreatLevel


class TestBlocklistGenerator(unittest.TestCase):
    def test_clean_device_generates_no_rules(self):
        a = LeakAssessment(
            ip="192.168.1.10",
            hostname="clean.lan",
            category=DeviceCategory.COMPUTE,
            total_tx_bytes=1000,
            wan_tx_bytes=50,
            local_tx_bytes=950,
            outbound_leak_ratio=0.05,
            threat_level=ThreatLevel.CLEAN,
            reason="Clean",
        )
        rules = BlocklistGenerator.generate_rules_for_leak(a)
        self.assertEqual(len(rules), 0)

    def test_leaking_tv_generates_iptables_and_dns(self):
        a = LeakAssessment(
            ip="192.168.1.200",
            hostname="smart-tv.lan",
            category=DeviceCategory.SMART_TV,
            total_tx_bytes=100000,
            wan_tx_bytes=90000,
            local_tx_bytes=10000,
            outbound_leak_ratio=0.90,
            threat_level=ThreatLevel.HIGH_EXFILTRATION,
            reason="Heavy telemetry leak",
        )
        rules = BlocklistGenerator.generate_rules_for_leak(a, wan_interface="eth0")
        types = [r.rule_type for r in rules]
        self.assertIn("iptables", types)
        self.assertIn("nftables", types)
        self.assertIn("pihole", types)
        self.assertIn("hosts", types)

        # Check that iptables drops WAN without blocking local subnet
        iptables_rule = next(r for r in rules if r.rule_type == "iptables")
        self.assertEqual(iptables_rule.command_or_line, "sudo iptables -I FORWARD -s 192.168.1.200 -o eth0 -j DROP")


if __name__ == "__main__":
    unittest.main()
