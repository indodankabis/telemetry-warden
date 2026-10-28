"""
Unit tests for AnomalyEngine.
"""

import unittest
from telemetry_warden.engine.anomaly import AnomalyEngine
from telemetry_warden.models import DeviceCategory, LeakAssessment, ThreatLevel


class TestAnomalyEngine(unittest.TestCase):
    def test_detect_iot_outlier(self):
        a1 = LeakAssessment(
            ip="192.168.1.50",
            hostname="workstation.local",
            category=DeviceCategory.COMPUTE,
            total_tx_bytes=1000000,
            wan_tx_bytes=100000,
            local_tx_bytes=900000,
            outbound_leak_ratio=0.10,
            threat_level=ThreatLevel.CLEAN,
            reason="Clean",
        )
        a2 = LeakAssessment(
            ip="192.168.1.80",
            hostname="roku-tv.local",
            category=DeviceCategory.SMART_TV,
            total_tx_bytes=500000,
            wan_tx_bytes=450000,
            local_tx_bytes=50000,
            outbound_leak_ratio=0.90,
            threat_level=ThreatLevel.HIGH_EXFILTRATION,
            reason="Leaking",
        )

        suspicious = AnomalyEngine.detect_burst_anomalies([a1, a2])
        self.assertEqual(len(suspicious), 1)
        self.assertEqual(suspicious[0].ip, "192.168.1.80")
        self.assertEqual(suspicious[0].threat_level, ThreatLevel.HIGH_EXFILTRATION)


if __name__ == "__main__":
    unittest.main()
