"""
Unit tests for TrafficAccountingEngine.
"""

import unittest
from telemetry_warden.engine.accounting import TrafficAccountingEngine
from telemetry_warden.models import DeviceCategory, DeviceNode, ThreatLevel


class TestTrafficAccounting(unittest.TestCase):
    def test_assess_clean_device(self):
        dev = DeviceNode(ip="192.168.1.150", hostname="desktop.lan", category=DeviceCategory.COMPUTE)
        # 10% WAN, 90% LAN
        assessment = TrafficAccountingEngine.assess_device_leak(dev, total_tx=100000, wan_tx=10000)
        self.assertEqual(assessment.threat_level, ThreatLevel.CLEAN)
        self.assertAlmostEqual(assessment.outbound_leak_ratio, 0.10, places=2)

    def test_assess_high_exfiltration(self):
        dev = DeviceNode(ip="192.168.1.140", hostname="smart-tv.lan", category=DeviceCategory.SMART_TV)
        # 95% WAN
        assessment = TrafficAccountingEngine.assess_device_leak(dev, total_tx=100000, wan_tx=95000)
        self.assertEqual(assessment.threat_level, ThreatLevel.HIGH_EXFILTRATION)
        self.assertAlmostEqual(assessment.outbound_leak_ratio, 0.95, places=2)

    def test_verify_camera_private(self):
        cam = DeviceNode(ip="192.168.1.139", hostname="eufy-cam.lan", category=DeviceCategory.SECURITY_CAMERA)
        # 2 Mbps camera ingress, only 0.02 Mbps WAN uplink (stays local to NVR)
        verif = TrafficAccountingEngine.verify_camera_stream(
            camera_node=cam,
            cam_ingress_bps=2000000.0,
            wan_uplink_bps=20000.0,
        )
        self.assertTrue(verif.is_verified_local_private)
        self.assertIn("VERIFIED PRIVATE", verif.notes)

    def test_verify_camera_cloud_leak(self):
        cam = DeviceNode(ip="192.168.1.139", hostname="cloud-cam.lan", category=DeviceCategory.SECURITY_CAMERA)
        # 2 Mbps camera ingress, and 1.95 Mbps WAN uplink (streaming up to cloud!)
        verif = TrafficAccountingEngine.verify_camera_stream(
            camera_node=cam,
            cam_ingress_bps=2000000.0,
            wan_uplink_bps=1950000.0,
        )
        self.assertFalse(verif.is_verified_local_private)
        self.assertIn("POTENTIAL CLOUD LEAK", verif.notes)


if __name__ == "__main__":
    unittest.main()
