"""
Integration tests for CLI functionality.
"""

import os
import tempfile
import unittest
from telemetry_warden.cli import perform_audit


class TestCliIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_audit.db")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_perform_audit_end_to_end(self):
        report = perform_audit(
            gateway_ip="192.168.1.1",
            wan_iface="eth0",
            db_path=self.db_path,
            commit_ledger=True,
        )
        self.assertGreater(report.total_devices_scanned, 0)
        self.assertGreater(report.ledger_block_index, 0)
        self.assertTrue(len(report.ledger_block_hash) == 64)
        self.assertTrue(os.path.exists(self.db_path))


if __name__ == "__main__":
    unittest.main()
