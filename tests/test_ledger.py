"""
Unit tests for LocalAuditLedger.
"""

import os
import tempfile
import unittest
from telemetry_warden.storage.ledger import LocalAuditLedger


class TestLocalAuditLedger(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_ledger.db")
        self.ledger = LocalAuditLedger(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_commit_and_verify_chain(self):
        b1, h1 = self.ledger.commit_audit_event("AUDIT_PULSE", {"scanned": 10}, "2026-10-28T00:00:00Z")
        self.assertEqual(b1, 1)

        b2, h2 = self.ledger.commit_audit_event("AUDIT_PULSE", {"scanned": 12}, "2026-10-28T01:00:00Z")
        self.assertEqual(b2, 2)

        valid, count, err = self.ledger.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(count, 2)
        self.assertIsNone(err)

    def test_tamper_detection(self):
        self.ledger.commit_audit_event("AUDIT_PULSE", {"scanned": 5}, "2026-10-28T00:00:00Z")
        self.ledger.commit_audit_event("AUDIT_PULSE", {"scanned": 8}, "2026-10-28T01:00:00Z")

        # Tamper directly with the database
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        with conn:
            conn.execute("UPDATE audit_chain SET payload_json = '{\"scanned\": 999}' WHERE block_index = 1")
        conn.close()

        valid, count, err = self.ledger.verify_integrity()
        self.assertFalse(valid)
        self.assertIn("Hash mismatch", err)


if __name__ == "__main__":
    unittest.main()
