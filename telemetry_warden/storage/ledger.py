"""
Local Verifiable Cryptographic Ledger.
Append-only SQLite storage with SHA-256 block chaining. 100% offline.
"""

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class LocalAuditLedger:
    def __init__(self, db_path: str = "telemetry_audit.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_chain (
                        block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        prev_block_hash TEXT NOT NULL,
                        block_hash TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_chain_timestamp ON audit_chain(timestamp)"
                )
        finally:
            conn.close()

    def _compute_hash(self, prev_hash: str, timestamp: str, event_type: str, payload_str: str) -> str:
        blob = f"{prev_hash}:{timestamp}:{event_type}:{payload_str}".encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def get_latest_block(self) -> Optional[Tuple[int, str, str, str, str]]:
        """Returns (block_index, timestamp, event_type, prev_block_hash, block_hash)."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute(
                "SELECT block_index, timestamp, event_type, prev_block_hash, block_hash "
                "FROM audit_chain ORDER BY block_index DESC LIMIT 1"
            ).fetchone()
            return row
        finally:
            conn.close()

    def commit_audit_event(self, event_type: str, payload: Dict[str, Any], timestamp: str) -> Tuple[int, str]:
        """
        Commits an immutable audit record to the local ledger.
        Returns (block_index, block_hash).
        """
        payload_str = json.dumps(payload, sort_keys=True)
        conn = sqlite3.connect(str(self.db_path))
        try:
            with conn:
                latest = conn.execute(
                    "SELECT block_index, block_hash FROM audit_chain ORDER BY block_index DESC LIMIT 1"
                ).fetchone()

                if latest:
                    prev_index, prev_hash = latest
                    new_index = prev_index + 1
                else:
                    new_index = 1
                    prev_hash = "0" * 64

                block_hash = self._compute_hash(prev_hash, timestamp, event_type, payload_str)

                conn.execute(
                    """
                    INSERT INTO audit_chain (block_index, timestamp, event_type, payload_json, prev_block_hash, block_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (new_index, timestamp, event_type, payload_str, prev_hash, block_hash),
                )
                return new_index, block_hash
        finally:
            conn.close()

    def verify_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Validates the entire local chain.
        Returns (is_valid, total_blocks_verified, error_message).
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute(
                "SELECT block_index, timestamp, event_type, payload_json, prev_block_hash, block_hash "
                "FROM audit_chain ORDER BY block_index ASC"
            ).fetchall()

            if not rows:
                return True, 0, None

            expected_prev = "0" * 64
            for idx, r in enumerate(rows):
                b_idx, ts, ev_type, p_json, prev_h, b_h = r
                if prev_h != expected_prev:
                    return False, idx, f"Broken chain link at block {b_idx}: expected prev {expected_prev}, got {prev_h}"

                computed = self._compute_hash(prev_h, ts, ev_type, p_json)
                if computed != b_h:
                    return False, idx, f"Hash mismatch at block {b_idx}: computed {computed}, recorded {b_h}"

                expected_prev = b_h

            return True, len(rows), None
        finally:
            conn.close()
