import io
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import wazuh_live  # noqa: E402


class FakeSFTP:
    def __init__(self, content: bytes):
        self.content = content

    def open(self, path: str, mode: str):
        assert path == "/var/ossec/logs/alerts/alerts.json"
        assert mode == "rb"
        return io.BytesIO(self.content)

    def stat(self, path: str):
        assert path == "/var/ossec/logs/alerts/alerts.json"
        return SimpleNamespace(st_size=len(self.content))


class WazuhLiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "watchu.sqlite"
        self.connection = sqlite3.connect(self.db_path)
        self.connection.executescript((ROOT / "database" / "schema.sql").read_text(encoding="utf-8"))
        self.path = "/var/ossec/logs/alerts/alerts.json"
        self.source = "192.168.1.10:22:" + self.path

    def tearDown(self):
        self.connection.close()
        self.temp.cleanup()

    def alert(self, title: str) -> bytes:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"level": 10, "description": title, "groups": ["authentication"]},
            "agent": {"ip": "192.168.1.20"},
        }
        return json.dumps(event).encode("utf-8") + b"\n"

    def ingest(self, content: bytes, from_start: bool = False):
        identity = wazuh_live.file_signature(content[:wazuh_live.IDENTITY_BYTES])
        return wazuh_live.ingest_snapshot(
            self.connection, FakeSFTP(content), self.source, self.path, identity, len(content), from_start
        )

    def test_first_run_skips_old_alerts_then_only_reads_new_bytes(self):
        old = self.alert("Old alert")
        self.assertEqual(len(old), self.ingest(old)["skipped_backlog"])
        self.assertEqual(0, self.connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])

        combined = old + self.alert("New alert")
        self.assertEqual(1, self.ingest(combined)["created"])
        self.connection.close()
        self.connection = sqlite3.connect(self.db_path)
        self.assertEqual(0, self.ingest(combined)["read"])
        self.assertEqual(1, self.connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])

    def test_from_start_keeps_existing_deduplication(self):
        alert = self.alert("Repeated alert")
        stats = self.ingest(alert + alert, from_start=True)
        self.assertEqual(1, stats["created"])
        self.assertEqual(1, stats["deduplicated"])
        self.assertEqual(2, self.connection.execute("SELECT event_count FROM incidents").fetchone()[0])

    def test_partial_line_waits_and_rotation_reads_new_file(self):
        first = self.alert("First alert")
        self.assertEqual(0, self.ingest(first[:-3], from_start=True)["read"])
        self.assertEqual(1, self.ingest(first)["created"])
        replacement = self.alert("After rotation")
        rotated = self.ingest(replacement)
        self.assertTrue(rotated["rotated"])
        self.assertEqual(1, rotated["created"])
        self.assertEqual(2, self.connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])

    def test_trailing_partial_line_does_not_spin_without_new_bytes(self):
        complete = self.alert("Complete alert")
        partial = self.alert("Later alert")[:-2]
        stats = self.ingest(complete + partial, from_start=True)
        self.assertEqual(1, stats["created"])
        self.assertFalse(stats["has_more"])
        self.assertEqual(1, self.ingest(complete + partial + b"}\n")["created"])

    def test_malformed_complete_line_is_skipped_once(self):
        content = b"not-json\n" + self.alert("Valid alert")
        stats = self.ingest(content, from_start=True)
        self.assertEqual(1, stats["invalid"])
        self.assertEqual(1, stats["created"])
        self.assertEqual(0, self.ingest(content)["read"])

    def test_existing_database_gets_cursor_table(self):
        self.connection.execute("DROP TABLE wazuh_ingest_cursor")
        wazuh_live.ensure_cursor_table(self.connection)
        self.assertIsNotNone(self.connection.execute("SELECT name FROM sqlite_master WHERE name = 'wazuh_ingest_cursor'").fetchone())

    def test_sftp_file_identity_stays_stable_on_append_and_changes_on_rotation(self):
        first = self.alert("First alert")
        identity, size = wazuh_live.remote_file_state(FakeSFTP(first), self.path)
        appended_identity, _ = wazuh_live.remote_file_state(FakeSFTP(first + self.alert("Second alert")), self.path)
        replacement_identity, _ = wazuh_live.remote_file_state(FakeSFTP(self.alert("Replacement")), self.path)
        self.assertEqual(len(first), size)
        self.assertEqual(identity, appended_identity)
        self.assertNotEqual(identity, replacement_identity)

    def test_database_failure_rolls_back_incident_and_cursor_together(self):
        alert = self.alert("Retry after failure")
        real_store = wazuh_live.watchu_worker.store_event

        def fail_after_insert(connection, event):
            real_store(connection, event)
            raise sqlite3.OperationalError("simulated write failure")

        with patch.object(wazuh_live.watchu_worker, "store_event", side_effect=fail_after_insert):
            with self.assertRaises(sqlite3.OperationalError):
                self.ingest(alert, from_start=True)
        self.assertEqual(0, self.connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])
        self.assertEqual(0, self.connection.execute("SELECT byte_offset FROM wazuh_ingest_cursor").fetchone()[0])
        self.assertEqual(1, self.ingest(alert)["created"])


if __name__ == "__main__":
    unittest.main()
