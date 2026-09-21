import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import watchu_worker  # noqa: E402


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "watchu.sqlite"
        self.connection = sqlite3.connect(self.db_path)
        self.connection.executescript((ROOT / "database" / "schema.sql").read_text(encoding="utf-8"))
        self.connection.execute("INSERT INTO settings (setting_key, setting_value) VALUES ('dedupe_window_minutes', '15')")
        self.connection.commit()

    def tearDown(self):
        self.connection.close()
        self.temp.cleanup()

    def suricata_event(self):
        return {
            "timestamp": "2026-07-20T02:11:40+00:00",
            "src_ip": "10.10.10.117",
            "dest_ip": "198.51.100.27",
            "alert": {"signature": "ET MALWARE Possible Cobalt Strike", "category": "Command and Control", "severity": 1},
        }

    def test_scoring_marks_cobalt_strike_critical(self):
        event = watchu_worker.normalize_event(self.suricata_event())
        self.assertEqual("Critical", event.severity)
        self.assertEqual(100, event.score)

    def test_repeated_event_is_deduplicated(self):
        event = watchu_worker.normalize_event(self.suricata_event())
        first_id, first_created = watchu_worker.store_event(self.connection, event)
        second_id, second_created = watchu_worker.store_event(self.connection, event)
        self.connection.commit()
        row = self.connection.execute("SELECT event_count FROM incidents WHERE id = ?", (first_id,)).fetchone()
        self.assertTrue(first_created)
        self.assertFalse(second_created)
        self.assertEqual(first_id, second_id)
        self.assertEqual(2, row[0])

    def test_wazuh_event_uses_template_summary(self):
        raw = {"timestamp": datetime.now(timezone.utc).isoformat(), "rule": {"level": 10, "description": "Suspicious sudo use", "groups": ["privilege_escalation"]}, "agent": {"ip": "10.10.10.10"}}
        event = watchu_worker.normalize_event(raw)
        summary, provider = watchu_worker.ai_summary(event)
        self.assertEqual("template", provider)
        self.assertIn("Watch-U assigned", summary)


if __name__ == "__main__":
    unittest.main()

