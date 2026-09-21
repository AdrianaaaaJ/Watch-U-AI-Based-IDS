#!/usr/bin/env python3
"""Watch-U JSON ingestion worker.

Accepts Suricata EVE JSON or Wazuh alert JSON, applies deterministic scoring,
deduplicates repeated signals, and stores incidents in the Watch-U SQLite DB.
Optional AI and Telegram integrations fail safely back to local behaviour.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_env(ROOT / ".env")


@dataclass(frozen=True)
class NormalizedEvent:
    source: str
    title: str
    category: str
    src_ip: str | None
    dest_ip: str | None
    score: int
    severity: str
    occurred_at: datetime
    raw: dict[str, Any]

    @property
    def base_fingerprint(self) -> str:
        parts = [self.source, self.title, self.category, self.src_ip or "local", self.dest_ip or "host"]
        return hashlib.sha256("|".join(part.lower().strip() for part in parts).encode("utf-8")).hexdigest()


def parse_timestamp(value: Any) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def severity_for_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def category_modifier(category: str, title: str) -> int:
    text = f"{category} {title}".lower()
    modifiers = {
        "command and control": 12,
        "cobalt strike": 14,
        "malware": 12,
        "exfiltration": 12,
        "ransomware": 18,
        "privilege escalation": 10,
        "persistence": 8,
        "administrator": 7,
        "authentication": 4,
        "reconnaissance": -4,
        "policy": -8,
    }
    return sum(value for keyword, value in modifiers.items() if keyword in text)


def normalize_event(event: dict[str, Any]) -> NormalizedEvent:
    if isinstance(event.get("alert"), dict):
        alert = event["alert"]
        title = str(alert.get("signature") or "Suricata network alert")
        category = str(alert.get("category") or "Network Detection")
        priority = int(alert.get("severity") or alert.get("priority") or 3)
        base = {1: 84, 2: 64, 3: 42}.get(priority, 34)
        source = "Suricata"
        src_ip = event.get("src_ip")
        dest_ip = event.get("dest_ip")
    elif isinstance(event.get("rule"), dict):
        rule = event["rule"]
        title = str(rule.get("description") or "Wazuh host alert")
        groups = rule.get("groups") or []
        category = str(groups[0] if isinstance(groups, list) and groups else "Host Detection").replace("_", " ").title()
        level = max(0, min(15, int(rule.get("level") or 3)))
        base = round(18 + level * 5.1)
        source = "Wazuh"
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        agent = event.get("agent") if isinstance(event.get("agent"), dict) else {}
        src_ip = data.get("srcip") or data.get("src_ip") or agent.get("ip")
        dest_ip = data.get("dstip") or data.get("dest_ip")
    else:
        raise ValueError("JSON is neither a Suricata alert nor a Wazuh rule event")

    score = max(0, min(100, base + category_modifier(category, title)))
    return NormalizedEvent(
        source=source,
        title=title[:240],
        category=category[:120],
        src_ip=str(src_ip)[:64] if src_ip else None,
        dest_ip=str(dest_ip)[:64] if dest_ip else None,
        score=score,
        severity=severity_for_score(score),
        occurred_at=parse_timestamp(event.get("timestamp")),
        raw=event,
    )


def template_summary(event: NormalizedEvent) -> str:
    origin = event.src_ip or "a local endpoint"
    destination = f" toward {event.dest_ip}" if event.dest_ip else ""
    return (
        f"{event.source} detected {event.title.lower()} from {origin}{destination}. "
        f"Watch-U assigned {event.severity} severity ({event.score}/100) in the {event.category} category. "
        "Validate the source, correlate nearby authentication and endpoint activity, then contain the affected asset if confirmed."
    )


def ai_summary(event: NormalizedEvent) -> tuple[str, str]:
    endpoint = os.getenv("WATCHU_AI_SUMMARY_URL", "").strip()
    api_key = os.getenv("WATCHU_AI_API_KEY", "").strip()
    if not endpoint:
        return template_summary(event), "template"

    payload = json.dumps({
        "task": "Summarise this security incident in two concise analyst-ready sentences. Do not invent facts.",
        "event": {
            "source": event.source,
            "title": event.title,
            "category": event.category,
            "src_ip": event.src_ip,
            "dest_ip": event.dest_ip,
            "severity": event.severity,
            "score": event.score,
        },
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            decoded = json.loads(response.read().decode("utf-8"))
        summary = str(decoded.get("summary") or "").strip()
        if 20 <= len(summary) <= 1600:
            return summary, "ai"
    except (OSError, ValueError, urllib.error.URLError):
        pass
    return template_summary(event), "template"


def get_settings(connection: sqlite3.Connection) -> dict[str, str]:
    defaults = {
        "dedupe_window_minutes": "15",
        "telegram_enabled": "0",
        "telegram_chat_id": "",
        "alert_min_severity": "High",
    }
    try:
        rows = connection.execute("SELECT setting_key, setting_value FROM settings").fetchall()
    except sqlite3.OperationalError:
        return defaults
    defaults.update({row[0]: row[1] for row in rows})
    return defaults


def send_telegram(connection: sqlite3.Connection, incident_id: int, event: NormalizedEvent, settings: dict[str, str]) -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = settings.get("telegram_chat_id", "").strip()
    if not token or not chat_id or settings.get("telegram_enabled") != "1":
        return
    minimum = settings.get("alert_min_severity", "High")
    if SEVERITY_RANK[event.severity] < SEVERITY_RANK.get(minimum, 3):
        return

    message = (
        f"<b>Watch-U {html.escape(event.severity)} alert</b>\n"
        f"{html.escape(event.title)}\n"
        f"Score: {event.score}/100 · Source: {html.escape(event.source)}\n"
        f"Origin: {html.escape(event.src_ip or 'local endpoint')}"
    )
    payload = json.dumps({"chat_id": chat_id, "text": message, "parse_mode": "HTML"}).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    status, response_message = "Sent", "Telegram accepted the alert."
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            decoded = json.loads(response.read().decode("utf-8"))
        if not decoded.get("ok"):
            status, response_message = "Failed", str(decoded.get("description") or "Telegram rejected the alert")
    except (OSError, ValueError, urllib.error.URLError) as error:
        status, response_message = "Failed", str(error)[:500]
    connection.execute(
        "INSERT INTO notification_log (incident_id, channel, status, response_message) VALUES (?, 'telegram', ?, ?)",
        (incident_id, status, response_message),
    )


def store_event(connection: sqlite3.Connection, event: NormalizedEvent) -> tuple[int, bool]:
    settings = get_settings(connection)
    try:
        window_minutes = max(1, min(1440, int(settings.get("dedupe_window_minutes", "15"))))
    except ValueError:
        window_minutes = 15
    cutoff = event.occurred_at - timedelta(minutes=window_minutes)
    fingerprint = event.base_fingerprint
    existing = connection.execute(
        """SELECT id, fingerprint, last_seen FROM incidents
           WHERE fingerprint = ? OR fingerprint LIKE ?
           ORDER BY last_seen DESC LIMIT 1""",
        (fingerprint, fingerprint + ":%"),
    ).fetchone()

    timestamp = event.occurred_at.strftime("%Y-%m-%d %H:%M:%S")
    raw_json = json.dumps(event.raw, ensure_ascii=False, separators=(",", ":"))
    summary, provider = ai_summary(event)
    if existing:
        last_seen = parse_timestamp(str(existing[2]).replace(" ", "T") + "+00:00")
        if last_seen >= cutoff:
            connection.execute(
                """UPDATE incidents SET event_count = event_count + 1, last_seen = ?, updated_at = CURRENT_TIMESTAMP,
                   score = MAX(score, ?), severity = CASE WHEN score < ? THEN ? ELSE severity END, raw_json = ?
                   WHERE id = ?""",
                (timestamp, event.score, event.score, event.severity, raw_json, existing[0]),
            )
            return int(existing[0]), False
        fingerprint = f"{fingerprint}:{int(event.occurred_at.timestamp() // (window_minutes * 60))}"

    cursor = connection.execute(
        """INSERT INTO incidents
           (fingerprint, title, source, category, src_ip, dest_ip, severity, score, event_count, status,
            summary, summary_provider, raw_json, first_seen, last_seen, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'Open', ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
        (
            fingerprint, event.title, event.source, event.category, event.src_ip, event.dest_ip,
            event.severity, event.score, summary, provider, raw_json, timestamp, timestamp,
        ),
    )
    incident_id = int(cursor.lastrowid)
    send_telegram(connection, incident_id, event, settings)
    return incident_id, True


def parse_lines(lines: Iterable[str], connection: sqlite3.Connection, dry_run: bool = False) -> dict[str, int]:
    stats = {"read": 0, "created": 0, "deduplicated": 0, "invalid": 0}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        stats["read"] += 1
        try:
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError("event must be a JSON object")
            event = normalize_event(raw)
            if dry_run:
                print(json.dumps({"title": event.title, "severity": event.severity, "score": event.score, "fingerprint": event.base_fingerprint}))
                continue
            _, created = store_event(connection, event)
            connection.commit()
            stats["created" if created else "deduplicated"] += 1
        except (ValueError, TypeError, sqlite3.Error) as error:
            connection.rollback()
            stats["invalid"] += 1
            print(f"Skipped event: {error}", file=sys.stderr)
    return stats


def iter_files(paths: list[Path]) -> Iterable[str]:
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            yield from handle


def watch_directory(directory: Path, connection: sqlite3.Connection, interval: float) -> None:
    offsets: dict[Path, int] = {}
    print(f"Watching {directory} for JSON/JSONL files. Press Ctrl+C to stop.")
    while True:
        for path in sorted([*directory.glob("*.jsonl"), *directory.glob("*.json")]):
            offset = offsets.get(path, 0)
            with path.open("r", encoding="utf-8") as handle:
                handle.seek(offset)
                stats = parse_lines(handle, connection)
                offsets[path] = handle.tell()
            if stats["read"]:
                print(f"{path.name}: {stats}")
        time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Suricata/Wazuh JSON into the Watch-U SQLite database.")
    parser.add_argument("files", nargs="*", type=Path, help="JSONL input files; stdin is used when omitted")
    parser.add_argument("--db", type=Path, default=None, help="SQLite path (defaults to DB_PATH or database/watchu.sqlite)")
    parser.add_argument("--dry-run", action="store_true", help="Score and normalise without writing to SQLite")
    parser.add_argument("--watch", type=Path, help="Continuously read appended *.json and *.jsonl files")
    parser.add_argument("--interval", type=float, default=3.0, help="Watch polling interval in seconds")
    args = parser.parse_args()

    configured_db = os.getenv("DB_PATH", "database/watchu.sqlite")
    db_path = args.db or Path(configured_db)
    if not db_path.is_absolute():
        db_path = ROOT / db_path
    if not db_path.exists() and not args.dry_run:
        print(f"Database does not exist: {db_path}. Run php database/init.php first.", file=sys.stderr)
        return 2

    connection = sqlite3.connect(db_path if not args.dry_run else ":memory:", timeout=5)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.row_factory = sqlite3.Row
    try:
        if args.watch:
            watch_directory(args.watch, connection, max(.5, args.interval))
        else:
            lines = iter_files(args.files) if args.files else sys.stdin
            stats = parse_lines(lines, connection, args.dry_run)
            print(json.dumps(stats))
    except KeyboardInterrupt:
        print("Worker stopped.")
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
