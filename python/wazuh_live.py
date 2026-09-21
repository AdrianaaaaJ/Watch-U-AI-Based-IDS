#!/usr/bin/env python3
"""Read new Wazuh alert lines over verified SSH/SFTP into Watch-U SQLite.

Each incident change and its remote byte offset commit together. This lets the
process restart without replaying the whole alerts.json file. Scoring and
deduplication are provided by watchu_worker.py.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import watchu_worker


ROOT = Path(__file__).resolve().parents[1]
MAX_FETCH_BYTES = 4 * 1024 * 1024
IDENTITY_BYTES = 64 * 1024
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
))


class LiveError(Exception):
    """A safe, actionable message for the local operator."""


class FatalLiveError(LiveError):
    """A setup problem that needs a restart after the operator fixes it."""


@contextmanager
def single_worker_lock():
    """Prevent two live readers from advancing the same SQLite cursor."""
    lock_path = ROOT / "data" / "wazuh-live.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        handle.seek(0)
        if handle.read(1) == b"":
            handle.seek(0)
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise LiveError("Wazuh live sudah berjalan dalam proses lain.") from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class LiveConfig:
    host: str
    port: int
    username: str
    remote_path: str
    key_path: str
    password: str
    key_passphrase: str
    known_hosts: Path
    database: Path
    interval: float

    @property
    def source_key(self) -> str:
        return f"{self.host}:{self.port}:{self.remote_path}"


def settings_from_env(database_override: Path | None, interval_override: float | None) -> LiveConfig:
    host = os.getenv("WAZUH_SSH_HOST", "").strip()
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as error:
        raise LiveError("WAZUH_SSH_HOST mesti alamat IPv4 private VM.") from error
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise LiveError("WAZUH_SSH_HOST mesti dalam rangkaian private RFC1918.")

    try:
        port = int(os.getenv("WAZUH_SSH_PORT", "22"))
        interval = float(interval_override if interval_override is not None else os.getenv("WAZUH_POLL_SECONDS", "3"))
    except ValueError as error:
        raise LiveError("Port SSH atau sela masa tidak sah.") from error
    if not 1 <= port <= 65535 or not 0.5 <= interval <= 3600:
        raise LiveError("Port SSH atau sela masa di luar julat yang dibenarkan.")

    username = os.getenv("WAZUH_SSH_USERNAME", "").strip()
    key_path = os.getenv("WAZUH_SSH_PRIVATE_KEY", "").strip()
    password = os.getenv("WAZUH_SSH_PASSWORD", "")
    key_passphrase = os.getenv("WAZUH_SSH_KEY_PASSPHRASE", "")
    remote_path = os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json").strip()
    if not username or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", username):
        raise LiveError("Isi WAZUH_SSH_USERNAME dengan akaun Linux VM yang sah.")
    if not key_path and not password:
        raise LiveError("Isi WAZUH_SSH_PRIVATE_KEY atau WAZUH_SSH_PASSWORD dalam .env.")
    if key_path:
        key_file = Path(key_path).expanduser()
        if not key_file.is_absolute() or not key_file.is_file():
            raise LiveError("WAZUH_SSH_PRIVATE_KEY mesti path penuh kepada fail key yang wujud.")
        key_path = str(key_file)
    if not posixpath.isabs(remote_path) or "\n" in remote_path or "\r" in remote_path:
        raise LiveError("WAZUH_ALERTS_PATH mesti laluan mutlak Linux.")

    known_hosts = Path(os.getenv("WAZUH_SSH_KNOWN_HOSTS", "").strip() or Path.home() / ".ssh" / "known_hosts").expanduser()
    if not known_hosts.is_absolute() or not known_hosts.is_file():
        raise LiveError("Fail known_hosts tiada. Sahkan fingerprint SSH VM dan sambung sekali dengan ssh dahulu.")

    configured_db = database_override or Path(os.getenv("DB_PATH", "database/watchu.sqlite"))
    database = configured_db if configured_db.is_absolute() else ROOT / configured_db
    if not database.is_file():
        raise LiveError("Database SQLite tiada. Jalankan php database\\init.php dahulu.")

    return LiveConfig(host, port, username, remote_path, key_path, password, key_passphrase, known_hosts, database, interval)


def connect_ssh(config: LiveConfig) -> Any:
    try:
        import paramiko
    except ImportError as error:
        raise FatalLiveError("Paramiko belum dipasang. Jalankan python -m pip install -r python\\requirements.txt.") from error

    client = paramiko.SSHClient()
    try:
        client.load_host_keys(str(config.known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            config.host,
            port=config.port,
            username=config.username,
            password=config.password or None,
            key_filename=config.key_path or None,
            passphrase=config.key_passphrase or None,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
    except paramiko.BadHostKeyException as error:
        client.close()
        raise FatalLiveError("Fingerprint SSH VM berubah. Sahkan VM sebelum kemas kini known_hosts.") from error
    except paramiko.AuthenticationException as error:
        client.close()
        raise FatalLiveError("Login SSH gagal. Semak username dan key/password dalam .env.") from error
    except (OSError, paramiko.SSHException) as error:
        client.close()
        raise LiveError("SSH VM tidak dapat disambung. Semak IP, port, firewall dan known_hosts.") from error
    return client


def remote_file_state(sftp: Any, remote_path: str) -> tuple[str, int]:
    # SFTP does not expose inode numbers. A signature of the first alert line
    # identifies a replacement file without requiring shell access on the VM.
    try:
        size = int(sftp.stat(remote_path).st_size)
        with sftp.open(remote_path, "rb") as remote_file:
            first_bytes = remote_file.read(min(size, IDENTITY_BYTES))
    except OSError as error:
        raise LiveError("alerts.json tidak boleh dibaca oleh akaun SSH. Semak path dan izin baca VM.") from error
    if size < 0 or not isinstance(first_bytes, bytes):
        raise LiveError("Metadata alerts.json tidak sah pada VM.")
    return file_signature(first_bytes), size


def file_signature(first_bytes: bytes) -> str:
    return hashlib.sha256(first_bytes.partition(b"\n")[0]).hexdigest()


def ensure_cursor_table(connection: sqlite3.Connection) -> None:
    # Also migrates an existing Watch-U database created before live ingestion.
    connection.execute("""CREATE TABLE IF NOT EXISTS wazuh_ingest_cursor (
        source_key TEXT PRIMARY KEY,
        file_identity TEXT NOT NULL,
        byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    connection.commit()


def save_cursor(connection: sqlite3.Connection, source_key: str, identity: str, offset: int) -> None:
    connection.execute("""INSERT INTO wazuh_ingest_cursor (source_key, file_identity, byte_offset)
        VALUES (?, ?, ?)
        ON CONFLICT(source_key) DO UPDATE SET
            file_identity = excluded.file_identity,
            byte_offset = excluded.byte_offset,
            updated_at = CURRENT_TIMESTAMP""", (source_key, identity, offset))


def last_complete_line_end(remote_file: Any, size: int) -> int:
    if size == 0:
        return 0
    start = max(0, size - MAX_FETCH_BYTES)
    remote_file.seek(start)
    tail = remote_file.read(size - start)
    newline = tail.rfind(b"\n")
    return start + newline + 1 if newline >= 0 else (0 if start == 0 else size)


def ingest_snapshot(
    connection: sqlite3.Connection,
    sftp: Any,
    source_key: str,
    remote_path: str,
    identity: str,
    size: int,
    from_start: bool = False,
) -> dict[str, int | bool]:
    """Process complete new lines; commit each line with its byte checkpoint."""
    stats: dict[str, int | bool] = {"read": 0, "created": 0, "deduplicated": 0, "invalid": 0, "skipped_backlog": 0, "rotated": False, "has_more": False}
    checkpoint = connection.execute(
        "SELECT file_identity, byte_offset FROM wazuh_ingest_cursor WHERE source_key = ?", (source_key,)
    ).fetchone()

    with sftp.open(remote_path, "rb") as remote_file:
        if file_signature(remote_file.read(min(size, IDENTITY_BYTES))) != identity:
            raise LiveError("Fail alert berubah ketika dibaca. Cuba semula pada semakan berikutnya.")
        if checkpoint is None:
            offset = 0 if from_start else last_complete_line_end(remote_file, size)
            stats["skipped_backlog"] = offset
            save_cursor(connection, source_key, identity, offset)
            connection.commit()
        elif checkpoint[0] != identity or size < int(checkpoint[1]):
            offset = 0
            stats["rotated"] = True
            save_cursor(connection, source_key, identity, offset)
            connection.commit()
        else:
            offset = int(checkpoint[1])

        if offset >= size:
            return stats
        remote_file.seek(offset)
        chunk = remote_file.read(min(size - offset, MAX_FETCH_BYTES))
        more_beyond_chunk = size - offset > len(chunk)
        if not isinstance(chunk, bytes):
            raise LiveError("Bacaan SFTP bukan data binari yang dijangka.")
        newline = chunk.rfind(b"\n")
        if newline < 0:
            if len(chunk) >= MAX_FETCH_BYTES:
                raise FatalLiveError("Satu baris alert melebihi 4 MB. Semak alerts.json pada VM.")
            return stats  # Wait for the Wazuh writer to finish this line.

        complete = chunk[:newline + 1]
        for raw_line in complete.split(b"\n")[:-1]:
            offset += len(raw_line) + 1
            if not raw_line.strip():
                save_cursor(connection, source_key, identity, offset)
                connection.commit()
                continue
            stats["read"] = int(stats["read"]) + 1
            try:
                raw = json.loads(raw_line.decode("utf-8"))
                if not isinstance(raw, dict):
                    raise ValueError("alert must be an object")
                event = watchu_worker.normalize_event(raw)
            except (UnicodeError, ValueError, TypeError):
                # A complete malformed line is skipped once, without blocking later alerts.
                save_cursor(connection, source_key, identity, offset)
                connection.commit()
                stats["invalid"] = int(stats["invalid"]) + 1
                continue

            try:
                _, created = watchu_worker.store_event(connection, event)
                save_cursor(connection, source_key, identity, offset)
                connection.commit()
            except Exception:
                connection.rollback()  # Keep the old offset so this alert is retried.
                raise
            key = "created" if created else "deduplicated"
            stats[key] = int(stats[key]) + 1

        stats["has_more"] = more_beyond_chunk
        return stats


def poll_once(connection: sqlite3.Connection, sftp: Any, config: LiveConfig, from_start: bool) -> dict[str, int | bool]:
    identity, size = remote_file_state(sftp, config.remote_path)
    return ingest_snapshot(connection, sftp, config.source_key, config.remote_path, identity, size, from_start)


def report(stats: dict[str, int | bool]) -> None:
    if stats["skipped_backlog"]:
        print("Bacaan pertama: log lama dilangkau; menunggu alert baharu.", flush=True)
    if stats["rotated"]:
        print("Fail alert bertukar/direset; membaca fail baharu dari awal.", flush=True)
    if stats["read"]:
        print(f"Alert dibaca: {stats['read']}; baru: {stats['created']}; digabung: {stats['deduplicated']}; tidak sah: {stats['invalid']}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Tarik alert Wazuh baharu melalui SSH/SFTP ke Watch-U.")
    parser.add_argument("--once", action="store_true", help="Semak dan proses satu kali sahaja")
    parser.add_argument("--from-start", action="store_true", help="Baca log sedia ada pada sambungan pertama sahaja")
    parser.add_argument("--db", type=Path, help="Laluan SQLite untuk ujian/staging")
    parser.add_argument("--interval", type=float, help="Sela masa semakan dalam saat")
    args = parser.parse_args()
    try:
        config = settings_from_env(args.db, args.interval)
    except LiveError as error:
        print(error, file=sys.stderr)
        return 2

    try:
        with single_worker_lock():
            connection = sqlite3.connect(config.database, timeout=30)
            connection.execute("PRAGMA foreign_keys = ON")
            ensure_cursor_table(connection)
            print("Watch-U Wazuh live bermula. Ctrl+C untuk berhenti.", flush=True)
            last_error = ""
            try:
                while True:
                    try:
                        client = connect_ssh(config)
                        try:
                            sftp = client.open_sftp()
                            try:
                                while True:
                                    stats = poll_once(connection, sftp, config, args.from_start)
                                    report(stats)
                                    last_error = ""
                                    if args.once:
                                        return 0
                                    time.sleep(0 if stats["has_more"] else config.interval)
                            finally:
                                sftp.close()
                        finally:
                            client.close()
                    except KeyboardInterrupt:
                        raise
                    except FatalLiveError as error:
                        print(error, file=sys.stderr, flush=True)
                        return 2
                    except Exception as error:
                        message = str(error) if isinstance(error, LiveError) else "SFTP atau SQLite gagal; semak sambungan VM, izin fail dan database."
                        if message != last_error:
                            print(message, file=sys.stderr, flush=True)
                            last_error = message
                        if args.once:
                            return 1
                        time.sleep(max(5, config.interval))
            finally:
                connection.close()
    except KeyboardInterrupt:
        print("Watch-U Wazuh live dihentikan.", flush=True)
        return 0
    except (LiveError, sqlite3.Error) as error:
        print(error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
