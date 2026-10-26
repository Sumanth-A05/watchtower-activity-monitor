"""WatchTower: a local, consent-based Windows activity monitoring prototype."""
from __future__ import annotations

import ctypes
import base64
import hashlib
import hmac
from contextlib import contextmanager
import json
import os
import platform
import re
import secrets
import smtplib
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import textwrap
import urllib.parse
from ctypes import wintypes
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import parseaddr
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LOGO_FULL_PATH = ROOT / "watchtower_logo.png"
LOGO_EMBLEM_PATH = ROOT / "watchtower_emblem.png"
DB_PATH = ROOT / "watchtower.db"
SNAPSHOT_DIR = ROOT / "rollback_data"
MAX_SNAPSHOT_FILE_BYTES = 25 * 1024 * 1024
MAX_DIFF_FILE_BYTES = 256 * 1024
HOST = "127.0.0.1"
PORT = int(os.environ.get("WATCHTOWER_PORT", "8765"))
FAILURE_THRESHOLD = int(os.environ.get("WATCHTOWER_FAILURE_THRESHOLD", "1"))
FAILURE_WINDOW_MINUTES = int(os.environ.get("WATCHTOWER_FAILURE_WINDOW_MINUTES", "5"))
TOKEN = secrets.token_urlsafe(32)
STOP = threading.Event()
STATUS = {
    "windows_events": "Starting",
    "file_monitor": "Starting",
    "application_monitor": "Starting",
    "email_notifications": (
        "Configured" if os.environ.get("WATCHTOWER_SMTP_HOST") and os.environ.get("WATCHTOWER_ALERT_TO")
        else "Not configured - alerts remain on the dashboard"
    ),
}
STATUS_LOCK = threading.Lock()
SESSION_STARTED_AT: str | None = None
APP_MONITOR_LAST_SAMPLE = 0.0
APP_ACTIVITY_LOCK = threading.Lock()
APP_SESSION_USAGE: dict[str, dict[str, int | str]] = {}
LOGIN_PBKDF2_ROUNDS = 310_000
LOGIN_SESSION_SECONDS = 12 * 60 * 60
AUTH_SESSIONS: dict[str, tuple[str, float]] = {}
AUTH_SESSIONS_LOCK = threading.Lock()


def now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


@contextmanager
def db_session():
    db = connect()
    try:
        with db:
            yield db
    finally:
        db.close()


def init_db() -> None:
    with db_session() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            category TEXT NOT NULL, message TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            title TEXT NOT NULL, message TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}',
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS watches (
            id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL UNIQUE,
            baseline_done INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS file_states (
            path TEXT PRIMARY KEY, size INTEGER, modified REAL, digest TEXT, present INTEGER NOT NULL,
            snapshot_path TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS app_policies (
            exe_name TEXT PRIMARY KEY, locked INTEGER NOT NULL DEFAULT 0,
            time_limit_minutes INTEGER, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_usage (
            usage_date TEXT NOT NULL, exe_name TEXT NOT NULL, seconds INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(usage_date, exe_name)
        );
        CREATE TABLE IF NOT EXISTS app_usage_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            exe_name TEXT NOT NULL, seconds INTEGER NOT NULL DEFAULT 3
        );
        CREATE INDEX IF NOT EXISTS idx_app_usage_samples_created ON app_usage_samples(created_at);
        CREATE INDEX IF NOT EXISTS idx_events_category_created ON events(category,created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
        """)
        watch_columns = {row["name"] for row in db.execute("PRAGMA table_info(watches)")}
        if "baseline_done" not in watch_columns:
            db.execute("ALTER TABLE watches ADD COLUMN baseline_done INTEGER NOT NULL DEFAULT 0")
        state_columns = {row["name"] for row in db.execute("PRAGMA table_info(file_states)")}
        if "snapshot_path" not in state_columns:
            db.execute("ALTER TABLE file_states ADD COLUMN snapshot_path TEXT")
        alert_columns = {row["name"] for row in db.execute("PRAGMA table_info(alerts)")}
        if "details" not in alert_columns:
            db.execute("ALTER TABLE alerts ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")


def login_is_configured() -> bool:
    with db_session() as db:
        return db.execute("SELECT 1 FROM settings WHERE key='login_password_hash'").fetchone() is not None


def reset_login() -> None:
    """Clear only dashboard login credentials so the owner can set them again."""
    with db_session() as db:
        db.execute("DELETE FROM settings WHERE key IN ('login_username','login_salt','login_password_hash','login_hash_rounds')")


def create_login(username: str, password: str) -> None:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, LOGIN_PBKDF2_ROUNDS)
    with db_session() as db:
        if db.execute("SELECT 1 FROM settings WHERE key='login_password_hash'").fetchone():
            raise ValueError("A WatchTower login has already been created")
        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('login_username',?)", (username.strip(),))
        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('login_salt',?)", (salt.hex(),))
        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('login_password_hash',?)", (password_hash.hex(),))
        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('login_hash_rounds',?)", (str(LOGIN_PBKDF2_ROUNDS),))


def verify_login(username: str, password: str) -> str | None:
    with db_session() as db:
        saved_username = db.execute("SELECT value FROM settings WHERE key='login_username'").fetchone()
        salt_row = db.execute("SELECT value FROM settings WHERE key='login_salt'").fetchone()
        hash_row = db.execute("SELECT value FROM settings WHERE key='login_password_hash'").fetchone()
        rounds_row = db.execute("SELECT value FROM settings WHERE key='login_hash_rounds'").fetchone()
    if not saved_username or not salt_row or not hash_row:
        return None
    try:
        salt = bytes.fromhex(salt_row["value"])
        expected = bytes.fromhex(hash_row["value"])
        rounds = int(rounds_row["value"]) if rounds_row else LOGIN_PBKDF2_ROUNDS
    except (TypeError, ValueError):
        return None
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    if hmac.compare_digest(actual, expected) and hmac.compare_digest(username.strip().casefold(), saved_username["value"].casefold()):
        return saved_username["value"]
    return None


def create_auth_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    with AUTH_SESSIONS_LOCK:
        AUTH_SESSIONS[token] = (username, time.time() + LOGIN_SESSION_SECONDS)
    return token


def record_event(category: str, message: str, details: dict | None = None,
                created_at: str | None = None) -> None:
    with db_session() as db:
        db.execute("INSERT INTO events(created_at,category,message,details) VALUES(?,?,?,?)",
                   (created_at or now_text(), category, message, json.dumps(details or {}, ensure_ascii=False)))


def record_alert(title: str, message: str, details: dict | None = None,
                 created_at: str | None = None, notify: bool = True) -> None:
    created_at = created_at or now_text()
    details = details or {}
    with connect() as db:
        db.execute("INSERT INTO alerts(created_at,title,message,details) VALUES(?,?,?,?)",
                   (created_at, title, message, json.dumps(details, ensure_ascii=False)))
    if not notify:
        return
    email_message = message
    if details:
        email_message = "\n".join((
            "WatchTower detected failed sign-in activity.",
            f"Time frame: {details.get('timeframe_minutes', 'Unknown')} minutes",
            f"Failed attempts: {details.get('failed_attempts', 'Unknown')}",
            f"Account name: {', '.join(details.get('account_names', [])) or 'Unknown'}",
            f"Attempt times: {', '.join(details.get('attempt_times', [])) or 'Not provided'}",
            f"Date: {created_at}",
            "If you do not recognize this activity, review your Windows account security.",
        ))
    send_email(title, email_message)


def get_sign_in_history(db: sqlite3.Connection, limit: int | None = None) -> list[dict]:
    # Windows can emit both a successful interactive logon and an unlock record
    # for the same account in the same second. Keep the unlock record in that case.
    rows = [dict(row) for row in db.execute("""
        SELECT id, created_at, message
        FROM events
        WHERE category='authentication' AND datetime(created_at) >= datetime('now','-1 day') AND
          (message LIKE 'Failed sign-in:%' OR message LIKE 'Successful sign-in:%' OR
           message LIKE 'Session unlocked:%' OR message LIKE 'Session locked:%')
        ORDER BY id DESC
    """)]
    unlock_keys = set()
    for row in rows:
        if row["message"].startswith("Session unlocked:"):
            account = row["message"].split(":", 1)[1].strip().rsplit("\\", 1)[-1].casefold()
            unlock_keys.add((row["created_at"], account))
    result: list[dict] = []
    seen_successes = set()
    seen_unlocks = set()
    for row in rows:
        message = row["message"]
        if message.startswith("Failed sign-in:"):
            result.append(row)
        elif message.startswith("Successful sign-in:"):
            account = message.split(":", 1)[1].strip().rsplit("\\", 1)[-1].casefold()
            key = (row["created_at"], account)
            if key not in unlock_keys and key not in seen_successes:
                seen_successes.add(key)
                result.append(row)
        elif message.startswith(("Session unlocked:", "Session locked:")):
            account = message.split(":", 1)[1].strip().rsplit("\\", 1)[-1].casefold()
            key = (row["created_at"], account, message.split(":", 1)[0])
            if key not in seen_unlocks:
                seen_unlocks.add(key)
                result.append(row)
    return result if limit is None else result[:limit]


EMAIL_SETTING_KEYS = {
    "host": "email_smtp_host", "port": "email_smtp_port", "username": "email_smtp_user",
    "sender": "email_smtp_from", "recipient": "email_alert_to", "password": "email_smtp_password_dpapi",
}


def protect_email_password(password: str) -> str:
    """Encrypt an SMTP password for the current Windows account using DPAPI."""
    if platform.system() != "Windows":
        raise RuntimeError("Secure saved email settings are supported on Windows only")

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    raw = password.encode("utf-8")
    source = ctypes.create_string_buffer(raw)
    source_blob = DataBlob(len(raw), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    encrypted_blob = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [ctypes.POINTER(DataBlob), wintypes.LPCWSTR,
                                         ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(DataBlob)]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    if not crypt32.CryptProtectData(ctypes.byref(source_blob), "WatchTower SMTP password", None,
                                    None, None, 1, ctypes.byref(encrypted_blob)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return base64.b64encode(ctypes.string_at(encrypted_blob.pbData, encrypted_blob.cbData)).decode("ascii")
    finally:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(encrypted_blob.pbData)


def unprotect_email_password(encoded: str) -> str:
    """Decrypt the saved SMTP password for the Windows account that protected it."""
    if platform.system() != "Windows":
        raise RuntimeError("Saved email password can only be decrypted on Windows")

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    raw = base64.b64decode(encoded, validate=True)
    source = ctypes.create_string_buffer(raw)
    source_blob = DataBlob(len(raw), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    plain_blob = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(DataBlob), ctypes.POINTER(wintypes.LPWSTR),
                                           ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(DataBlob)]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    if not crypt32.CryptUnprotectData(ctypes.byref(source_blob), None, None, None, None, 1,
                                      ctypes.byref(plain_blob)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(plain_blob.pbData, plain_blob.cbData).decode("utf-8")
    finally:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(plain_blob.pbData)


def get_email_config() -> dict[str, str]:
    with db_session() as db:
        saved = {row["key"]: row["value"] for row in db.execute(
            "SELECT key,value FROM settings WHERE key LIKE 'email_%'")}
    config = {
        "host": saved.get(EMAIL_SETTING_KEYS["host"]) or os.environ.get("WATCHTOWER_SMTP_HOST", "smtp.gmail.com"),
        "port": saved.get(EMAIL_SETTING_KEYS["port"]) or os.environ.get("WATCHTOWER_SMTP_PORT", "587"),
        "username": saved.get(EMAIL_SETTING_KEYS["username"]) or os.environ.get("WATCHTOWER_SMTP_USER", ""),
        "sender": saved.get(EMAIL_SETTING_KEYS["sender"]) or os.environ.get("WATCHTOWER_SMTP_FROM", ""),
        "recipient": saved.get(EMAIL_SETTING_KEYS["recipient"]) or os.environ.get("WATCHTOWER_ALERT_TO", ""),
        "password": "",
        "password_saved": "false",
    }
    encrypted = saved.get(EMAIL_SETTING_KEYS["password"], "")
    if encrypted:
        config["password"] = unprotect_email_password(encrypted)
        config["password_saved"] = "true"
    else:
        config["password"] = os.environ.get("WATCHTOWER_SMTP_PASSWORD", "")
        config["password_saved"] = "false"
    return config


def public_email_settings() -> dict:
    config = get_email_config()
    return {
        "host": config["host"], "port": config["port"], "username": config["username"],
        "sender": config["sender"], "recipient": config["recipient"],
        "password_saved": config["password_saved"] == "true",
        "configured": bool(config["host"] and config["recipient"] and
                            (not config["username"] or config["password"])),
    }


def update_email_status() -> None:
    try:
        config = get_email_config()
        ready = bool(config["host"] and config["recipient"] and
                     (not config["username"] or config["password"]))
        status("email_notifications", "Configured - ready to send alerts" if ready else
               "Not configured - save settings in Email alerts")
    except Exception as exc:
        status("email_notifications", f"Saved email settings unavailable: {str(exc)[:100]}")


def save_email_config(data: dict) -> None:
    host = str(data.get("host", "")).strip()
    port_text = str(data.get("port", "587")).strip()
    username = str(data.get("username", "")).strip()
    sender = str(data.get("sender", "")).strip()
    recipient = str(data.get("recipient", "")).strip()
    password = str(data.get("password", ""))
    if len(username) > 254 or len(sender) > 254 or len(recipient) > 254 or len(password) > 1024:
        raise ValueError("Email settings exceed the allowed length.")
    if not host or len(host) > 255 or any(ch in host for ch in "\r\n"):
        raise ValueError("Enter a valid SMTP server address.")
    try:
        port = int(port_text)
    except ValueError:
        raise ValueError("SMTP port must be a number between 1 and 65535.") from None
    if not 1 <= port <= 65535:
        raise ValueError("SMTP port must be a number between 1 and 65535.")
    for label, address in (("Sender", sender), ("Recipient", recipient)):
        parsed = parseaddr(address)[1]
        if not parsed or parsed != address or "@" not in parsed or any(ch in address for ch in "\r\n"):
            raise ValueError(f"Enter a valid {label.lower()} email address.")
    if username and not password:
        existing = get_email_config()
        password = existing["password"]
        if not password:
            raise ValueError("Enter the SMTP or Gmail app password.")
    if password:
        encrypted_password = protect_email_password(password)
    else:
        encrypted_password = ""
    values = {
        EMAIL_SETTING_KEYS["host"]: host,
        EMAIL_SETTING_KEYS["port"]: str(port),
        EMAIL_SETTING_KEYS["username"]: username,
        EMAIL_SETTING_KEYS["sender"]: sender,
        EMAIL_SETTING_KEYS["recipient"]: recipient,
    }
    with db_session() as db:
        for key, value in values.items():
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))
        if encrypted_password:
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                       (EMAIL_SETTING_KEYS["password"], encrypted_password))
        elif not username:
            db.execute("DELETE FROM settings WHERE key=?", (EMAIL_SETTING_KEYS["password"],))


def send_email(subject: str, body: str) -> bool:
    try:
        config = get_email_config()
    except Exception as exc:
        status("email_notifications", f"Saved email settings unavailable: {str(exc)[:100]}")
        return False
    host = config["host"]
    recipient = config["recipient"]
    if not host or not recipient:
        status("email_notifications", "Not configured - save settings in Email alerts")
        return False
    msg = EmailMessage()
    msg["Subject"] = f"WatchTower alert: {subject}"
    msg["From"] = config["sender"] or recipient
    msg["To"] = recipient
    msg.set_content(body)
    try:
        status("email_notifications", "Sending alert email")
        with smtplib.SMTP(host, int(config["port"]), timeout=10) as server:
            server.starttls()
            username = config["username"]
            password = config["password"]
            if username:
                server.login(username, password or "")
            server.send_message(msg)
        status("email_notifications", "Alert email sent")
        return True
    except Exception as exc:
        status("email_notifications", f"Email failed: {str(exc)[:120]}")
        record_event("system", "Email notification failed", {"error": str(exc)[:300]})
        return False


def status(key: str, value: str) -> None:
    with STATUS_LOCK:
        STATUS[key] = value


def windows_event_loop() -> None:
    """Poll Windows for newly written sign-in events, keeping a short local delay."""
    if platform.system() != "Windows":
        status("windows_events", "Unavailable: Windows only")
        return
    script = r"""
$ErrorActionPreference = 'Stop'
try {
  $null = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop
} catch {
  if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.FullyQualifiedErrorId -like '*UnauthorizedAccess*') {
    [Console]::Error.WriteLine('ACCESS_DENIED: Run WatchTower as administrator to read the Windows Security log.')
    exit 5
  }
  if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { Write-Output '[]'; exit 0 }
  throw
}
try {
  $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4800,4801; StartTime=__START_TIME__} -MaxEvents __MAX_EVENTS__ -ErrorAction Stop
} catch {
  if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { Write-Output '[]'; exit 0 }
  throw
}
$events | ForEach-Object {
  $xml = [xml]$_.ToXml(); $data = @{}
  foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = [string]$item.'#text' }
  if ($_.Id -in 4800,4801) {
    $user = [string]$data['SubjectUserName']; $domain = [string]$data['SubjectDomainName']
  } else {
    $user = [string]$data['TargetUserName']; $domain = [string]$data['TargetDomainName']
  }
  if ([string]::IsNullOrWhiteSpace($user) -or $user -eq '-') { $user = '' }
  if ([string]::IsNullOrWhiteSpace($domain) -or $domain -eq '-') { $domain = '' }
  [pscustomobject]@{ RecordId=$_.RecordId; Id=$_.Id; Time=$_.TimeCreated.ToString('o'); User=$user; Domain=$domain; LogonType=$data['LogonType'] }
} | ConvertTo-Json -Compress
"""
    last_id = 0
    first_read = True
    collector_started_at = time.time()
    failures: list[tuple[float, str]] = []
    last_alert_at: float | None = None
    while not STOP.is_set():
        try:
            # The first read backfills the last day. Re-querying that whole
            # history on every poll can time out on busy Security logs; later
            # reads use a small overlap and rely on RecordId deduplication.
            start_time = "(Get-Date).AddHours(-24)" if first_read else "(Get-Date).AddSeconds(-15)"
            max_events = 5000 if first_read else 500
            query_script = script.replace("__START_TIME__", start_time).replace("__MAX_EVENTS__", str(max_events))
            encoded_script = base64.b64encode(query_script.encode("utf-16le")).decode("ascii")
            proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                                  capture_output=True, text=True, timeout=60 if first_read else 20,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if proc.returncode:
                error_text = (proc.stderr or proc.stdout or "Windows Security log is unavailable").strip()
                if proc.returncode == 5 or "ACCESS_DENIED" in error_text or "UnauthorizedAccess" in error_text:
                    status("windows_events", "Access denied - close WatchTower and reopen it as administrator")
                    STOP.wait(15)
                    continue
                raise RuntimeError(error_text[:250])
            payload = json.loads(proc.stdout) if proc.stdout.strip() else []
            if isinstance(payload, dict):
                payload = [payload]
            initial_poll = first_read
            candidates = payload
            first_read = False
            imported = 0
            with db_session() as db:
                saved_ids = {str(json.loads(row[0] or '{}').get('record_id')) for row in db.execute(
                    "SELECT details FROM events WHERE category='authentication' AND details LIKE '%record_id%' ")}
            for event in sorted(candidates, key=lambda item: int(item.get("RecordId", 0))):
                    record_id = int(event.get("RecordId", 0))
                    if str(record_id) in saved_ids or record_id <= last_id:
                        continue
                    last_id = max(last_id, record_id)
                    event_id = int(event.get("Id", 0))
                    account = "\\".join(part for part in (event.get("Domain"), event.get("User"))
                                         if part and part.strip() and part.strip() != "-") or "Not reported by Windows"
                    if event_id == 4625:
                        event_time_text = event.get("Time") or now_text()
                        logon_type = str(event.get("LogonType", ""))
                        record_event("authentication", f"Failed sign-in: {account}",
                                     {"windows_event_id": event_id, "record_id": record_id,
                                      "logon_type": logon_type}, event_time_text)
                        imported += 1
                        try:
                            event_time = datetime.fromisoformat(event.get("Time", "")).timestamp()
                        except (TypeError, ValueError):
                            event_time = time.time()
                        failures.append((event_time, account))
                        failures = [(stamp, name) for stamp, name in failures
                                    if stamp >= event_time - FAILURE_WINDOW_MINUTES * 60]
                        can_alert = last_alert_at is None or event_time - last_alert_at >= FAILURE_WINDOW_MINUTES * 60
                        if (len(failures) >= FAILURE_THRESHOLD and can_alert and
                                event_time >= time.time() - FAILURE_WINDOW_MINUTES * 60):
                            attempt_count = len(failures)
                            account_names = sorted({name.rsplit("\\", 1)[-1] for _, name in failures})
                            attempt_times = [datetime.fromtimestamp(stamp).astimezone().isoformat(timespec="seconds")
                                             for stamp, _ in failures]
                            accounts = ", ".join(account_names)
                            alert_title = "Failed sign-in detected" if attempt_count == 1 else "Multiple failed sign-ins detected"
                            attempt_word = "attempt" if attempt_count == 1 else "attempts"
                            record_alert(alert_title,
                                f"Windows recorded {attempt_count} failed sign-in {attempt_word} within {FAILURE_WINDOW_MINUTES} minutes for {accounts}.",
                                {"timeframe_minutes": FAILURE_WINDOW_MINUTES, "failed_attempts": attempt_count,
                                 "account_names": account_names, "timeline_start": attempt_times[0],
                                 "timeline_end": attempt_times[-1], "attempt_times": attempt_times},
                                created_at=event_time_text, notify=True)
                            last_alert_at = event_time
                    # Windows can report an unlock as logon type 7 without a
                    # matching 4801 event, so include it in sign-in history.
                    elif event_id == 4624 and str(event.get("LogonType", "")) in {"2", "7", "10", "11"}:
                        record_event("authentication", f"Successful sign-in: {account}",
                                     {"windows_event_id": event_id, "record_id": record_id,
                                      "logon_type": event.get("LogonType")}, event.get("Time"))
                        imported += 1
                    elif event_id in (4800, 4801):
                        state = "locked" if event_id == 4800 else "unlocked"
                        record_event("authentication", f"Session {state}: {account}",
                                     {"windows_event_id": event_id, "record_id": record_id}, event.get("Time"))
                        imported += 1
            if initial_poll:
                last_id = max(last_id, max((int(item.get("RecordId", 0)) for item in payload), default=0))
            status("windows_events", f"Connected · checked {now_text()} · {imported} new sign-in/session events")
        except subprocess.TimeoutExpired:
            status("windows_events", "Windows Security log query timed out - retrying")
            STOP.wait(5)
            continue
        except Exception as exc:
            status("windows_events", f"Unavailable: {str(exc)[:160]}")
        STOP.wait(2)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def save_snapshot(path: Path) -> str | None:
    """Keep a local copy of small files so a later rollback has their old bytes."""
    try:
        if path.stat().st_size > MAX_SNAPSHOT_FILE_BYTES:
            return None
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        snapshot = SNAPSHOT_DIR / f"{secrets.token_hex(16)}.snapshot"
        shutil.copy2(path, snapshot)
        return str(snapshot)
    except OSError:
        return None


def read_text_preview(snapshot: str | None, missing_label: str) -> str:
    """Read a bounded UTF-8 preview for the dashboard's before/after panels."""
    if not snapshot:
        return missing_label
    try:
        preview_path = Path(snapshot)
        if preview_path.stat().st_size > MAX_DIFF_FILE_BYTES:
            return "Text preview omitted because this file is larger than 256 KB."
        return preview_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        return "Text preview unavailable (the file may be binary or use another encoding)."


def scan_watches() -> None:
    with db_session() as db:
        watches = [(Path(row["path"]), bool(row["baseline_done"]))
                   for row in db.execute("SELECT path,baseline_done FROM watches")]
    roots = [root for root, _ in watches if not root.is_dir()]
    observed: dict[str, tuple[int, float, str]] = {}
    for root in roots:
        try:
            candidates = [root] if root.is_file() else []
            for path in candidates:
                resolved = path.resolve()
                if resolved == DB_PATH or resolved == DB_PATH.with_name(DB_PATH.name + "-wal") or resolved == DB_PATH.with_name(DB_PATH.name + "-shm"):
                    continue
                if _under_root(str(resolved), SNAPSHOT_DIR.resolve()):
                    continue
                if len(observed) >= 2500:
                    break
                try:
                    stat = resolved.stat()
                    key = str(resolved)
                    with db_session() as db:
                        old = db.execute("SELECT size,modified,digest,present,snapshot_path FROM file_states WHERE path=?", (key,)).fetchone()
                    if old and old["present"] and old["size"] == stat.st_size and old["modified"] == stat.st_mtime:
                        digest = old["digest"] or file_digest(path)
                    else:
                        digest = file_digest(path)
                    observed[key] = (stat.st_size, stat.st_mtime, digest)
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue
    with db_session() as db:
        previous = {row["path"]: row for row in db.execute("SELECT * FROM file_states")}
        for key, (size, modified, digest) in observed.items():
            old = previous.get(key)
            kind = None
            baseline_for_path = any(done and _under_root(key, root) for root, done in watches)
            if old is None or not old["present"]:
                kind = "File created" if baseline_for_path else None
            elif old["digest"] != digest:
                kind = "File modified"
            before_snapshot = old["snapshot_path"] if old else None
            current_snapshot = (
                old["snapshot_path"]
                if old and old["present"] and old["digest"] == digest and old["snapshot_path"]
                else save_snapshot(Path(key))
            )
            if kind:
                details = {
                    "path": key,
                    "size_bytes": size,
                    "sha256": digest,
                    "after_snapshot": current_snapshot,
                    "rollback_action": "delete" if kind == "File created" else "restore",
                }
                if kind == "File modified" and old:
                    details["previous_sha256"] = old["digest"]
                if kind == "File modified":
                    details["before_snapshot"] = before_snapshot
                details["rollback_available"] = kind == "File created" or bool(before_snapshot)
                db.execute("INSERT INTO events(created_at,category,message,details) VALUES(?,?,?,?)",
                           (now_text(), "file", f"{kind}: {key}", json.dumps(details)))
            db.execute("INSERT INTO file_states(path,size,modified,digest,present,snapshot_path) VALUES(?,?,?,?,1,?) "
                       "ON CONFLICT(path) DO UPDATE SET size=excluded.size,modified=excluded.modified,digest=excluded.digest,present=1,snapshot_path=excluded.snapshot_path",
                       (key, size, modified, digest, current_snapshot))
        for key, old in previous.items():
            if old["present"] and key not in observed and any(_under_root(key, root) for root in roots):
                db.execute("UPDATE file_states SET present=0 WHERE path=?", (key,))
                db.execute("INSERT INTO events(created_at,category,message,details) VALUES(?,?,?,?)",
                           (now_text(), "file", f"File deleted: {key}", json.dumps({
                               "path": key,
                               "last_sha256": old["digest"],
                               "size_bytes": old["size"],
                               "before_snapshot": old["snapshot_path"],
                               "rollback_action": "restore",
                               "rollback_available": bool(old["snapshot_path"]),
                           })))
        db.execute("UPDATE watches SET baseline_done=1")
    status("file_monitor", f"Watching {len(roots)} file(s)")


def _under_root(file_name: str, root: Path) -> bool:
    try:
        return Path(file_name) == root or Path(file_name).is_relative_to(root)
    except (OSError, ValueError):
        return False


class RollbackConflict(Exception):
    pass


def rollback_file_event(event_id: int) -> dict:
    with db_session() as db:
        event = db.execute("SELECT * FROM events WHERE id=? AND category='file'", (event_id,)).fetchone()
        if not event or not event["message"].startswith(("File created:", "File modified:", "File deleted:")):
            raise ValueError("This activity entry cannot be rolled back")
        details = json.loads(event["details"] or "{}")
        if not details.get("rollback_available"):
            raise ValueError("No saved file snapshot is available for this entry")

        target = Path(details["path"]).resolve()
        roots = [Path(row[0]) for row in db.execute("SELECT path FROM watches")]
        if not any(_under_root(str(target), root) for root in roots):
            raise ValueError("This file is no longer inside a monitored location")

        if details.get("rollback_action") == "delete":
            if not target.is_file():
                raise RollbackConflict("The created file is already missing")
            if file_digest(target) != details.get("sha256"):
                raise RollbackConflict("The file changed again after this entry; refusing to delete the newer version")
            target.unlink()
            db.execute("UPDATE file_states SET present=0 WHERE path=?", (str(target),))
            restored_digest = None
        else:
            snapshot_value = details.get("before_snapshot")
            if not snapshot_value:
                raise ValueError("The previous file snapshot is unavailable")
            snapshot = Path(snapshot_value).resolve(strict=True)
            if not _under_root(str(snapshot), SNAPSHOT_DIR.resolve()):
                raise ValueError("The saved snapshot path is invalid")
            was_deletion = event["message"].startswith("File deleted:")
            if was_deletion:
                if target.exists():
                    raise RollbackConflict("A file now exists at this path; refusing to overwrite it")
            else:
                if not target.is_file():
                    raise RollbackConflict("The changed file is now missing; refusing to recreate over a later action")
                if file_digest(target) != details.get("sha256"):
                    raise RollbackConflict("The file changed again after this entry; refusing to overwrite the newer version")

            if not target.parent.is_dir():
                raise RollbackConflict("The parent folder no longer exists")
            temporary = target.with_name(f".{target.name}.{secrets.token_hex(6)}.rollback-tmp")
            try:
                shutil.copy2(snapshot, temporary)
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    temporary.unlink()
            stat = target.stat()
            restored_digest = file_digest(target)
            new_snapshot = save_snapshot(target)
            db.execute("INSERT INTO file_states(path,size,modified,digest,present,snapshot_path) VALUES(?,?,?,?,1,?) "
                       "ON CONFLICT(path) DO UPDATE SET size=excluded.size,modified=excluded.modified,digest=excluded.digest,present=1,snapshot_path=excluded.snapshot_path",
                       (str(target), stat.st_size, stat.st_mtime, restored_digest, new_snapshot))

        db.execute("INSERT INTO events(created_at,category,message,details) VALUES(?,?,?,?)",
                   (now_text(), "file", f"Rollback applied: {target}", json.dumps({
                       "path": str(target), "rolled_back_event_id": event_id,
                       "sha256": restored_digest,
                   })))
        return {"ok": True, "path": str(target)}


def file_loop() -> None:
    while not STOP.is_set():
        try:
            scan_watches()
        except Exception as exc:
            status("file_monitor", f"Issue: {str(exc)[:140]}")
        STOP.wait(5)


def foreground_app() -> tuple[str, str, int] | None:
    if platform.system() != "Windows":
        return None
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        length = user32.GetWindowTextLengthW(hwnd)
        title = ctypes.create_unicode_buffer(min(length + 1, 512))
        user32.GetWindowTextW(hwnd, title, len(title))
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid.value)
        process = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_ulong(len(process))
        image = "Unknown process"
        if handle:
            if kernel32.QueryFullProcessImageNameW(handle, 0, process, ctypes.byref(size)):
                image = Path(process.value).name
            kernel32.CloseHandle(handle)
        return image, title.value or "(no window title)", int(pid.value)
    except Exception:
        return None


def application_loop() -> None:
    global APP_MONITOR_LAST_SAMPLE
    if platform.system() != "Windows":
        status("application_monitor", "Unavailable: Windows only")
        return
    previous = None
    while not STOP.is_set():
        monitor_status = "Sampling active window every 3 seconds (records app changes)"
        current = foreground_app()
        APP_MONITOR_LAST_SAMPLE = time.monotonic() if current else 0.0
        if current:
            image, title, pid = current
            exe_name = image.casefold()
            with APP_ACTIVITY_LOCK:
                usage_row = APP_SESSION_USAGE.setdefault(exe_name, {"application": image, "seconds": 0})
                usage_row["application"] = image
                usage_row["seconds"] = int(usage_row["seconds"]) + 3
            if current != previous:
                record_event("application", f"Active application: {image}", {"application": image, "window_title": title})
                previous = current
            usage = add_app_usage(exe_name, 3)
            with db_session() as db:
                db.execute("INSERT INTO app_usage_samples(created_at,exe_name,seconds) VALUES(?,?,3)",
                           (now_text(), exe_name))
            policy = get_app_policy(exe_name)
            if policy:
                limit = policy["time_limit_minutes"]
                time_expired = limit is not None and usage >= int(limit) * 60
                if time_expired and not policy["locked"]:
                    with db_session() as db:
                        db.execute("UPDATE app_policies SET locked=1,updated_at=? WHERE exe_name=?", (now_text(), exe_name))
                should_close = bool(policy["locked"]) or time_expired
                if should_close:
                    reason = "app locked" if policy["locked"] else "daily time limit reached"
                    monitor_status = f"Blocked {image}: {reason}"
                    try:
                        subprocess.run(["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                                       capture_output=True, timeout=5, check=False,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                elif limit is not None:
                    monitor_status = f"Monitoring {image}: {max(0, int(limit) * 60 - usage)} seconds remain today"
        else:
            previous = None
            monitor_status = "Waiting for an active desktop window"
        status("application_monitor", monitor_status)
        STOP.wait(3)


def get_app_policy(exe_name: str) -> dict | None:
    with db_session() as db:
        row = db.execute("SELECT locked,time_limit_minutes FROM app_policies WHERE exe_name=?", (exe_name,)).fetchone()
    return dict(row) if row else None


def app_control_data(db=None) -> dict:
    owns_db = db is None
    if owns_db:
        db = connect()
    try:
        today = datetime.now().astimezone().date().isoformat()
        policies = [dict(row) for row in db.execute(
            "SELECT p.exe_name,p.locked,p.time_limit_minutes,COALESCE(u.seconds,0) AS used_seconds "
            "FROM app_policies p LEFT JOIN app_usage u ON u.exe_name=p.exe_name AND u.usage_date=? "
            "ORDER BY p.exe_name", (today,))]
        configured = db.execute("SELECT 1 FROM settings WHERE key='app_control_hash'").fetchone() is not None
        return {"password_configured": configured, "policies": policies}
    finally:
        if owns_db:
            db.close()


def add_app_usage(exe_name: str, seconds: int) -> int:
    usage_date = datetime.now().astimezone().date().isoformat()
    with db_session() as db:
        db.execute("INSERT INTO app_usage(usage_date,exe_name,seconds) VALUES(?,?,?) "
                   "ON CONFLICT(usage_date,exe_name) DO UPDATE SET seconds=seconds+excluded.seconds",
                   (usage_date, exe_name, seconds))
        row = db.execute("SELECT seconds FROM app_usage WHERE usage_date=? AND exe_name=?",
                         (usage_date, exe_name)).fetchone()
    return int(row[0])


def verify_app_control_password(password: str) -> bool:
    with db_session() as db:
        salt = db.execute("SELECT value FROM settings WHERE key='app_control_salt'").fetchone()
        hashed = db.execute("SELECT value FROM settings WHERE key='app_control_hash'").fetchone()
    if not salt or not hashed:
        return False
    expected = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt[0]), LOGIN_PBKDF2_ROUNDS)
    return hmac.compare_digest(expected.hex(), hashed[0])


def login_page() -> bytes:
    setup_required = not login_is_configured()
    heading = "Create your WatchTower login" if setup_required else "Sign in to WatchTower"
    intro = ("Set a username and password to protect this dashboard on this computer."
             if setup_required else "Enter your WatchTower username and password to continue.")
    confirm_field = ('<label for="confirm">Confirm password</label><input id="confirm" type="password" autocomplete="new-password" required minlength="10">'
                     if setup_required else "")
    button_label = "Create secure login" if setup_required else "Sign in"
    page = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" type="image/png" href="/watchtower_emblem.png"><title>WatchTower sign in</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 15% 15%,#e9f4f8 0,transparent 32%),#f3f6fa;color:#182230;font-family:Segoe UI,Arial,sans-serif}.login-card{width:min(420px,100%);padding:32px;border:1px solid #dfe7ef;border-radius:18px;background:#fff;box-shadow:0 18px 55px #12243a14}.brand{display:flex;align-items:center;gap:12px;margin-bottom:25px}.brand-icon{width:48px;height:48px;display:grid;place-items:center;border-radius:13px;background:transparent}.brand-icon .watchtower-mark{width:48px;height:48px;display:block}.brand-name{font-size:18px;font-weight:750}.brand-sub{margin-top:3px;color:#788696;font-size:12px}.login-card h1{margin:0;font-size:21px;letter-spacing:-.02em}.intro{margin:9px 0 22px;color:#647487;font-size:13px;line-height:1.55}.field{margin:14px 0}.field label{display:block;margin-bottom:6px;color:#34485d;font-size:12px;font-weight:650}.field input{width:100%;min-width:0;padding:12px 13px;border:1px solid #ccd7e2;border-radius:9px;background:#fbfcfe;color:#182230;font:inherit;font-size:14px;outline:none}.field input:focus{border-color:#18829a;box-shadow:0 0 0 3px #18829a20}.submit{width:100%;margin-top:8px;padding:12px;border:0;border-radius:9px;background:#155e75;color:#fff;font-size:14px;font-weight:700;cursor:pointer}.submit:hover{background:#104b5d}.error{min-height:18px;margin-top:12px;color:#a73333;font-size:12px}.privacy{margin-top:18px;padding-top:15px;border-top:1px solid #edf0f3;color:#8491a0;font-size:11px;line-height:1.5}.privacy strong{color:#596b7e}</style><style>
body{background:radial-gradient(ellipse at 50% 0%,#fff 0,#eef3f8 55%,#e6edf4 100%);color:#202b38}
.login-card{border:1px solid #d8c28d;border-radius:20px;background:#fff;box-shadow:0 28px 80px #13253b22,0 0 0 5px #d4a83b12;padding:36px}
.brand{justify-content:center;margin-bottom:26px;padding-bottom:22px;border-bottom:1px solid #eee8da}
.login-card h1{color:#172333;font-size:24px;letter-spacing:-.035em}
.intro{color:#687587}
.field label{color:#344253}
.field input{border-color:#d7dce3;border-radius:10px;background:#f9fafb;transition:border-color .18s,box-shadow .18s}
.field input:focus{border-color:#bd8e22;box-shadow:0 0 0 4px #d2a63b25}
.submit{border:1px solid #d9b75f;border-radius:10px;background:linear-gradient(110deg,#202c3b,#354457);box-shadow:0 5px 14px #19243226;transition:transform .16s,box-shadow .16s,background .16s}
.submit:hover{transform:translateY(-1px);background:linear-gradient(110deg,#303d4e,#45566b);box-shadow:0 8px 20px #19243238}
.privacy{border-color:#eee8da;color:#758193}
</style></head><body>
<main class="login-card"><div class="brand"><img src="/watchtower_logo.png" alt="WatchTower logo" style="display:block;width:230px;max-width:100%;height:auto;margin:0 auto"></div><h1>__HEADING__</h1><p class="intro">__INTRO__</p><form id="login-form"><div class="field"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required minlength="3" maxlength="64"></div><div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="__AUTOCOMPLETE__" required minlength="10">__CONFIRM_FIELD__</div><button class="submit" type="submit">__BUTTON__</button><div id="error" class="error" role="alert"></div></form><div class="privacy"><strong>Privacy:</strong> Credentials are stored on this computer as a salted password hash. The dashboard remains available only on this computer.</div></main>
<script>const token='__TOKEN__',setupRequired=__SETUP__;document.querySelector('#login-form').addEventListener('submit',async e=>{e.preventDefault();const error=document.querySelector('#error');error.textContent='';const username=document.querySelector('#username').value.trim(),password=document.querySelector('#password').value;const data={username,password};if(setupRequired){data.confirm_password=document.querySelector('#confirm').value;if(password!==data.confirm_password){error.textContent='The passwords do not match.';return}}try{const response=await fetch(setupRequired?'/api/login/setup':'/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-WatchTower-Token':token},body:JSON.stringify(data)});const result=await response.json();if(!response.ok)throw Error(result.error||'Could not sign in');location.reload()}catch(err){error.textContent=err.message}});</script></body></html>'''
    return (page.replace("__HEADING__", heading).replace("__INTRO__", intro)
            .replace("__AUTOCOMPLETE__", "new-password" if setup_required else "current-password")
            .replace("__CONFIRM_FIELD__", confirm_field).replace("__BUTTON__", button_label)
            .replace("__SETUP__", "true" if setup_required else "false")
            .replace("__TOKEN__", TOKEN).encode("utf-8"))


def dashboard() -> bytes:
    page = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" type="image/png" href="/watchtower_emblem.png"><title>WatchTower</title>
<style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#182230;background:#f4f7fb}*{box-sizing:border-box}body{margin:0}.top{background:#12243a;color:white;padding:22px max(24px,calc((100% - 1180px)/2));display:flex;align-items:center;justify-content:space-between}.top h1{margin:0;font-size:24px}.top p{margin:5px 0 0;color:#b9c8d8;font-size:13px}.wrap{max-width:1180px;margin:24px auto;padding:0 20px}.notice{background:#fff8e6;border:1px solid #f0d994;border-radius:9px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#654f18}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card{background:white;border:1px solid #e3e9f0;border-radius:11px;padding:17px;box-shadow:0 2px 8px #18223008}.card h2{font-size:15px;margin:0 0 12px}.status{font-size:13px;color:#536273;line-height:1.45;min-height:38px}.metric{font-size:26px;font-weight:700;color:#155e75}.wide{grid-column:span 2}.full{grid-column:1/-1}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}input{padding:10px;border:1px solid #cad3de;border-radius:7px;min-width:240px;flex:1}button{border:0;border-radius:7px;padding:10px 14px;font-weight:600;cursor:pointer;background:#155e75;color:white}button.secondary{background:#e7eef4;color:#24364a}button.danger{background:#a73333}.list{max-height:310px;overflow:auto}.row{padding:11px 0;border-bottom:1px solid #edf0f3}.row:last-child{border:0}.row strong{font-size:13px}.meta{font-size:11px;color:#788696;margin-top:3px}.empty{color:#7c8998;font-size:13px;padding:12px 0}.pill{display:inline-block;background:#edf5f7;color:#155e75;border-radius:20px;padding:3px 8px;font-size:11px;margin-right:7px}@media(max-width:760px){.grid{grid-template-columns:1fr}.wide,.full{grid-column:auto}.wrap{margin:14px auto}.top{padding:18px 20px}}
</style><style>
[hidden]{display:none!important}.confirm-overlay{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;padding:20px;background:rgba(12,25,42,.58);backdrop-filter:blur(5px);animation:fade-in .16s ease-out}.confirm-dialog{width:min(440px,100%);padding:25px;border-radius:16px;background:#fff;box-shadow:0 24px 70px #07142655;border:1px solid #e3e9f0;animation:pop-in .18s ease-out}.confirm-icon{display:grid;place-items:center;width:44px;height:44px;margin-bottom:15px;border-radius:14px;background:#fff3d6;color:#9a5a14;font-size:23px;font-weight:800}.confirm-dialog[data-tone="danger"] .confirm-icon{background:#fff0ef;color:#a73333}.confirm-dialog h2{margin:0 0 8px;font-size:19px;color:#182230}.confirm-dialog p{margin:0;color:#536273;font-size:14px;line-height:1.55}.confirm-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:23px}.confirm-actions button{min-width:105px}.confirm-actions .danger{background:#a73333}.confirm-actions .danger:hover{background:#842828}.confirm-actions .primary{background:#155e75}.confirm-actions .primary:hover{background:#104b5d}@keyframes fade-in{from{opacity:0}to{opacity:1}}@keyframes pop-in{from{opacity:0;transform:translateY(8px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}@media(max-width:760px){.confirm-dialog{padding:21px}.confirm-actions button{flex:1}}
</style><style>
.app-chart{display:grid;gap:14px;margin:16px 0 20px}.app-usage-row{display:grid;grid-template-columns:40px minmax(110px,180px) minmax(80px,1fr) 58px;align-items:center;gap:12px}.app-icon{width:38px;height:38px;display:grid;place-items:center;border:1px solid #dce8f2;border-radius:11px;background:linear-gradient(145deg,#f1f7fc,#e6f0f7);color:#155e75;font-size:13px;font-weight:750;box-shadow:0 2px 5px #152a3c0c}.app-usage-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#24364a;font-size:13px}.app-bar-track{height:9px;border-radius:99px;background:#edf2f6;overflow:hidden}.app-bar-fill{height:100%;border-radius:99px;background:linear-gradient(90deg,#155e75,#35a995);transition:width .35s ease}.app-duration{text-align:right;color:#526477;font-size:12px;font-weight:650}.app-chart-note{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 12px;border:1px solid #e5edf4;border-radius:9px;background:#f8fafc}.app-switches{margin-top:16px;border-top:1px solid #edf0f3;padding-top:12px}.app-switches summary{cursor:pointer;color:#155e75;font-size:12px;font-weight:650}.app-switch{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid #edf0f3}.app-switch-name{display:flex;align-items:center;gap:10px}.security-alert{position:relative;overflow:hidden;margin:10px 0 2px;padding:15px;border:1px solid #f0dfcf;border-left:4px solid #d97706;border-radius:11px;background:linear-gradient(135deg,#fffaf4,#fff 72%);box-shadow:0 4px 12px #79400b0a}.security-alert__head{display:flex;align-items:center;gap:10px}.security-alert__icon{width:34px;height:34px;flex:none;display:grid;place-items:center;border-radius:11px;background:#fff0d6;color:#9b570b;font-size:17px;font-weight:800}.security-alert__title{color:#26364a;font-size:14px;font-weight:700}.security-alert__badge{margin-left:auto;padding:5px 9px;border:1px solid #f1d9b9;border-radius:99px;background:#fff4e4;color:#8a4b08;font-size:10px;font-weight:750;letter-spacing:.04em;text-transform:uppercase}.security-facts{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px}.security-fact{min-width:0;padding:9px 10px;border:1px solid #edf0f3;border-radius:8px;background:#fff}.security-fact .meta{margin:0 0 4px}.security-fact strong{display:block;overflow-wrap:anywhere;color:#26364a;font-size:12px}.security-timeline{margin-top:13px;padding:11px;border-radius:9px;background:#fff;border:1px solid #edf0f3}.security-timeline__label{margin-bottom:9px;color:#69798a;font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}.security-timeline__points{display:flex;align-items:center;gap:6px;overflow-x:auto;padding:2px 0 4px}.timeline-point{display:flex;align-items:center;gap:6px;flex:none;color:#34485d;font-size:11px;white-space:nowrap}.timeline-point i{width:20px;height:20px;display:grid;place-items:center;border-radius:50%;background:#fff0d6;color:#9b570b;font-size:10px;font-style:normal;font-weight:750}.timeline-connector{width:18px;height:1px;flex:none;background:#e4c79f}.security-guidance{margin-top:10px;color:#69798a;font-size:11px;line-height:1.45}.security-guidance b{color:#42566b}.export-button{display:inline-flex;align-items:center;gap:8px;padding:10px 13px;border:1px solid #ffffff30;border-radius:8px;background:#1c7690;color:#fff;font-size:12px;font-weight:700;text-decoration:none;white-space:nowrap}.export-button:hover{background:#238ca5}.logout-button{padding:9px 11px;border:1px solid #ffffff45;border-radius:8px;background:#ffffff12;color:#eff6fc;font-size:12px}.logout-button:hover{background:#ffffff24}.top-brand{display:flex;align-items:center;gap:12px}.top-brand .watchtower-mark{display:block;width:46px;height:46px;flex:none}@media(max-width:760px){.app-usage-row{grid-template-columns:38px minmax(80px,1fr) 54px;gap:9px}.app-bar-track{grid-column:2/4;grid-row:2}.app-usage-name{grid-column:2;grid-row:1}.app-duration{grid-column:3;grid-row:1}.security-facts{grid-template-columns:1fr 1fr}.top{gap:12px}.export-button{padding:8px 10px;font-size:11px}}
</style><style>
:root{font-family:"Segoe UI",Arial,sans-serif;color:#202b38;background:#f2f4f7}
body{background:linear-gradient(180deg,#e9edf2 0,#f4f6f8 250px,#f4f6f8 100%);color:#202b38}
.top{position:relative;background:linear-gradient(112deg,#182433 0%,#263648 62%,#354455 100%);box-shadow:0 8px 26px #14213125}
.top:after{content:"";position:absolute;inset:auto 0 0;height:3px;background:linear-gradient(90deg,#9e7620,#e1bd60,#9e7620)}
.top-brand h1{letter-spacing:-.04em}.top-brand p{color:#c1cbd6}
.top-brand img{border:1px solid #d9bd70;box-shadow:0 3px 12px #080e1938}
.wrap{max-width:1280px;padding-top:27px;padding-bottom:40px}
.notice{border-color:#e5c778;background:linear-gradient(110deg,#fff9e9,#fffdf7);box-shadow:0 3px 12px #9b76200c}
.grid{gap:18px}
.card{border:1px solid #e0e5eb;border-radius:15px;padding:21px;background:linear-gradient(145deg,#fff,#fcfdfe);box-shadow:0 5px 18px #1d2b3b0b;transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease}
.card:hover{transform:translateY(-2px);border-color:#d5c28e;box-shadow:0 10px 26px #1d2b3b14}
.card h2{color:#1e2b3a;letter-spacing:-.02em}
.card h2:before{content:"";display:inline-block;width:4px;height:16px;margin:0 9px 0 0;border-radius:4px;background:#c49a37;vertical-align:-2px}
.meta,.card p{color:#6c7887}
.app-icon{border-color:#e6dcc2;background:linear-gradient(145deg,#fffaf0,#f3eddf);color:#67511f}
.app-bar-track{background:#e9edf1}.app-bar-fill{background:linear-gradient(90deg,#344457,#c19a3d)}
.app-chart-note{border-color:#e7e0d0;background:#fcfaf5}
.app-switches summary{color:#87671d}.app-switches{border-color:#e9edf1}
.security-alert{border-color:#ead9b6;border-left-color:#bd8e2d;background:linear-gradient(135deg,#fffaf0,#fff 76%);box-shadow:0 5px 16px #8a67160d}
.security-alert__icon,.security-timeline__points .timeline-point i{background:#f8edcf;color:#775916}
.security-alert__badge{border-color:#e8d59d;background:#fff8e4;color:#755719}
.security-fact,.security-timeline{border-color:#e7e9ec;background:#fff}
.export-button{border:1px solid #dfc36f;background:linear-gradient(110deg,#354354,#253243);box-shadow:0 3px 9px #10192325;transition:transform .16s,box-shadow .16s}
.export-button:hover{transform:translateY(-1px);background:linear-gradient(110deg,#46566a,#303f52);box-shadow:0 6px 14px #10192336}
.logout-button{border-color:#ffffff55;background:#ffffff0d;transition:background .16s,border-color .16s}.logout-button:hover{border-color:#dfc36f;background:#ffffff1b}
.button,.secondary,.danger{border-radius:9px;transition:transform .15s,box-shadow .15s,filter .15s}
.button:focus-visible,.secondary:focus-visible,.danger:focus-visible,.export-button:focus-visible,.logout-button:focus-visible{outline:3px solid #d7b557;outline-offset:2px}
.button:hover,.secondary:hover,.danger:hover{filter:brightness(1.04);transform:translateY(-1px);box-shadow:0 4px 10px #1823311b}
@media(max-width:980px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.grid{grid-template-columns:1fr}.wide,.full{grid-column:1}.wrap{padding-top:18px}.card{padding:17px}}
</style><style>
:root{color:#e7edf4;background:#111923}
body{background:radial-gradient(ellipse at 50% 0%,#293849 0,#182330 300px,#111923 760px);color:#e7edf4}
.top{background:linear-gradient(112deg,#101923 0%,#1b2938 62%,#29394b 100%)}
.notice{color:#f1dfae;background:linear-gradient(110deg,#302a1e,#28271f);border-color:#79612b;box-shadow:0 4px 16px #0003}
.grid .card{color:#e7edf4;border-color:#354252;background:linear-gradient(145deg,#202c3a,#1a2532);box-shadow:0 8px 24px #070c1280}
.grid .card:hover{border-color:#9b7d3c;box-shadow:0 12px 30px #070c12a8}
.card h2{color:#f1f4f8}.meta,.card p{color:#a8b4c2}.status{color:#c0cad5}.empty{color:#a8b4c2}
.row,.app-switches{border-color:#354252}.row strong,.app-usage-name{color:#e5ebf2}.app-duration{color:#bbc5d0}
.app-icon{border-color:#625332;background:linear-gradient(145deg,#393525,#2a2b2b);color:#e2c46e;box-shadow:0 2px 6px #0004}
.app-bar-track{background:#354252}.app-bar-fill{background:linear-gradient(90deg,#65788e,#d3ad4f)}
.app-chart-note{border-color:#3e4650;background:#252f3a;color:#dce3eb}.pill{background:#303c49;color:#e0c166}
.app-switches summary{color:#e0c166}.app-switch{border-color:#354252}.timeline-point{color:#d4dce5}.timeline-connector{background:#8b7440}
.security-alert{border-color:#6e5930;border-left-color:#d4ad4f;background:linear-gradient(135deg,#332d21,#252b32 78%);box-shadow:0 6px 18px #080d1380}
.security-alert__icon,.security-timeline__points .timeline-point i{background:#514326;color:#f0d27a}
.security-alert__title,.security-fact strong{color:#f0f3f7}.security-alert__badge{border-color:#766132;background:#41371f;color:#f0d27a}
.security-fact,.security-timeline{border-color:#3b4653;background:#202b37}.security-timeline__label,.security-guidance{color:#b6c0cb}.security-guidance b{color:#e7d18f}
.list{scrollbar-color:#637184 #202b37}
input{border-color:#465361;background:#151f2a;color:#ecf1f6}input::placeholder{color:#8492a1}input:focus{outline:2px solid #b99743;outline-offset:1px}
button.secondary{background:#344151;color:#e6ecf2;border:1px solid #4c5b6b}.button,button.danger{color:#fff}
.confirm-dialog{background:#202b37;border-color:#43505e;box-shadow:0 24px 70px #000a}.confirm-dialog h2{color:#f1f4f8}.confirm-dialog p{color:#c0cad5}
.confirm-actions .secondary{background:#354252;color:#e7edf4}.confirm-icon{background:#514326;color:#f0d27a}
.privacy{color:#abb6c3;border-color:#414d5a}.privacy strong{color:#e4d39d}
.wrap{max-width:1320px;padding-top:30px}
.grid{align-items:stretch;gap:20px}
.grid .card{border-radius:16px;padding:22px}
.card h2{font-size:16px;line-height:1.35}
.metric{color:#e1c064}
.monitor-card{border-color:#77633a!important;background:linear-gradient(145deg,#242f3b,#1b2632)!important}
.monitor-card .meta{line-height:1.55}
#watchform{margin-top:15px}
#watchform input{min-height:44px;border-radius:9px}
#watchform button:not(.secondary){background:linear-gradient(110deg,#d7b456,#b88e32);color:#18212b;box-shadow:0 3px 10px #080d1455}
#watchform button:not(.secondary):hover{background:linear-gradient(110deg,#e8c96f,#cca448)}
button{transition:background .16s ease,transform .16s ease,box-shadow .16s ease}
button:hover{transform:translateY(-1px)}
button:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid #d7b557;outline-offset:3px}
.list{scrollbar-width:thin;scrollbar-color:#637184 #202b37}
.panel-heading{display:flex;align-items:center;justify-content:space-between;gap:10px}
.email-dialog{width:min(620px,calc(100% - 28px));max-height:min(88vh,800px);overflow:auto;padding:24px;border:1px solid #9b7d3c;border-radius:17px;background:linear-gradient(145deg,#202c3a,#17212d);color:#e7edf4;box-shadow:0 28px 90px #000b}
.email-dialog::backdrop{background:#07111ddd;backdrop-filter:blur(5px)}
.email-dialog h2{margin:0 0 8px;color:#f1f4f8;font-size:19px}
.email-dialog h2:before{content:"";display:inline-block;width:4px;height:18px;margin:0 9px 0 0;border-radius:4px;background:#c49a37;vertical-align:-3px}
.email-dialog-header{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:8px}
.email-dialog-close{padding:5px 10px;border:1px solid #4c5b6b;background:#344151;color:#e6ecf2;font-size:18px}
.email-settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 18px;margin:16px 0}
.email-field{display:grid;gap:6px;color:#d8e0e9;font-size:12px;font-weight:650}
.email-field input{width:100%;min-width:0;min-height:42px;border:1px solid #465361;border-radius:9px;background:#151f2a;color:#ecf1f6;padding:10px 12px}
.email-help{margin:0;color:#a8b4c2;font-size:12px;line-height:1.55}
.email-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:14px}
#email-config-state{color:#d8c27b;font-size:12px}
.email-dialog h3,.app-controls h3{margin:10px 0;color:#e9edf3;font-size:15px}
.app-controls{border-top:1px solid #d9e0e8;margin-top:18px;padding-top:16px}
.browse-wrap{position:relative;display:inline-flex}
.browse-menu{position:absolute;z-index:5;top:calc(100% + 6px);left:0;display:grid;gap:6px;min-width:150px;padding:7px;border:1px solid #9b7d3c;border-radius:10px;background:#202c3a;box-shadow:0 10px 25px #0008}
.browse-menu[hidden]{display:none}
.browse-menu button{white-space:nowrap}
<style>.app-usage-row{grid-template-columns:40px minmax(110px,180px) minmax(80px,1fr) 58px 78px}
.settings-status-section{margin-bottom:18px;padding:12px;border:1px solid #786331;border-radius:12px;background:#222c35}
.settings-status-section h3{margin-top:0}
@media(max-width:620px){.email-settings-grid{grid-template-columns:1fr}}
@media(max-width:760px){.wrap{padding-top:18px}.grid .card{padding:18px}}
</style><style>
:root{color-scheme:light;color:#202b38;background:#f3f6fa}
body{background:linear-gradient(180deg,#e8edf3 0,#f5f7fa 260px,#f5f7fa 100%);color:#202b38}
.top{background:linear-gradient(112deg,#182433 0%,#263648 62%,#354455 100%)}
.notice{color:#654f18;background:linear-gradient(110deg,#fff9e9,#fffdf7);border-color:#e5c778}
.grid .card{color:#202b38;border-color:#e0e5eb;background:linear-gradient(145deg,#fff,#fcfdfe);box-shadow:0 5px 18px #1d2b3b0b}
.grid .card:hover{border-color:#d5c28e;box-shadow:0 10px 26px #1d2b3b14}
.card h2{color:#1e2b3a}.meta,.card p{color:#6c7887}.status{color:#536273}.empty{color:#7c8998}
.row,.app-switches{border-color:#edf0f3}.row strong,.app-usage-name{color:#26364a}.app-duration{color:#526477}
.app-icon{border-color:#e6dcc2;background:linear-gradient(145deg,#fffaf0,#f3eddf);color:#67511f;box-shadow:0 2px 5px #152a3c0c}
.app-bar-track{background:#e9edf1}.app-bar-fill{background:linear-gradient(90deg,#344457,#c19a3d)}
.app-chart-note{border-color:#e7e0d0;background:#fcfaf5;color:#34485d}.pill{background:#edf5f7;color:#155e75}
.app-switches summary{color:#87671d}.app-switch{border-color:#edf0f3}.timeline-point{color:#34485d}.timeline-connector{background:#e4c79f}
.security-alert{border-color:#ead9b6;border-left-color:#bd8e2d;background:linear-gradient(135deg,#fffaf0,#fff 76%);box-shadow:0 5px 16px #8a67160d}
.security-alert__icon,.security-timeline__points .timeline-point i{background:#f8edcf;color:#775916}
.security-alert__title,.security-fact strong{color:#26364a}.security-alert__badge{border-color:#e8d59d;background:#fff8e4;color:#755719}
.security-fact,.security-timeline{border-color:#e7e9ec;background:#fff}.security-timeline__label,.security-guidance{color:#69798a}.security-guidance b{color:#42566b}
.list{scrollbar-color:#c3ccd6 #f2f4f7}
input{border-color:#cad3de;background:#fff;color:#202b38}input::placeholder{color:#8491a0}input:focus{outline:2px solid #b99743;outline-offset:1px}
button.secondary{background:#e7eef4;color:#24364a;border:1px solid #d3dde6}.button,button.danger{color:#fff}
.confirm-dialog{background:#fff;border-color:#e3e9f0;box-shadow:0 24px 70px #07142635}.confirm-dialog h2{color:#182230}.confirm-dialog p{color:#536273}
.confirm-actions .secondary{background:#e7eef4;color:#24364a}.confirm-icon{background:#fff3d6;color:#9a5a14}
.privacy{color:#758193;border-color:#eee8da}.privacy strong{color:#596b7e}
.monitor-card{border-color:#dfc77f!important;background:linear-gradient(145deg,#fff,#fcfdfe)!important}
#watchform button:not(.secondary){background:linear-gradient(110deg,#e0bd5b,#c69a37);color:#202b38;box-shadow:0 3px 10px #080d1422}
.email-dialog{border-color:#d8c28d;background:linear-gradient(145deg,#fff,#f6f8fb);color:#202b38;box-shadow:0 28px 90px #07142655}
.email-dialog h2{color:#182230}.email-dialog-close{border-color:#d3dde6;background:#e7eef4;color:#24364a}
.email-field{color:#34485d}.email-field input{border-color:#cad3de;background:#fff;color:#202b38}
.email-help{color:#687587}#email-config-state{color:#755719}.email-dialog h3,.app-controls h3{color:#26364a}
.browse-menu{border-color:#d8c28d;background:#fff;box-shadow:0 10px 25px #17263822}
.settings-status-section{border-color:#e0e5eb;background:#f8fafc}
</style><style>.app-usage-row{grid-template-columns:40px minmax(110px,180px) minmax(80px,1fr) 58px 82px;align-items:center}.app-actions{display:flex;align-items:center;justify-content:center;gap:8px;align-self:center}.app-action-button{width:36px;height:36px;display:grid;place-items:center;align-self:center;padding:0;border:1px solid #d5dce4;border-radius:10px;background:#f3f6f9;color:#775916;cursor:pointer;font-size:17px;line-height:1}.app-action-button svg{display:block;width:17px;height:17px;stroke:currentColor;stroke-width:1.8;fill:none;stroke-linecap:round;stroke-linejoin:round}.app-action-button.is-locked{background:#fff0e9;border-color:#d49a87}.app-action-button.has-limit{border-color:#c4a653;color:#775916}.app-limit-options{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:16px 0;max-height:260px;overflow-y:auto;padding:3px 5px 3px 3px;scrollbar-width:thin;scrollbar-color:#c49a37 #edf0f3}.app-limit-option{min-height:54px;display:grid;align-content:center;justify-items:center;gap:3px;border:1px solid #d9e0e8;border-radius:12px;background:#f7f9fb;color:#26364a}.app-limit-option strong{font-size:18px}.app-limit-option span{font-size:10px;color:#687587}.app-limit-option[aria-pressed=true]{border-color:#c49a37;background:#fff8e7;box-shadow:0 0 0 2px #c49a3722}.app-limit-dialog-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:12px}@media(max-width:760px){.app-usage-row{grid-template-columns:38px minmax(80px,1fr) 54px;gap:9px}.app-usage-name{grid-column:2;grid-row:1}.app-duration{grid-column:3;grid-row:1}.app-bar-track{grid-column:2/4;grid-row:2}.app-actions{grid-column:2/4;grid-row:3;justify-content:flex-start}.app-limit-options{grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;max-height:240px}.app-limit-option{min-height:50px}}</style></head><body><header class="top"><div class="top-brand"><img src="/watchtower_emblem.png" alt="WatchTower emblem" style="display:block;width:48px;height:48px;object-fit:contain;border-radius:10px;background:#fff"><div><h1>WatchTower</h1><p>Local user activity and security monitor</p></div></div><div style="display:flex;align-items:center;gap:15px;flex-wrap:wrap;justify-content:flex-end"><a class="export-button" href="/api/report.pdf" title="Download current activity as a PDF">⇩ Export PDF</a><button id="settings-open-button" class="secondary" type="button" title="Settings" aria-label="Open settings" style="font-size:19px;padding:8px 12px">⚙</button><button class="logout-button" type="button" onclick="logout()">Sign out</button><span id="app-indicator" style="display:flex;align-items:center;gap:8px;color:#e6edf3;font-size:13px;font-weight:700"><i style="width:10px;height:10px;border-radius:50%;background:#8a96a3;display:inline-block"></i><b>Inactive</b></span></div></header><main class="wrap">
<div class="notice"><b>Privacy:</b> Monitoring is visible and runs only while this app is open. Records stay in a local SQLite file. Use only on a computer you own or are authorized to monitor.</div>
<section class="grid"><article class="card"><h2>Windows sign-ins</h2><div id="win" class="status" hidden></div><div id="fails" class="metric">—</div><div class="meta">Failed sign-ins in the last 24 hours</div></article>
<article class="card"><h2>File integrity</h2><div id="files" class="metric">—</div><div class="status">Monitored locations</div><div id="fstatus" class="meta"></div></article>
<article class="card"><h2>Session action</h2><div class="status">Lock the current Windows session when needed.</div><button class="danger" onclick="lockSession()">Lock this Windows session</button></article>
<article class="card full monitor-card"><h2>Monitor a file</h2><form id="watchform" class="toolbar"><input id="path" placeholder="Choose a file to monitor" required><button type="button" class="secondary" onclick="browsePath(&#39;file&#39;)">Browse files</button><button>Add file</button><button type="button" class="secondary" onclick="refresh()">Refresh</button></form><div id="watch-message" class="meta" role="status" style="margin-top:9px"></div><div class="meta">Each selected file is monitored individually. Changes are recorded using SHA-256 hashes.</div><div id="watchlist" class="list"></div></article>
<article class="card wide"><div style="display:flex;align-items:center;justify-content:space-between;gap:10px"><h2>Recent activity</h2><button class="secondary" onclick="clearActivity()">Clear recent activity</button></div><div id="events" class="list"></div></article>
<article class="card"><div class="panel-heading"><h2>Security alerts</h2></div><div id="alerts-help" class="meta" style="margin:-4px 0 8px">Alerts are created for failed sign-ins. Windows may require WatchTower to run as administrator to read sign-in events.</div><div id="alerts" class="list"></div></article>
<article class="card full"><div style="display:flex;align-items:center;justify-content:space-between;gap:10px"><h2>Windows sign-in history</h2><button id="signin-history-toggle" class="secondary" type="button" onclick="toggleSignInHistory()">View detailed history</button></div><div class="meta" style="margin:-4px 0 8px">Latest 10 sign-ins and session lock/unlock events. Older entries are available in detailed history.</div><div id="signin-events" class="list"></div></article>
<article class="card full"><h2>Application activity</h2><div class="meta" style="margin:-4px 0 8px">App use is estimated from samples recorded during the last 24 hours while WatchTower was running. Set a four-digit app lock password in Settings, then use the lock or clock controls beside an app.</div><div id="application-events" class="list"></div></article><article class="card full"><h2>Collector status</h2><div id="dashboard-collector-status" class="status"><div class="empty">Connecting to collectors…</div></div></article></section></main>
<dialog id="settings-dialog" class="email-dialog" aria-labelledby="settings-dialog-title"><div class="email-dialog-header"><div><h2 id="settings-dialog-title">WatchTower settings</h2><p class="email-help">Email alerts and the four-digit app lock password.</p></div><button id="settings-close-button" type="button" class="email-dialog-close" aria-label="Close settings">×</button></div><section><h3>Email alerts</h3><div id="email-config-state" role="status">Loading saved settings…</div><form id="email-settings-form"><div class="email-settings-grid"><label class="email-field">SMTP server<input id="email-host" name="host" value="smtp.gmail.com" maxlength="255" required></label><label class="email-field">SMTP port<input id="email-port" name="port" type="number" min="1" max="65535" value="587" required></label><label class="email-field">Email account / SMTP username<input id="email-username" name="username" type="email" autocomplete="username" required></label><label class="email-field">Sender email<input id="email-sender" name="sender" type="email" required></label><label class="email-field">Alert recipient<input id="email-recipient" name="recipient" type="email" required></label><label class="email-field">Mail app password<input id="email-password" name="password" type="password" autocomplete="new-password" placeholder="Enter mail app password"></label></div><p class="email-help">For Gmail, use your Google app password. It is encrypted for this Windows account. Leave it blank to keep the saved password.</p><div class="email-actions"><button type="submit">Save email settings</button><button id="email-test-button" type="button" class="secondary">Send test email</button><span id="email-action-message" class="meta" role="status"></span></div></form></section><section class="settings-password-section"><h3>App lock password</h3><p id="app-password-state" class="email-help">Set a four-digit password to lock and unlock apps.</p><form id="app-password-form" class="email-settings-grid"><label class="email-field">Current password<input id="app-password-current" type="password" inputmode="numeric" maxlength="256" autocomplete="current-password"></label><label class="email-field">Four-digit password<input id="app-password-new" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" minlength="4" autocomplete="new-password" required></label><button type="submit">Save app lock password</button><span id="app-password-message" class="meta" role="status"></span></form></section></dialog>
<dialog id="app-rule-password-dialog" class="email-dialog" aria-labelledby="rule-password-title"><div class="email-dialog-header"><div><h2 id="rule-password-title">Lock this app</h2><p id="rule-password-help" class="email-help"></p></div><button id="rule-password-close" type="button" class="email-dialog-close" aria-label="Cancel">×</button></div><form id="rule-password-form"><label class="email-field">Four-digit app lock password<input id="rule-password-input" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" minlength="4" autocomplete="current-password" required></label><input id="rule-password-action" type="hidden"><input id="rule-password-exe" type="hidden"><div class="email-actions"><button id="rule-password-submit" type="submit">Lock app</button><button id="rule-password-cancel" type="button" class="secondary">Cancel</button><span id="rule-password-message" class="meta" role="status"></span></div></form></dialog>
<dialog id="app-time-limit-dialog" class="email-dialog" aria-labelledby="app-time-limit-title"><div class="email-dialog-header"><div><h2 id="app-time-limit-title">Daily app time limit</h2><p id="app-time-limit-help" class="email-help">Choose a daily limit for this application.</p></div><button id="app-time-limit-close" type="button" class="email-dialog-close" aria-label="Close time limit dialog">×</button></div><form id="app-time-limit-form"><input id="app-time-limit-exe" type="hidden"><input id="app-time-limit-value" type="hidden" value="15"><div id="app-limit-options" class="app-limit-options" role="listbox" aria-label="Choose daily app time limit"></div><p id="app-time-limit-message" class="email-help" role="status"></p><label id="app-time-limit-password-wrap" class="email-field" hidden>App lock password<input id="app-time-limit-password" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" minlength="4" autocomplete="current-password"></label><div class="app-limit-dialog-actions"><button id="app-time-limit-remove" type="button" class="secondary" aria-label="Remove this app time limit">Remove time limit</button><button id="app-time-limit-cancel" type="button" class="secondary">Cancel</button><button id="app-time-limit-save" type="submit">Save time limit</button></div></form></dialog>
<div id="confirm-overlay" class="confirm-overlay" hidden><section id="confirm-dialog" class="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-message"><div class="confirm-icon" aria-hidden="true">!</div><h2 id="confirm-title">Please confirm</h2><p id="confirm-message"></p><div class="confirm-actions"><button id="confirm-cancel" class="secondary" type="button">Cancel</button><button id="confirm-accept" class="danger" type="button">Confirm</button></div></section></div>
<script>
const token='__TOKEN__';async function api(url,options={}){options.headers={...(options.headers||{}),'X-WatchTower-Token':token,'Content-Type':'application/json'};const r=await fetch(url,options);const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
const expandedFileDetails = new Set();
document.querySelector('#events').addEventListener('toggle', event => {
  const details = event.target;
  if (!details.matches?.('details[data-event-id]')) return;
  const id = Number(details.dataset.eventId);
  if (details.open) expandedFileDetails.add(id); else expandedFileDetails.delete(id);
  const summary = details.querySelector('summary');
  if (summary) summary.textContent = details.open ? 'Close change details' : 'View change details';
}, true);
function rows(items) {
  if (!items.length) {
    return '<div class="empty">Nothing recorded yet</div>';
  }

  return items.map(x => {
    const beforeAfter = x.before_text !== null || x.after_text !== null
      ? `<details data-event-id="${Number(x.id)}" ${expandedFileDetails.has(Number(x.id)) ? 'open' : ''} style="margin-top:8px"><summary style="cursor:pointer;color:#155e75;font-weight:600">${expandedFileDetails.has(Number(x.id)) ? 'Close change details' : 'View change details'}</summary>
          <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:10px">
            <section style="flex:1;min-width:220px"><strong>Before</strong><pre style="white-space:pre-wrap;overflow:auto;max-height:220px;background:#fff3f2;border:1px solid #f0d4d1;border-radius:6px;padding:10px;font:12px Consolas,monospace">${esc(x.before_text ?? 'Previous contents unavailable.')}</pre></section>
            <section style="flex:1;min-width:220px"><strong>After</strong><pre style="white-space:pre-wrap;overflow:auto;max-height:220px;background:#f0faf4;border:1px solid #cdebd8;border-radius:6px;padding:10px;font:12px Consolas,monospace">${esc(x.after_text ?? 'Current contents unavailable.')}</pre></section>
          </div>
        </details>`
      : '';
    const undoLabel = x.message?.startsWith('File created:')
      ? 'Remove new file'
      : x.message?.startsWith('File deleted:')
        ? 'Restore deleted file'
        : 'Restore previous version';
    const undo = x.rollback_available
      ? `<button style="margin-top:8px;background:#9a5a14;padding:7px 10px;font-size:12px" onclick="rollbackEvent(${Number(x.id)})">${undoLabel}</button>`
      : '';

    return `<div class="row">
      <strong>${esc(x.message || x.title)}</strong>
      ${beforeAfter}
      <div class="meta">${esc(x.created_at)} ${x.category ? `· ${esc(x.category)}` : ''}</div>
      ${undo}
    </div>`;
  }).join('');
}
function displayDateTime(value){
  const date=new Date(value);
  if(Number.isNaN(date.getTime()))return {date:String(value||'Unknown'),time:'Unknown'};
  return {
    date:new Intl.DateTimeFormat(undefined,{year:'numeric',month:'short',day:'numeric'}).format(date),
    time:new Intl.DateTimeFormat(undefined,{hour:'numeric',minute:'2-digit',second:'2-digit'}).format(date)
  };
}
function signInRows(items){
  if(!items.length)return '<div class="empty">No sign-in events recorded yet</div>';
  return items.map(x=>{
    const failed=x.message?.startsWith('Failed sign-in:');
    const unlocked=x.message?.startsWith('Session unlocked:');
    const locked=x.message?.startsWith('Session locked:');
    const result=failed?'Failed sign-in':unlocked?'Session unlocked':locked?'Session locked':'Successful sign-in';
    const account=String(x.message||'').replace(/^(Failed sign-in|Successful sign-in|Session unlocked|Session locked):\s*/, '').split('\\').pop();
    const when=displayDateTime(x.created_at);
    const badgeStyle=failed?'background:#fff0ef;color:#a73333':locked?'background:#eef2f6;color:#4c5b6a':'background:#eaf8ef;color:#19713a';
    return `<div class="row" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px 14px;align-items:center"><div><div class="meta">Status</div><span class="pill" style="${badgeStyle}">${esc(result)}</span></div><div><div class="meta">Account</div><strong>${esc(account||'Unknown')}</strong></div><div><div class="meta">Date</div><span>${esc(when.date)}</span></div><div><div class="meta">Time</div><span>${esc(when.time)}</span></div></div>`;
  }).join('');
}
function applicationRows(items,controlData={},usageData=[]){
  if(!items.length&&!(usageData||[]).length)return '<div class="empty">Waiting for a foreground app sample. Keep WatchTower open while using apps.</div>';
  const chronological=[...items].sort((a,b)=>Date.parse(a.created_at)-Date.parse(b.created_at));
  const usage=new Map();
  const appName=x=>x.details?.application||x.message?.replace(/^Active application:\s*/,'')||'Unknown application';
  chronological.forEach((x,index)=>{const start=Date.parse(x.created_at);const next=chronological[index+1];const end=next?Date.parse(next.created_at):Date.now();if(!Number.isFinite(start)||!Number.isFinite(end)||end<=start)return;const duration=Math.min(end-start,30*60*1000);const name=appName(x);usage.set(name,(usage.get(name)||0)+duration)});
  const sampled=(usageData||[]).map(row=>[row.application,Number(row.seconds||0)*1000]).filter(row=>row[0]&&row[1]>0);const ranked=(sampled.length?sampled:[...usage.entries()]).sort((a,b)=>b[1]-a[1]).slice(0,8);const maxDuration=Math.max(...ranked.map(([,duration])=>duration),1);
  const iconFor=name=>{const key=name.toLowerCase().replace(/\.exe$/,'');const known={chrome:'🌐',msedge:'🌐',firefox:'🌐',code:'</>',notepad:'N',explorer:'📁',winword:'W',excel:'X',powerpnt:'P',teams:'T',python:'Py'};return known[key]||key.slice(0,2).toUpperCase()||'APP'};
  const formatDuration=ms=>{const minutes=Math.round(ms/60000);if(minutes<1)return '<1 min';const hours=Math.floor(minutes/60);return hours?`${hours}h ${minutes%60}m`:`${minutes}m`};
  const policies=new Map((controlData?.policies||[]).map(p=>[p.exe_name.toLowerCase(),p]));const passwordSet=Boolean(controlData?.password_configured);
  const chart=ranked.length?`<div class="app-chart">${ranked.map(([name,duration])=>{const policy=policies.get(name.toLowerCase())||{};const locked=Boolean(policy.locked);const key=encodeURIComponent(name).replace(/'/g,'%27');const selected=Number(policy.time_limit_minutes)||0;return `<div class="app-usage-row"><span class="app-icon" aria-hidden="true">${esc(iconFor(name))}</span><strong class="app-usage-name" title="${esc(name)}">${esc(name)}</strong><div class="app-bar-track" aria-label="Estimated focus time"><div class="app-bar-fill" style="width:${Math.max(4,duration/maxDuration*100)}%"></div></div><span class="app-duration">${esc(formatDuration(duration))}</span><div class="app-actions"><button class="app-action-button ${locked?'is-locked':''}" type="button" ${passwordSet?'':'disabled'} title="${passwordSet?(locked?'Unlock this app':'Lock this app'):'Set the app lock password in Settings first'}" aria-label="${locked?'Unlock':'Lock'} ${esc(name)}" onclick="openAppLock(decodeURIComponent('${key}'),${locked})"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path>${locked?'<path d="M12 14v3"></path>':''}</svg></button><button class="app-action-button ${selected?'has-limit':''}" type="button" ${passwordSet?'':'disabled'} title="Set daily time limit" aria-label="Set daily time limit for ${esc(name)}" onclick="openAppTimeLimit(decodeURIComponent('${key}'),${selected})"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path></svg></button></div></div>`}).join('')}</div>`:'<div class="empty">Switch between apps while WatchTower is running to build the usage chart.</div>';
  const recent=[...items].sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at)).slice(0,12).map(x=>{const details=x.details||{};const app=appName(x);const title=details.window_title||'';const when=displayDateTime(x.created_at);const titleDetails=title?`<details style="margin-top:5px"><summary style="cursor:pointer;color:#536273;font-size:11px">View window title</summary><div class="meta">${esc(title)}</div></details>`:'';return `<div class="app-switch"><div class="app-switch-name"><span class="app-icon" style="width:30px;height:30px;border-radius:8px;font-size:11px" aria-hidden="true">${esc(iconFor(app))}</span><div><strong>${esc(app)}</strong>${titleDetails}</div></div><div class="meta">${esc(when.date)} · ${esc(when.time)}</div></div>`}).join('');
  return `<div class="app-chart-note"><span class="meta" style="margin:0">Tracked app use · last 24 hours</span><span class="pill">${ranked.length} apps</span></div>${chart}<details class="app-switches"><summary>Recent app switches</summary><div style="margin-top:8px">${recent}</div></details>`;
}let latestSignInEvents=[];let detailedSignInEvents=null;let showingDetailedHistory=false;
function renderSignInHistory(){document.querySelector('#signin-events').innerHTML=signInRows(showingDetailedHistory?(detailedSignInEvents||[]):latestSignInEvents);document.querySelector('#signin-history-toggle').textContent=showingDetailedHistory?'Show latest 10':'View detailed history'}
async function toggleSignInHistory(){try{if(!showingDetailedHistory){const d=await api('/api/signin-history');detailedSignInEvents=d.signin_events||[];showingDetailedHistory=true}else{showingDetailedHistory=false}renderSignInHistory()}catch(e){console.error(e)}}
function alertRows(items){
  if(!items.length)return '<div class="empty">No sign-in alerts yet. WatchTower will list a notice here if it detects repeated incorrect password attempts.</div>';
  return items.map(a=>{
    let title=a.title||'Security alert',message=a.message||'';
    let details=a.details||{};
    const current=message.match(/Windows recorded (\d+) failed sign-in attempts? within (\d+) minutes for (.+)\.$/i);
    const legacy=message.match(/^(\d+) failed sign-ins? were recorded within (\d+) minutes\. Accounts: (.+)\.$/i);
    const parsed=current||legacy;
    if(parsed){
      const count=Number(parsed[1]);
      details={...details,failed_attempts:details.failed_attempts||count,timeframe_minutes:details.timeframe_minutes||Number(parsed[2]),account_names:details.account_names||parsed[3].split(/,\s*/).map(name=>name.split('\\').pop())};
      title=count===1?'Failed sign-in detected':'Multiple failed sign-ins detected';
    }
    const when=displayDateTime(a.created_at);
    const rawAccounts=Array.isArray(details.account_names)?details.account_names:[];
    const normalizedAccounts=rawAccounts.map(name=>String(name).split('\\').pop().trim()).filter(name=>name&&name!=='-'&&!/^unknown( account)?$/i.test(name)&&!/^not reported by windows$/i.test(name));
    const accountNames=normalizedAccounts.join(', ')||'Not reported by Windows';
    const attempts=Number.isFinite(Number(details.failed_attempts))?Number(details.failed_attempts):null;
    const timeframe=details.timeframe_minutes?`${Number(details.timeframe_minutes)} min`:'—';
    const attemptTimes=Array.isArray(details.attempt_times)?details.attempt_times:[];
    const timelinePoints=(attemptTimes.length?attemptTimes:[a.created_at]).map((value,index)=>{const point=displayDateTime(value);return `<span class="timeline-point" title="${esc(point.date)} ${esc(point.time)}"><i>${index+1}</i>${esc(point.time)}</span>`}).join('<span class="timeline-connector" aria-hidden="true"></span>');
    const alertTitle=attempts===1?'Failed sign-in':'Repeated failed sign-ins';
    return `<div class="security-alert"><div class="security-alert__head"><span class="security-alert__icon" aria-hidden="true">!</span><div><div class="security-alert__title">${esc(alertTitle)}</div><div class="meta">Windows sign-in activity</div></div><span class="security-alert__badge">Review</span></div><div class="security-facts"><div class="security-fact"><div class="meta">Failed attempts</div><strong>${esc(attempts===null?'—':attempts)}</strong></div><div class="security-fact"><div class="meta">Account</div><strong>${esc(accountNames)}</strong></div><div class="security-fact"><div class="meta">Detection window</div><strong>${esc(timeframe)}</strong></div><div class="security-fact"><div class="meta">Alert date</div><strong>${esc(when.date)}</strong></div></div><div class="security-timeline"><div class="security-timeline__label">Individual attempts · local time</div><div class="security-timeline__points">${timelinePoints}</div></div><div class="security-guidance"><b>If this wasn't you:</b> review your Windows account security.</div></div>`;
  }).join('');
}
function updateAppPasswordStatus(info){document.querySelector('#app-password-state').textContent=info?.password_configured?'Four-digit app lock password is set.':'Set a four-digit password here before locking or unlocking apps.'}
function showRefreshError(error){const message=esc(error?.message||'Unknown data refresh error');for(const selector of ['#events','#watchlist','#application-events','#signin-events','#alerts']){const node=document.querySelector(selector);if(node)node.innerHTML=`<div class="empty">Could not load this panel: ${message}</div>`}for(const selector of ['#win','#fstatus']){const node=document.querySelector(selector);if(node)node.textContent='Refresh failed: '+message}document.querySelector('#files').textContent='—';document.querySelector('#fails').textContent='—'}
async function refreshCollectorStatus(){const panel=document.querySelector('#dashboard-collector-status');try{const d=await api('/api/status');const entries=Object.entries(d.status||{});const active=d.application_active;const indicator=document.querySelector('#app-indicator');indicator.querySelector('i').style.background=active?'#34d399':'#8a96a3';indicator.querySelector('b').textContent=active?'Active':'Inactive';entries.push(['application_activity',active?'Active · sampling the foreground app':'Inactive · waiting for application monitor']);panel.innerHTML=entries.map(([key,value])=>`<div class="row"><strong>${esc(key.replaceAll('_',' '))}</strong><div class="meta">${esc(value)}</div></div>`).join('')}catch(e){panel.innerHTML=`<div class="row"><strong>Collector status unavailable</strong><div class="meta">${esc(e.message)} · Confirm WatchTower is running, then refresh this page.</div></div>`}}
let refreshInProgress=false;
async function refresh(){if(refreshInProgress)return;refreshInProgress=true;try{const d=await api('/api/data');document.querySelector('#fails').textContent=d.failed_24h;document.querySelector('#files').textContent=d.watches.length;document.querySelector('#win').textContent=d.status.windows_events;document.querySelector('#fstatus').textContent=d.status.file_monitor;const indicator=document.querySelector('#app-indicator');const active=d.application_active;indicator.querySelector('i').style.background=active?'#34d399':'#8a96a3';indicator.querySelector('b').textContent=active?'Active':'Inactive';document.querySelector('#events').innerHTML=rows(d.events);document.querySelector('#application-events').innerHTML=applicationRows(d.application_events||[],d.app_controls||{},d.application_usage||[]);latestSignInEvents=d.signin_events||[];if(!showingDetailedHistory)renderSignInHistory();document.querySelector('#alerts').innerHTML=alertRows(d.alerts||[]);document.querySelector('#watchlist').innerHTML=d.watches.length?d.watches.map(w=>{const path=String(w.path||"");const name=path.substring(Math.max(path.lastIndexOf("/"),path.lastIndexOf("\\"))+1)||path;return `<div class="row"><strong>${esc(name)}</strong><div class="meta">${esc(path)}</div></div>`}).join(''):'<div class="empty">No locations selected</div>';document.querySelector('#dashboard-collector-status').innerHTML=Object.entries(d.status).map(([k,v])=>`<div class="row"><strong>${esc(k.replaceAll('_',' '))}</strong><div class="meta">${esc(v)}</div></div>`).join('');updateAppPasswordStatus(d.app_controls)}catch(e){console.error(e);showRefreshError(e);document.querySelector('#dashboard-collector-status').innerHTML=`<div class="row"><strong>Collector information unavailable</strong><div class="meta">${esc(e.message)} · Check that WatchTower is still running, then refresh this page.</div></div>`}finally{refreshInProgress=false}}
document.querySelector('#watchform').addEventListener('submit',async e=>{e.preventDefault();const message=document.querySelector('#watch-message');message.textContent='Adding location…';try{await api('/api/watches',{method:'POST',body:JSON.stringify({path:document.querySelector('#path').value})});document.querySelector('#path').value='';await refresh();message.textContent='Location added. WatchTower is creating its baseline now.'}catch(err){message.textContent='Could not add location: '+err.message}});
function toggleBrowseMenu(){const menu=document.querySelector('#browse-menu');menu.hidden=!menu.hidden}
async function browsePath(kind){try{const d=await api('/api/browse-path',{method:'POST',body:JSON.stringify({kind:'file'})});if(d.path)document.querySelector('#path').value=d.path}catch(e){alert(e.message)}}
async function loadEmailSettings(){try{const d=await api('/api/email-settings');for(const key of ['host','port','username','sender','recipient'])document.querySelector('#email-'+key).value=d[key]||'';document.querySelector('#email-password').placeholder=d.password_saved?'Saved securely · leave blank to keep it':'Enter mail app password';document.querySelector('#email-config-state').textContent=d.configured?'Email alerts are configured for '+(d.recipient||'the selected recipient'):'Enter mail details and save to enable email alerts'}catch(e){document.querySelector('#email-config-state').textContent='Could not load saved email settings: '+e.message}}
document.querySelector('#settings-open-button').addEventListener('click',()=>{document.querySelector('#settings-dialog').showModal();refresh()});
document.querySelector('#settings-close-button').addEventListener('click',()=>document.querySelector('#settings-dialog').close());
document.querySelector('#email-settings-form').addEventListener('submit',async e=>{e.preventDefault();const message=document.querySelector('#email-action-message');message.textContent='Saving settings…';const body=Object.fromEntries(new FormData(e.currentTarget));try{const d=await api('/api/email-settings',{method:'POST',body:JSON.stringify(body)});document.querySelector('#email-password').value='';document.querySelector('#email-password').placeholder=d.settings.password_saved?'Saved securely · leave blank to keep it':'Enter mail app password';document.querySelector('#email-config-state').textContent='Email alerts are configured for '+d.settings.recipient;message.textContent='Settings saved on this computer.';refresh()}catch(err){message.textContent=err.message}});
document.querySelector('#email-test-button').addEventListener('click',async()=>{const message=document.querySelector('#email-action-message');message.textContent='Sending test email…';try{const d=await api('/api/email-test',{method:'POST',body:'{}'});message.textContent=d.message;refresh()}catch(err){message.textContent=err.message;refresh()}});
loadEmailSettings();refreshCollectorStatus();setInterval(refreshCollectorStatus,2000);
function openAppLock(exeName,isLocked){const action=isLocked?'unlock':'lock';const dialog=document.querySelector('#app-rule-password-dialog');document.querySelector('#rule-password-title').textContent=isLocked?'Unlock this app':'Lock this app';document.querySelector('#rule-password-help').textContent=`Enter your four-digit password to ${action} ${exeName}.`;document.querySelector('#rule-password-submit').textContent=isLocked?'Unlock app':'Lock app';document.querySelector('#rule-password-action').value=action;document.querySelector('#rule-password-exe').value=exeName;document.querySelector('#rule-password-input').value='';document.querySelector('#rule-password-message').textContent='';dialog.showModal();document.querySelector('#rule-password-input').focus()}
function buildAppLimitOptions(){const options=document.querySelector('#app-limit-options');if(options.childElementCount)return;for(let minutes=5;minutes<=240;minutes+=5){const button=document.createElement('button');button.type='button';button.className='app-limit-option';button.dataset.minutes=String(minutes);button.setAttribute('role','option');button.setAttribute('aria-pressed','false');button.innerHTML=`<strong>${minutes} min</strong><span>${minutes%60===0?`${minutes/60} hour${minutes===60?'':'s'}`:'per day'}</span>`;button.addEventListener('click',()=>selectAppLimitOption(minutes));options.appendChild(button)}}function openAppTimeLimit(exeName,current){buildAppLimitOptions();const dialog=document.querySelector('#app-time-limit-dialog');document.querySelector('#app-time-limit-exe').value=exeName;document.querySelector('#app-time-limit-help').textContent=`Choose a daily time limit for ${exeName}.`;document.querySelector('#app-time-limit-message').textContent=current?`Current limit: ${current} minutes per day.`:'No daily limit is set yet.';document.querySelector('#app-time-limit-remove').disabled=!current;document.querySelector('#app-time-limit-remove').textContent=current?'Remove time limit':'No time limit to remove';document.querySelector('#app-time-limit-password-wrap').hidden=true;document.querySelector('#app-time-limit-password').value='';document.querySelector('#app-time-limit-password').required=false;document.querySelector('#app-time-limit-save').hidden=false;selectAppLimitOption(current||15);dialog.showModal()}function selectAppLimitOption(minutes){document.querySelector('#app-time-limit-value').value=minutes;document.querySelectorAll('.app-limit-option').forEach(button=>button.setAttribute('aria-pressed',String(Number(button.dataset.minutes)===Number(minutes))));const selected=document.querySelector(`.app-limit-option[data-minutes="${Number(minutes)}"]`);if(selected)selected.scrollIntoView({block:'nearest'})}function closeAppLimitDialog(){document.querySelector('#app-time-limit-dialog').close()}document.querySelector('#app-time-limit-close').addEventListener('click',closeAppLimitDialog);document.querySelector('#app-time-limit-cancel').addEventListener('click',closeAppLimitDialog);document.querySelector('#app-time-limit-remove').addEventListener('click',async()=>{const passwordWrap=document.querySelector('#app-time-limit-password-wrap');const password=document.querySelector('#app-time-limit-password');const message=document.querySelector('#app-time-limit-message');if(passwordWrap.hidden){passwordWrap.hidden=false;password.required=true;document.querySelector('#app-time-limit-save').hidden=true;message.textContent='Enter your four-digit app lock password to remove this time limit.';password.focus();return}if(!password.reportValidity())return;const remove=document.querySelector('#app-time-limit-remove');remove.disabled=true;message.textContent='Removing time limit…';try{await api('/api/app-policy',{method:'POST',body:JSON.stringify({action:'clear-limit',exe_name:document.querySelector('#app-time-limit-exe').value,password:password.value})});closeAppLimitDialog();await refresh()}catch(err){message.textContent=err.message}finally{remove.disabled=false}});document.querySelector('#app-time-limit-form').addEventListener('submit',async e=>{e.preventDefault();const message=document.querySelector('#app-time-limit-message');const save=document.querySelector('#app-time-limit-save');save.disabled=true;message.textContent='Saving time limit…';try{await api('/api/app-policy',{method:'POST',body:JSON.stringify({action:'set-limit',exe_name:document.querySelector('#app-time-limit-exe').value,time_limit_minutes:document.querySelector('#app-time-limit-value').value})});closeAppLimitDialog();await refresh()}catch(err){message.textContent=err.message}finally{save.disabled=false}});
document.querySelector('#rule-password-close').addEventListener('click',()=>document.querySelector('#app-rule-password-dialog').close());document.querySelector('#rule-password-cancel').addEventListener('click',()=>document.querySelector('#app-rule-password-dialog').close());
document.querySelector('#rule-password-form').addEventListener('submit',async e=>{e.preventDefault();const message=document.querySelector('#rule-password-message');message.textContent='Applying change…';try{await api('/api/app-policy',{method:'POST',body:JSON.stringify({action:document.querySelector('#rule-password-action').value,exe_name:document.querySelector('#rule-password-exe').value,password:document.querySelector('#rule-password-input').value})});document.querySelector('#rule-password-input').value='';document.querySelector('#app-rule-password-dialog').close();refresh()}catch(err){message.textContent=err.message}});
document.querySelector('#app-password-form').addEventListener('submit',async e=>{e.preventDefault();const message=document.querySelector('#app-password-message');message.textContent='Saving password…';try{await api('/api/app-password',{method:'POST',body:JSON.stringify({current_password:document.querySelector('#app-password-current').value,new_password:document.querySelector('#app-password-new').value})});document.querySelector('#app-password-current').value='';document.querySelector('#app-password-new').value='';message.textContent='App-control password saved.';refresh()}catch(err){message.textContent=err.message}});
const confirmOverlay=document.querySelector('#confirm-overlay');const confirmDialog=document.querySelector('#confirm-dialog');let confirmResolver=null;
function finishConfirm(answer){confirmOverlay.hidden=true;document.body.style.overflow='';const resolve=confirmResolver;confirmResolver=null;if(resolve)resolve(answer)}
function showConfirm({title,message,confirmLabel='Confirm',tone='warning'}){document.querySelector('#confirm-title').textContent=title;document.querySelector('#confirm-message').textContent=message;const accept=document.querySelector('#confirm-accept');accept.textContent=confirmLabel;accept.className=tone==='danger'?'danger':'primary';confirmDialog.dataset.tone=tone;confirmOverlay.hidden=false;document.body.style.overflow='hidden';return new Promise(resolve=>{confirmResolver=resolve;accept.focus()})}
document.querySelector('#confirm-cancel').addEventListener('click',()=>finishConfirm(false));document.querySelector('#confirm-accept').addEventListener('click',()=>finishConfirm(true));confirmOverlay.addEventListener('click',e=>{if(e.target===confirmOverlay)finishConfirm(false)});document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!confirmOverlay.hidden)finishConfirm(false)});
async function clearActivity(){if(!await showConfirm({title:'Clear recent activity?',message:'This removes the file activity entries and their Undo options from WatchTower. It will not change or delete your files.',confirmLabel:'Clear activity',tone:'danger'}))return;try{await api('/api/events/clear',{method:'POST',body:'{}'});expandedFileDetails.clear();refresh()}catch(e){alert(e.message)}}
async function rollbackEvent(id){const d=await api('/api/data');const event=d.events.find(x=>x.id===id);if(!event)return;const created=event.message?.startsWith('File created:');const deleted=event.message?.startsWith('File deleted:');const action=created?'remove the file created by this event':deleted?'restore the deleted file from its saved copy':'restore the saved previous version of this file';const confirmLabel=created?'Remove file':deleted?'Restore file':'Restore version';if(!await showConfirm({title:created?'Remove this created file?':deleted?'Restore this deleted file?':'Restore the previous version?',message:`WatchTower will ${action}. This is available only if the file has not changed again since this activity was recorded.`,confirmLabel,tone:'warning'}))return;try{await api('/api/rollback',{method:'POST',body:JSON.stringify({event_id:id})});refresh()}catch(e){alert(e.message)}}
async function logout(){try{await api('/api/logout',{method:'POST',body:'{}'});location.reload()}catch(e){alert(e.message)}}
async function lockSession(){if(!confirm('Lock this Windows session now?'))return;try{await api('/api/lock',{method:'POST',body:'{}'})}catch(e){alert(e.message)}}refresh();setInterval(refresh,1000);
</script></body></html>'''.replace("__TOKEN__", TOKEN)
    return page.encode("utf-8")


def build_activity_report_pdf() -> bytes:
    """Build a small, dependency-free PDF report from WatchTower's local records."""
    with db_session() as db:
        file_events = [dict(row) for row in db.execute(
            "SELECT * FROM events WHERE category='file' AND "
            "(message LIKE 'File created:%' OR message LIKE 'File modified:%' OR "
            "message LIKE 'File deleted:%' OR message LIKE 'Rollback applied:%') "
            "ORDER BY id DESC LIMIT 150")]
        sign_ins = get_sign_in_history(db)
        app_events = [dict(row) for row in db.execute(
            "SELECT * FROM events WHERE category='application' AND datetime(created_at) >= datetime('now','-1 day') ORDER BY id DESC LIMIT 200")]
        alerts = [dict(row) for row in db.execute(
            "SELECT * FROM alerts WHERE datetime(created_at) >= datetime('now','-1 day') ORDER BY id DESC")]
        watches = [row["path"] for row in db.execute("SELECT path FROM watches ORDER BY path")]

    def human_time(value: str) -> str:
        try:
            return datetime.fromisoformat(value).astimezone().strftime("%b %d, %Y %I:%M:%S %p")
        except (TypeError, ValueError):
            return str(value or "Unknown time")

    def pdf_escape(value: str) -> str:
        safe = str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        return safe.encode("latin-1", "replace").decode("latin-1").replace("\r", " ").replace("\n", " ")

    page_contents: list[bytes] = []
    commands: list[str] = []
    y = 0

    def start_page(page_number: int) -> None:
        nonlocal commands, y
        commands = [
            "q 0.071 0.141 0.227 rg 0 754 595 88 re f Q",
            f"BT /F2 22 Tf 1 1 1 rg 1 0 0 1 48 805 Tm ({pdf_escape('WatchTower Activity Report')}) Tj ET",
            f"BT /F1 9 Tf 0.82 0.88 0.94 rg 1 0 0 1 50 781 Tm ({pdf_escape('Local user activity and security summary')}) Tj ET",
        ]
        y = 730

    def finish_page(page_number: int) -> None:
        commands.extend([
            "q 0.86 0.89 0.92 RG 48 48 m 547 48 l S Q",
            f"BT /F1 8 Tf 0.42 0.48 0.55 rg 1 0 0 1 48 32 Tm ({pdf_escape('Local report - WatchTower')}) Tj ET",
            f"BT /F1 8 Tf 0.42 0.48 0.55 rg 1 0 0 1 505 32 Tm ({pdf_escape(f'Page {page_number}')}) Tj ET",
        ])
        page_contents.append("\n".join(commands).encode("latin-1", "replace"))

    start_page(1)

    def add_text(value: str, *, size: int = 9, bold: bool = False,
                 color: tuple[float, float, float] = (0.16, 0.21, 0.28), gap: int = 4) -> None:
        nonlocal y
        sanitized = str(value).encode("latin-1", "replace").decode("latin-1")
        wrapped = textwrap.wrap(sanitized, width=max(35, int(500 / (size * 0.53))),
                                break_long_words=True, break_on_hyphens=False) or [""]
        for line in wrapped:
            if y < 67:
                finish_page(len(page_contents) + 1)
                start_page(len(page_contents) + 1)
            font = "F2" if bold else "F1"
            red, green, blue = color
            commands.append(
                f"BT /{font} {size} Tf {red:.3f} {green:.3f} {blue:.3f} rg "
                f"1 0 0 1 48 {y} Tm ({pdf_escape(line)}) Tj ET"
            )
            y -= size + 5
        y -= gap

    def section(title: str) -> None:
        nonlocal y
        y -= 5
        add_text(title, size=13, bold=True, color=(0.08, 0.35, 0.45), gap=2)
        commands.append(f"q 0.83 0.88 0.91 RG 48 {y + 3} m 547 {y + 3} l S Q")
        y -= 7

    add_text(f"Generated: {human_time(now_text())}", size=9, color=(0.35, 0.42, 0.50), gap=2)
    add_text("Report scope: sign-ins, alerts, and app activity from the last 24 hours; recent file activity is included.",
             size=9, color=(0.35, 0.42, 0.50), gap=8)
    section("Session summary")
    add_text(f"Monitored locations: {len(watches)}    |    File activity records: {len(file_events)}    |    Sign-in records: {len(sign_ins)}")
    add_text(f"Security alerts: {len(alerts)}    |    App switches recorded: {len(app_events)}")

    section("File activity")
    if not file_events:
        add_text("No file changes recorded.", color=(0.42, 0.48, 0.55))
    for event in file_events:
        try:
            details = json.loads(event.get("details") or "{}")
        except (TypeError, json.JSONDecodeError):
            details = {}
        file_name = Path(details.get("path", "")).name or "Unknown file"
        action = event.get("message", "File activity").split(":", 1)[0]
        add_text(f"{human_time(event.get('created_at'))}  |  {action}: {file_name}")

    section("Windows sign-in history")
    if not sign_ins:
        add_text("No sign-in events recorded in this session.", color=(0.42, 0.48, 0.55))
    for event in sign_ins:
        add_text(f"{human_time(event.get('created_at'))}  |  {event.get('message', 'Sign-in event')}")

    section("Security alerts")
    if not alerts:
        add_text("No security alerts recorded in this session.", color=(0.42, 0.48, 0.55))
    for alert in alerts:
        try:
            details = json.loads(alert.get("details") or "{}")
        except (TypeError, json.JSONDecodeError):
            details = {}
        accounts = ", ".join(details.get("account_names", [])) or "Not reported by Windows"
        count = details.get("failed_attempts", "Unknown")
        window = details.get("timeframe_minutes", "Unknown")
        add_text(f"{human_time(alert.get('created_at'))}  |  {alert.get('title', 'Security alert')}", bold=True)
        add_text(f"Failed attempts: {count}  |  Account: {accounts}  |  Detection window: {window} minutes")
        for attempt_time in details.get("attempt_times", []):
            add_text(f"    Attempt: {human_time(attempt_time)}", size=8, color=(0.38, 0.44, 0.51), gap=2)

    section("Application activity")
    if not app_events:
        add_text("No application switches recorded in this session.", color=(0.42, 0.48, 0.55))
    for event in app_events:
        try:
            details = json.loads(event.get("details") or "{}")
        except (TypeError, json.JSONDecodeError):
            details = {}
        app_name = details.get("application") or "Unknown application"
        add_text(f"{human_time(event.get('created_at'))}  |  {app_name}")

    section("Monitored locations")
    if not watches:
        add_text("No locations are currently monitored.", color=(0.42, 0.48, 0.55))
    for path in watches:
        add_text(path, size=8)

    finish_page(len(page_contents) + 1)

    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    }
    page_refs: list[str] = []
    for index, content in enumerate(page_contents):
        page_id = 5 + index * 2
        content_id = page_id + 1
        page_refs.append(f"{page_id} 0 R")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        objects[content_id] = f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream"
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>".encode("ascii")

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id in range(1, max(objects) + 1):
        offsets.append(len(pdf))
        pdf.extend(f"{object_id} 0 obj\n".encode("ascii"))
        pdf.extend(objects[object_id])
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii"))
    return bytes(pdf)


class Handler(BaseHTTPRequestHandler):
    server_version = "WatchTower/1.0"

    def handle_error(self, request, client_address) -> None:
        """Avoid noisy tracebacks when a browser closes a request mid-response."""
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{now_text()}] {fmt % args}")

    def send_json(self, data: dict, code: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            # The browser may cancel a poll during refresh/navigation. Collectors
            # run independently, so a closed client connection is harmless.
            return

    def session_token(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookie.get("WatchTowerSession")
        return morsel.value if morsel else None

    def authenticated_user(self) -> str | None:
        token = self.session_token()
        if not token:
            return None
        with AUTH_SESSIONS_LOCK:
            session = AUTH_SESSIONS.get(token)
            if not session:
                return None
            username, expires_at = session
            if expires_at <= time.time():
                AUTH_SESSIONS.pop(token, None)
                return None
            AUTH_SESSIONS[token] = (username, time.time() + LOGIN_SESSION_SECONDS)
            return username

    def send_html(self, raw: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_html(dashboard() if self.authenticated_user() else login_page())
        elif self.path == "/watchtower_logo.png" or self.path == "/watchtower_emblem.png":
            logo_path = LOGO_FULL_PATH if self.path == "/watchtower_logo.png" else LOGO_EMBLEM_PATH
            try:
                raw = logo_path.read_bytes()
            except OSError:
                self.send_json({"error": "Logo asset is unavailable"}, 404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(raw)
        elif not self.authenticated_user():
            self.send_json({"error": "Please sign in to access WatchTower"}, 401)
        elif self.path == "/api/status":
            with STATUS_LOCK:
                current = dict(STATUS)
            application_active = platform.system() == "Windows" and APP_MONITOR_LAST_SAMPLE > 0 and time.monotonic() - APP_MONITOR_LAST_SAMPLE < 10
            self.send_json({"status": current, "application_active": application_active})
        elif self.path == "/api/email-settings":
            try:
                self.send_json(public_email_settings())
            except Exception as exc:
                self.send_json({"error": f"Could not read email settings: {str(exc)[:160]}"}, 500)
        elif self.path == "/api/app-controls":
            self.send_json(app_control_data())
        elif self.path == "/api/report.pdf":
            try:
                raw = build_activity_report_pdf()
                filename = f"WatchTower-Activity-{datetime.now().astimezone():%Y%m%d-%H%M%S}.pdf"
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(raw)
            except Exception as exc:
                self.send_json({"error": f"Could not create the activity report: {exc}"}, 500)
        elif self.path == "/api/signin-history":
            with db_session() as db:
                sign_in_events = get_sign_in_history(db)
            self.send_json({"signin_events": sign_in_events})
        elif self.path == "/api/data":
            try:
              with db_session() as db:
                events = [dict(row) for row in db.execute(
                    "SELECT * FROM events WHERE category='file' AND "
                    "(message LIKE 'Monitoring started%' OR message LIKE 'File created:%' OR message LIKE 'File modified:%' OR "
                    "message LIKE 'File deleted:%' OR message LIKE 'Rollback applied:%') "
                    "ORDER BY id DESC LIMIT 100")]
                for event in events:
                    details = json.loads(event["details"] or "{}")
                    if details.get("path"):
                        event_kind = event["message"].split(":", 1)[0]
                        event["message"] = f"{event_kind}: {Path(details['path']).name}"
                    event["before_text"] = None
                    event["after_text"] = None
                    if "before_snapshot" in details or "after_snapshot" in details:
                        created = event["message"].startswith("File created:")
                        deleted = event["message"].startswith("File deleted:")
                        event["before_text"] = read_text_preview(
                            details.get("before_snapshot"), "This file did not exist before this event." if created else "Previous file contents were not saved."
                        )
                        event["after_text"] = read_text_preview(
                            details.get("after_snapshot"), "This file was deleted." if deleted else "Current file contents were not saved."
                        )
                    event["rollback_available"] = bool(details.get("rollback_available"))
                    # Keep full paths, hashes, and snapshot locations on the server.
                    event["details"] = "{}"
                sign_in_events = get_sign_in_history(db, limit=10)
                application_events = [dict(row) for row in db.execute(
                    "SELECT * FROM events WHERE category='application' AND datetime(created_at) >= datetime('now','-1 day') ORDER BY id DESC LIMIT 500")]
                for event in application_events:
                    try:
                        event["details"] = json.loads(event.get("details") or "{}")
                    except (TypeError, json.JSONDecodeError):
                        event["details"] = {}
                alerts = [dict(row) for row in db.execute("SELECT * FROM alerts WHERE datetime(created_at) >= datetime('now','-1 day') ORDER BY id DESC LIMIT 30")]
                for alert in alerts:
                    try:
                        alert["details"] = json.loads(alert.get("details") or "{}")
                    except (TypeError, json.JSONDecodeError):
                        alert["details"] = {}
                watches = [dict(row) for row in db.execute("SELECT * FROM watches ORDER BY id")
                           if not Path(row["path"]).is_dir()]
                app_controls = app_control_data(db)
                cutoff = datetime.fromtimestamp(datetime.now().astimezone().timestamp() - 86400).astimezone().isoformat(timespec="seconds")
                failed = db.execute("SELECT COUNT(*) FROM events WHERE category='authentication' AND message LIKE 'Failed sign-in:%' AND created_at >= ?",
                                    (cutoff,)).fetchone()[0]
                application_usage = [dict(row) for row in db.execute(
                    "SELECT exe_name AS application,SUM(seconds) AS seconds FROM app_usage_samples "
                    "WHERE datetime(created_at) >= datetime('now','-1 day') GROUP BY exe_name ORDER BY seconds DESC")]
              with STATUS_LOCK:
                  current = dict(STATUS)
              application_active = platform.system() == "Windows" and APP_MONITOR_LAST_SAMPLE > 0 and time.monotonic() - APP_MONITOR_LAST_SAMPLE < 10
              self.send_json({"events": events, "signin_events": sign_in_events,
                              "application_events": application_events,
                              "application_usage": application_usage,
                              "alerts": alerts, "watches": watches,
                              "app_controls": app_controls,
                              "failed_24h": failed, "status": current,
                              "application_active": application_active})
            except Exception as exc:
                if isinstance(exc, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)):
                    return
                print(f"[{now_text()}] /api/data failed: {type(exc).__name__}: {exc}")
                try:
                    self.send_json({"error": f"Could not refresh dashboard data ({type(exc).__name__}). Check the WatchTower terminal for details."}, 500)
                except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                    pass
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        if self.headers.get("X-WatchTower-Token") != TOKEN:
            self.send_json({"error": "Request rejected"}, 403)
            return
        size = min(int(self.headers.get("Content-Length", "0")), 10000)
        try:
            data = json.loads(self.rfile.read(size) or b"{}")
        except (json.JSONDecodeError, ValueError):
            self.send_json({"error": "Invalid request"}, 400)
            return
        if self.path == "/api/login/setup":
            if login_is_configured():
                self.send_json({"error": "A WatchTower login already exists. Please sign in."}, 409)
                return
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            if len(username) < 3 or len(username) > 64:
                self.send_json({"error": "Username must be between 3 and 64 characters."}, 400)
                return
            if len(password) < 10 or len(password) > 256:
                self.send_json({"error": "Choose a password between 10 and 256 characters."}, 400)
                return
            if password != str(data.get("confirm_password", "")):
                self.send_json({"error": "The passwords do not match."}, 400)
                return
            try:
                create_login(username, password)
                session = create_auth_session(username)
                cookie = f"WatchTowerSession={session}; Max-Age={LOGIN_SESSION_SECONDS}; Path=/; HttpOnly; SameSite=Strict"
                self.send_json({"ok": True}, extra_headers={"Set-Cookie": cookie})
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 409)
            return
        if self.path == "/api/login":
            if not login_is_configured():
                self.send_json({"error": "Set up your local WatchTower login first."}, 409)
                return
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
            authenticated = verify_login(username, password)
            if not authenticated:
                self.send_json({"error": "Username or password is incorrect."}, 401)
                return
            session = create_auth_session(authenticated)
            cookie = f"WatchTowerSession={session}; Max-Age={LOGIN_SESSION_SECONDS}; Path=/; HttpOnly; SameSite=Strict"
            self.send_json({"ok": True}, extra_headers={"Set-Cookie": cookie})
            return
        if self.path == "/api/logout":
            session = self.session_token()
            if not self.authenticated_user():
                self.send_json({"error": "Please sign in first."}, 401)
                return
            if session:
                with AUTH_SESSIONS_LOCK:
                    AUTH_SESSIONS.pop(session, None)
            self.send_json({"ok": True}, extra_headers={
                "Set-Cookie": "WatchTowerSession=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"
            })
            return
        if not self.authenticated_user():
            self.send_json({"error": "Please sign in to access WatchTower"}, 401)
            return
        if self.path == "/api/email-settings":
            try:
                save_email_config(data)
                update_email_status()
                self.send_json({"ok": True, "settings": public_email_settings()})
            except Exception as exc:
                self.send_json({"error": str(exc)[:200]}, 400)
        elif self.path == "/api/browse-path":
            try:
                if data.get("kind") != "file":
                    self.send_json({"error": "Choose a file. Folder monitoring is disabled."}, 400)
                    return
                if platform.system() != "Windows":
                    raise ValueError("File browsing is available on Windows only")
                import tkinter as tk
                from tkinter import filedialog
                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                try:
                    selected = filedialog.askopenfilename(parent=root, title="Choose a file to monitor")
                finally:
                    root.destroy()
                self.send_json({"path": selected or "", "cancelled": not bool(selected)})
            except Exception as exc:
                self.send_json({"error": f"Could not open the file picker: {str(exc)[:160]}"}, 400)
        elif self.path == "/api/app-password":
            current = str(data.get("current_password", ""))
            new_password = str(data.get("new_password", ""))
            if not re.fullmatch(r"[0-9]{4}", new_password):
                self.send_json({"error": "Choose exactly four digits for the app lock password."}, 400)
                return
            with db_session() as db:
                configured = db.execute("SELECT 1 FROM settings WHERE key='app_control_hash'").fetchone() is not None
            if configured and not verify_app_control_password(current):
                self.send_json({"error": "Current app-control password is incorrect."}, 403)
                return
            salt = secrets.token_bytes(16)
            password_hash = hashlib.pbkdf2_hmac("sha256", new_password.encode("utf-8"), salt, LOGIN_PBKDF2_ROUNDS)
            with db_session() as db:
                db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('app_control_salt',?)", (salt.hex(),))
                db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('app_control_hash',?)", (password_hash.hex(),))
            self.send_json({"ok": True})
        elif self.path == "/api/app-policy":
            action = str(data.get("action", "save"))
            exe_name = Path(str(data.get("exe_name", "")).strip()).name.casefold()
            protected = {"explorer.exe", "winlogon.exe", "wininit.exe", "csrss.exe", "services.exe", "svchost.exe", "lsass.exe", "dwm.exe", "system", "python.exe", "pythonw.exe", "watchtower.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "conhost.exe", "taskhostw.exe"}
            if not exe_name.endswith(".exe") or len(exe_name) > 128 or exe_name in protected:
                self.send_json({"error": "Enter an app .exe name. Core Windows and WatchTower processes cannot be restricted."}, 400)
                return
            if action in ("lock", "unlock", "remove", "reset", "clear-limit") and not verify_app_control_password(str(data.get("password", ""))):
                self.send_json({"error": "Enter the four-digit app lock password from Settings."}, 403)
                return
            with db_session() as db:
                today = datetime.now().astimezone().date().isoformat()
                if action == "lock":
                    db.execute("INSERT INTO app_policies(exe_name,locked,time_limit_minutes,updated_at) VALUES(?,1,NULL,?) "
                               "ON CONFLICT(exe_name) DO UPDATE SET locked=1,updated_at=excluded.updated_at", (exe_name, now_text()))
                elif action == "unlock":
                    db.execute("UPDATE app_policies SET locked=0,updated_at=? WHERE exe_name=?", (now_text(), exe_name))
                    db.execute("DELETE FROM app_usage WHERE exe_name=? AND usage_date=?", (exe_name, today))
                elif action == "set-limit":
                    try:
                        limit = int(data.get("time_limit_minutes"))
                    except (TypeError, ValueError):
                        self.send_json({"error": "Choose a time limit in 5-minute increments, from 5 to 240 minutes."}, 400)
                        return
                    if not 5 <= limit <= 240 or limit % 5:
                        self.send_json({"error": "Choose a time limit in 5-minute increments, from 5 to 240 minutes."}, 400)
                        return
                    db.execute("INSERT INTO app_policies(exe_name,locked,time_limit_minutes,updated_at) VALUES(?,0,?,?) "
                               "ON CONFLICT(exe_name) DO UPDATE SET time_limit_minutes=excluded.time_limit_minutes,updated_at=excluded.updated_at",
                               (exe_name, limit, now_text()))
                elif action == "clear-limit":
                    db.execute("UPDATE app_policies SET time_limit_minutes=NULL,updated_at=? WHERE exe_name=?",
                               (now_text(), exe_name))
                elif action == "remove":
                    db.execute("DELETE FROM app_policies WHERE exe_name=?", (exe_name,))
                    db.execute("DELETE FROM app_usage WHERE exe_name=?", (exe_name,))
                elif action == "reset":
                    db.execute("DELETE FROM app_usage WHERE exe_name=? AND usage_date=?", (exe_name, today))
                elif action == "save":
                    raw_limit = data.get("time_limit_minutes")
                    try:
                        limit = int(raw_limit) if raw_limit not in (None, "") else None
                    except (TypeError, ValueError):
                        self.send_json({"error": "Daily limit must be a number of minutes."}, 400)
                        return
                    if limit is not None and not 1 <= limit <= 1440:
                        self.send_json({"error": "Daily limit must be between 1 and 1,440 minutes."}, 400)
                        return
                    locked = 1 if data.get("locked") else 0
                    if not locked and limit is None:
                        self.send_json({"error": "Turn on app lock or set a daily time limit."}, 400)
                        return
                    db.execute("INSERT INTO app_policies(exe_name,locked,time_limit_minutes,updated_at) VALUES(?,?,?,?) "
                               "ON CONFLICT(exe_name) DO UPDATE SET locked=excluded.locked,time_limit_minutes=excluded.time_limit_minutes,updated_at=excluded.updated_at",
                               (exe_name, locked, limit, now_text()))
                else:
                    self.send_json({"error": "Unknown app-rule action."}, 400)
                    return
            self.send_json({"ok": True, "app_controls": app_control_data()})
        elif self.path == "/api/email-test":
            if send_email("Test email", "This is a WatchTower test email. Email alerts are set up and ready to notify you about detected failed sign-ins."):
                self.send_json({"ok": True, "message": "Test email sent. Check your inbox and spam folder."})
            else:
                with STATUS_LOCK:
                    email_status = STATUS.get("email_notifications", "Email sending failed")
                self.send_json({"error": email_status}, 400)
        elif self.path == "/api/events/clear":
            try:
                with db_session() as db:
                    db.execute("DELETE FROM events WHERE category='file'")
                    db.execute("UPDATE file_states SET snapshot_path=NULL WHERE present=0")
                    retained = {str(Path(row[0]).resolve()) for row in
                                db.execute("SELECT snapshot_path FROM file_states WHERE present=1 AND snapshot_path IS NOT NULL")}
                if SNAPSHOT_DIR.exists():
                    for snapshot in SNAPSHOT_DIR.glob("*.snapshot"):
                        if str(snapshot.resolve()) not in retained:
                            try:
                                snapshot.unlink()
                            except OSError:
                                pass
                self.send_json({"ok": True})
            except sqlite3.Error as exc:
                self.send_json({"error": str(exc)}, 500)
        elif self.path == "/api/rollback":
            try:
                event_id = int(data.get("event_id"))
                self.send_json(rollback_file_event(event_id))
            except RollbackConflict as exc:
                self.send_json({"error": str(exc)}, 409)
            except (TypeError, ValueError, OSError, sqlite3.Error) as exc:
                self.send_json({"error": str(exc)}, 400)
        elif self.path == "/api/watches":
            raw_path = str(data.get("path", "")).strip().strip('"')
            try:
                path = Path(raw_path).expanduser().resolve(strict=True)
                if not path.is_file():
                    raise ValueError("Choose an existing file. Folder monitoring is disabled.")
                with db_session() as db:
                    db.execute("INSERT OR IGNORE INTO watches(path) VALUES(?)", (str(path),))
                record_event("file", "Monitoring started", {"path": str(path)})
                self.send_json({"ok": True})
            except (OSError, ValueError, sqlite3.Error) as exc:
                self.send_json({"error": str(exc)}, 400)
        elif self.path == "/api/lock":
            if platform.system() != "Windows":
                self.send_json({"error": "Session locking is available on Windows only"}, 400)
                return
            try:
                if not ctypes.windll.user32.LockWorkStation():
                    raise OSError("Windows did not accept the lock request")
                record_event("action", "Current Windows session locked")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"error": str(exc)}, 500)
        else:
            self.send_json({"error": "Not found"}, 404)


def main() -> None:
    global SESSION_STARTED_AT
    init_db()
    update_email_status()
    # Bind first so a duplicate server launch cannot clear the existing session's records.
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    # Keep a rolling day of user activity across dashboard/server restarts.
    with db_session() as db:
        db.execute("DELETE FROM events WHERE category IN ('authentication','application') AND datetime(created_at) < datetime('now','-1 day')")
        db.execute("DELETE FROM alerts WHERE datetime(created_at) < datetime('now','-1 day')")
        db.execute("DELETE FROM app_usage_samples WHERE datetime(created_at) < datetime('now','-1 day')")
    SESSION_STARTED_AT = now_text()
    record_event("system", "WatchTower started", {"version": "1.0", "database": str(DB_PATH)})
    for target in (windows_event_loop, file_loop, application_loop):
        threading.Thread(target=target, daemon=True).start()
    print(f"WatchTower is running at http://{HOST}:{PORT}")
    print("Keep this window open while monitoring. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set()
        server.server_close()
        record_event("system", "WatchTower stopped")


if __name__ == "__main__":
    if "--reset-login" in sys.argv[1:]:
        init_db()
        reset_login()
        print("WatchTower login credentials cleared. Start WatchTower and create a new username and password in the browser.")
    else:
        main()
