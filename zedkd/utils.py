import json
import os
import sqlite3
from datetime import datetime
from typing import Any

from .paths import AUDIT_LOG_PATH, DB_PATH, SEQ_PATH, ensure_storage

__all__ = [
    "now_iso",
    "safe_load_data",
    "safe_save_data",
    "log_event",
    "load_audit_events",
    "list_users",
    "add_user",
    "user_has_keys",
    "calc_doc_hash_bytes",
    "calc_file_hash",
    "next_seq",
    "relpath_in_storage",
]


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _ensure_db() -> None:
    """Create the SQLite database and required tables if they do not exist."""

    ensure_storage()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                doc_id TEXT,
                extra TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sequences (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def safe_load_data(key: str, default: Any):
    """Read JSON-serializable data from the kv_store bucket in SQLite."""

    _ensure_db()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT data FROM kv_store WHERE key = ?", (key,)).fetchone()
            return json.loads(row[0]) if row else default
    except Exception:
        return default


def safe_save_data(key: str, obj: Any) -> None:
    """Persist JSON-serializable data into SQLite."""

    _ensure_db()
    payload = json.dumps(obj, ensure_ascii=False)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO kv_store(key, data) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET data = excluded.data",
            (key, payload),
        )


def list_users() -> list[dict]:
    """Return all registered users ordered by name."""

    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, username, created_at FROM users ORDER BY username"
        ).fetchall()
    return [
        {
            "id": row[0],
            "username": row[1],
            "created_at": row[2],
            "has_keys": user_has_keys(row[1]),
        }
        for row in rows
    ]


def add_user(username: str) -> dict:
    """Create a new user if it does not already exist."""

    clean_name = (username or "").strip()
    if not clean_name:
        raise ValueError("Имя пользователя не может быть пустым")

    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        exists = conn.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (clean_name,),
        ).fetchone()
        if exists:
            raise ValueError("Такой пользователь уже существует")

        created_at = now_iso()
        cur = conn.execute(
            "INSERT INTO users(username, created_at) VALUES(?, ?)",
            (clean_name, created_at),
        )
        user_id = cur.lastrowid

    return {"id": user_id, "username": clean_name, "created_at": created_at}


def log_event(user: str, action: str, result: str, doc_id: str | None = None, extra: dict | None = None) -> None:
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_log(timestamp, user, action, result, doc_id, extra)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso(),
                user,
                action,
                result,
                doc_id,
                json.dumps(extra or {}, ensure_ascii=False),
            ),
        )


def calc_doc_hash_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def calc_file_hash(path: str) -> str:
    with open(path, "rb") as f:
        return calc_doc_hash_bytes(f.read())


def next_seq(key: str) -> int:
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT value FROM sequences WHERE key = ?", (key,)).fetchone()
        val = (row[0] if row else 0) + 1
        conn.execute(
            "INSERT INTO sequences(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, val),
        )
        return val


def load_audit_events(limit: int | None = None) -> list[dict]:
    """Retrieve audit events ordered by insertion."""

    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        sql = "SELECT timestamp, user, action, result, doc_id, extra FROM audit_log ORDER BY id"
        if limit:
            sql += " LIMIT ?"
            rows = conn.execute(sql, (limit,)).fetchall()
        else:
            rows = conn.execute(sql).fetchall()

    events = []
    for ts, user, action, result, doc_id, extra in rows:
        try:
            extra_data = json.loads(extra) if extra else {}
        except Exception:
            extra_data = {}
        events.append(
            {
                "timestamp": ts,
                "user": user,
                "action": action,
                "result": result,
                "doc_id": doc_id,
                "extra": extra_data,
            }
        )
    return events


def relpath_in_storage(abs_path: str) -> str:
    from .paths import STORAGE_DIR

    try:
        return os.path.relpath(abs_path, STORAGE_DIR)
    except Exception:
        return abs_path


def user_has_keys(username: str) -> bool:
    """Check whether a keypair exists for the given user."""

    key_data = safe_load_data(f"keys:{username}", None)
    return bool(key_data and key_data.get("private_key") and key_data.get("public_key"))
