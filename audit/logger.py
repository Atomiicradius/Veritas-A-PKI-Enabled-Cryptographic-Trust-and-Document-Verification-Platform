import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "audit.db")

# New columns added in v2 – added via safe ALTER TABLE migrations
_V2_COLUMNS = [
    ("certificate_id",     "TEXT"),
    ("certificate_status", "TEXT"),
    ("timestamp_status",   "TEXT"),
    ("merkle_root",        "TEXT"),
]


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate_v2(conn) -> None:
    """Idempotently add v2 columns to audit_log if they are not yet present."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
    for col_name, col_type in _V2_COLUMNS:
        if col_name not in existing:
            conn.execute(
                f"ALTER TABLE audit_log ADD COLUMN {col_name} {col_type}"
            )
    conn.commit()


def init_db():
    """Initialise the database schema and run any pending migrations."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            operation TEXT,
            filename TEXT,
            file_hash TEXT,
            signer TEXT,
            key_size INTEGER,
            result TEXT,
            notes TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    _migrate_v2(conn)
    conn.close()


def log_operation(
    operation: str,
    filename: str,
    file_hash: str,
    signer: str,
    key_size: int,
    result: str,
    notes: str = "",
    *,
    certificate_id: str = "",
    certificate_status: str = "",
    timestamp_status: str = "",
    merkle_root: str = "",
) -> None:
    """
    Insert one audit record.

    Original positional parameters are unchanged for backward compatibility.
    New v2 fields are keyword-only with empty-string defaults so old callers
    continue to work without modification.
    """
    conn = _get_conn()
    conn.execute(
        """INSERT INTO audit_log
           (timestamp, operation, filename, file_hash, signer, key_size,
            result, notes,
            certificate_id, certificate_status, timestamp_status, merkle_root)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.utcnow().isoformat(), operation, filename,
            file_hash, signer, key_size, result, notes,
            certificate_id, certificate_status, timestamp_status, merkle_root,
        ),
    )
    conn.commit()
    conn.close()


def get_all_logs(limit: int = 200) -> list:
    """Return the most-recent *limit* audit records, newest first."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_logs() -> int:
    """Delete ALL rows from audit_log. Preserves the table schema.

    Returns the number of records deleted.
    Equivalent to: DELETE FROM audit_log (not DROP TABLE).
    """
    conn = _get_conn()
    cursor = conn.execute("DELETE FROM audit_log")
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def create_user(username, password) -> bool:
    """Create a new user. Returns True if successful, False if username already exists."""
    conn = _get_conn()
    try:
        pw_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, pw_hash, datetime.utcnow().isoformat())
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_username(username) -> dict:
    """Retrieve user details by username."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def check_user_password(username, password) -> dict:
    """Verify credentials. Returns user dict if valid, else None."""
    user = get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None
