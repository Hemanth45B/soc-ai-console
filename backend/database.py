"""
SQLite database layer for SOC AI Console.

Uses an FTS5 external-content virtual table for full-text log search,
kept in sync with the `logs` table via triggers.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DATABASE_PATH = os.environ.get("DATABASE_PATH", "./soc_console.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    host TEXT,
    log_type TEXT,
    raw_log TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
    raw_log,
    host,
    source_ip,
    log_type,
    content='logs',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts(rowid, raw_log, host, source_ip, log_type)
    VALUES (new.id, new.raw_log, new.host, new.source_ip, new.log_type);
END;

CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, raw_log, host, source_ip, log_type)
    VALUES ('delete', old.id, old.raw_log, old.host, old.source_ip, old.log_type);
END;

CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, raw_log, host, source_ip, log_type)
    VALUES ('delete', old.id, old.raw_log, old.host, old.source_ip, old.log_type);
    INSERT INTO logs_fts(rowid, raw_log, host, source_ip, log_type)
    VALUES (new.id, new.raw_log, new.host, new.source_ip, new.log_type);
END;

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'low',       -- low | medium | high | critical
    status TEXT NOT NULL DEFAULT 'new',          -- new | triaged_auto | pending_human_review | escalated | resolved | false_positive
    rule_name TEXT,
    related_log_ids TEXT,                        -- JSON list of log ids
    ai_verdict TEXT,
    ai_confidence INTEGER,
    ai_reasoning TEXT,
    ai_recommended_action TEXT,
    ai_iocs TEXT,                                 -- JSON list
    requires_human_approval INTEGER NOT NULL DEFAULT 0,
    human_decision TEXT,                          -- approved | overridden | null
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def insert_log(conn, timestamp, source_ip, host, log_type, raw_log) -> int:
    cur = conn.execute(
        "INSERT INTO logs (timestamp, source_ip, host, log_type, raw_log, ingested_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, source_ip, host, log_type, raw_log, now_iso()),
    )
    return cur.lastrowid


def search_logs(conn, query: str, limit: int = 50):
    rows = conn.execute(
        """
        SELECT logs.id, logs.timestamp, logs.source_ip, logs.host, logs.log_type, logs.raw_log
        FROM logs_fts
        JOIN logs ON logs.id = logs_fts.rowid
        WHERE logs_fts MATCH ?
        ORDER BY logs.timestamp DESC
        LIMIT ?
        """,
        (query, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def recent_logs(conn, limit: int = 50):
    rows = conn.execute(
        "SELECT id, timestamp, source_ip, host, log_type, raw_log FROM logs "
        "ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def insert_alert(conn, title, description, severity, rule_name, related_log_ids) -> int:
    ts = now_iso()
    cur = conn.execute(
        """
        INSERT INTO alerts (title, description, severity, status, rule_name,
                             related_log_ids, created_at, updated_at)
        VALUES (?, ?, ?, 'new', ?, ?, ?, ?)
        """,
        (title, description, severity, rule_name, json.dumps(related_log_ids), ts, ts),
    )
    return cur.lastrowid


def list_alerts(conn, status: str = None, severity: str = None):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_alert(conn, alert_id: int):
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def get_logs_by_ids(conn, log_ids):
    if not log_ids:
        return []
    placeholders = ",".join("?" * len(log_ids))
    rows = conn.execute(
        f"SELECT * FROM logs WHERE id IN ({placeholders})", log_ids
    ).fetchall()
    return [dict(r) for r in rows]


def update_alert_triage(conn, alert_id, verdict, confidence, reasoning,
                         recommended_action, iocs, requires_human_approval, status):
    conn.execute(
        """
        UPDATE alerts
        SET ai_verdict = ?, ai_confidence = ?, ai_reasoning = ?,
            ai_recommended_action = ?, ai_iocs = ?, requires_human_approval = ?,
            status = ?, updated_at = ?
        WHERE id = ?
        """,
        (verdict, confidence, reasoning, recommended_action, json.dumps(iocs),
         int(requires_human_approval), status, now_iso(), alert_id),
    )


def update_alert_human_decision(conn, alert_id, decision, status):
    conn.execute(
        "UPDATE alerts SET human_decision = ?, status = ?, updated_at = ? WHERE id = ?",
        (decision, status, now_iso(), alert_id),
    )
