# storage/database.py
"""
Storage layer: SQLite database for normalized security events.

Design decisions:
- Single denormalized events table for cross-event-type correlation
- Indexes on timestamp, event_id, target_user, source_ip for dashboard query performance
- Duplicate prevention via UNIQUE constraint on (timestamp, event_id, computer)
- Raw XML preserved for forensic audit trail
"""

import sqlite3
import os
import sys
from datetime import datetime
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_PATH


def get_connection() -> sqlite3.Connection:
    """
    Return a database connection with row_factory set so rows
    behave like dictionaries — e.g. row['event_id'] instead of row[0].
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode: allows reads during writes (important for dashboard
    # reading while collector is writing)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def initialize_database() -> None:
    """
    Create the events table and indexes if they do not exist.
    Safe to call on every startup — CREATE IF NOT EXISTS is idempotent.
    """
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id        INTEGER NOT NULL,
                event_name      TEXT,
                timestamp       TEXT,
                hour_of_day     INTEGER,
                day_of_week     TEXT,
                computer        TEXT,
                subject_user    TEXT,
                target_user     TEXT,
                logon_type      INTEGER,
                logon_type_desc TEXT,
                failure_reason  TEXT,
                substatus       TEXT,
                substatus_desc  TEXT,
                source_ip       TEXT,
                process_name    TEXT,
                command_line    TEXT,
                group_name      TEXT,
                raw_xml         TEXT,
                inserted_at     TEXT DEFAULT (datetime('now')),
                UNIQUE(timestamp, event_id, computer)
            )
        """)

        # Indexes: these are what make dashboard queries fast
        # Without indexes, every query does a full table scan
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_timestamp   ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_event_id    ON events(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_target_user ON events(target_user)",
            "CREATE INDEX IF NOT EXISTS idx_source_ip   ON events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_hour        ON events(hour_of_day)",
        ]
        for idx in indexes:
            conn.execute(idx)

        conn.commit()
        print("[+] Database initialized successfully")
    finally:
        conn.close()


def insert_events(events: list) -> dict:
    """
    Insert a list of normalized event dicts into the database.
    Skips duplicates silently via INSERT OR IGNORE.

    Returns a summary dict with inserted and skipped counts.
    """
    if not events:
        return {"inserted": 0, "skipped": 0}

    conn = get_connection()
    inserted = 0
    skipped  = 0

    try:
        for event in events:
            # Convert timestamp to ISO string for SQLite storage
            ts = event.get("timestamp")
            ts_str = ts.isoformat() if isinstance(ts, datetime) else str(ts) if ts else None

            try:
                conn.execute("""
                    INSERT OR IGNORE INTO events (
                        event_id, event_name, timestamp, hour_of_day,
                        day_of_week, computer, subject_user, target_user,
                        logon_type, logon_type_desc, failure_reason,
                        substatus, substatus_desc, source_ip,
                        process_name, command_line, group_name, raw_xml
                    ) VALUES (
                        :event_id, :event_name, :timestamp, :hour_of_day,
                        :day_of_week, :computer, :subject_user, :target_user,
                        :logon_type, :logon_type_desc, :failure_reason,
                        :substatus, :substatus_desc, :source_ip,
                        :process_name, :command_line, :group_name, :raw_xml
                    )
                """, {**event, "timestamp": ts_str})

                if conn.execute("SELECT changes()").fetchone()[0] > 0:
                    inserted += 1
                else:
                    skipped += 1

            except Exception as e:
                print(f"[!] Insert error for event {event.get('event_id')}: {e}")
                skipped += 1

        conn.commit()

    finally:
        conn.close()

    return {"inserted": inserted, "skipped": skipped}


def query_events(
    event_ids: list = None,
    user: str = None,
    hours_back: int = 24,
    limit: int = 1000
) -> list:
    """
    Flexible query function for the dashboard.
    All filters are optional — omit any to skip that filter.

    Returns list of sqlite3.Row objects (accessible as dicts).
    """
    conn = get_connection()
    try:
        conditions = ["timestamp >= datetime('now', ?)"]
        params     = [f"-{hours_back} hours"]

        if event_ids:
            placeholders = ",".join("?" * len(event_ids))
            conditions.append(f"event_id IN ({placeholders})")
            params.extend(event_ids)

        if user:
            conditions.append("(target_user = ? OR subject_user = ?)")
            params.extend([user, user])

        where = " AND ".join(conditions)
        sql   = f"""
            SELECT * FROM events
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return rows
    finally:
        conn.close()


def get_event_counts(hours_back: int = 24) -> list:
    """
    Returns event counts grouped by event_id for the dashboard
    overview panel.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT event_id, event_name, COUNT(*) as count
            FROM events
            WHERE timestamp >= datetime('now', ?)
            GROUP BY event_id, event_name
            ORDER BY count DESC
        """, (f"-{hours_back} hours",)).fetchall()
        return rows
    finally:
        conn.close()


def get_failed_logon_summary(hours_back: int = 24) -> list:
    """
    Returns failed logon counts grouped by target_user and source_ip.
    Core query for brute-force detection panel.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT
                target_user,
                source_ip,
                substatus_desc,
                COUNT(*) as attempt_count,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE event_id = 4625
              AND timestamp >= datetime('now', ?)
            GROUP BY target_user, source_ip
            ORDER BY attempt_count DESC
        """, (f"-{hours_back} hours",)).fetchall()
        return rows
    finally:
        conn.close()


def get_database_stats() -> dict:
    """
    Returns summary stats about the database — useful for
    dashboard header and README documentation.
    """
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        oldest = conn.execute(
            "SELECT MIN(timestamp) FROM events"
        ).fetchone()[0]
        newest = conn.execute(
            "SELECT MAX(timestamp) FROM events"
        ).fetchone()[0]
        by_id = conn.execute("""
            SELECT event_id, event_name, COUNT(*) as count
            FROM events GROUP BY event_id
            ORDER BY count DESC
        """).fetchall()

        return {
            "total_events": total,
            "oldest_event": oldest,
            "newest_event": newest,
            "by_event_id":  [dict(r) for r in by_id]
        }
    finally:
        conn.close()
