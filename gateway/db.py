"""SQLite schema and connection helpers shared by the gateway and dashboard.

A single database file holds three tables:
  events     - one row per DNS request (the forensic log, Section 5.1)
  blacklist  - known malicious / unwanted domains (Section 4.4)
  meta       - small key/value store (gateway heartbeat, blacklist version)
"""

import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,  -- request ID
    ts           REAL    NOT NULL,                   -- unix timestamp
    client       TEXT    NOT NULL,                   -- requesting client IP
    domain       TEXT    NOT NULL,                   -- domain requested
    qtype        TEXT    NOT NULL,                   -- record type (A, AAAA, TXT ...)
    verdict      TEXT    NOT NULL,                   -- allowed | blocked | suspicious
    reason       TEXT,                               -- block / alert reason (nullable)
    attack_type  TEXT,                               -- detected attack type (nullable)
    score        REAL    NOT NULL DEFAULT 0,         -- composite heuristic score 0..1
    rcode        TEXT,                               -- response code returned to client
    answer       TEXT,                               -- short answer summary
    latency_ms   REAL                                -- time spent in the gateway
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict, ts);
CREATE INDEX IF NOT EXISTS idx_events_domain  ON events(domain);

CREATE TABLE IF NOT EXISTS blacklist (
    domain    TEXT PRIMARY KEY,                      -- indexed by the primary key
    source    TEXT NOT NULL DEFAULT 'manual',
    category  TEXT NOT NULL DEFAULT 'malicious',
    added_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT
);
"""


def connect(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL lets the dashboard read while the gateway writes.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(path):
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def set_meta(conn, key, value):
    conn.execute("INSERT INTO meta(key, value) VALUES(?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    conn.commit()


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def bump_blacklist_version(conn):
    """Signal to the running gateway that the blacklist changed."""
    set_meta(conn, "blacklist_version", repr(time.time()))
