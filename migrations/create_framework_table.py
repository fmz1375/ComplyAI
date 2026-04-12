import sqlite3
from datetime import datetime

DB_PATH = "project.db"


def _ensure_column(cur, table: str, column: str, ddl_type: str):
    cur.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cur.fetchall()}
    if column not in existing:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")


def run():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Create single-row framework_config table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS framework_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        name TEXT,
        version TEXT,
        description TEXT,
        embedding_model TEXT,
        vector_store_path TEXT,
        last_updated_at TEXT,
        status TEXT DEFAULT 'ready',
        updated_by TEXT
    )
    """)

    # Ensure current schema has framework identifiers used for audit/version pinning
    _ensure_column(cur, "framework_config", "version_id", "TEXT")

    # Ensure there is always exactly one row (if none, insert an empty ready row)
    cur.execute("SELECT COUNT(1) FROM framework_config")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO framework_config (id, status, last_updated_at, version_id) VALUES (1, 'ready', ?, ?)",
            (datetime.utcnow().isoformat(), "default"),
        )
    else:
        cur.execute("UPDATE framework_config SET version_id = COALESCE(version_id, version, 'default') WHERE id = 1")

    # Store all ingested framework versions (active + historical)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS framework_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id TEXT UNIQUE NOT NULL,
        framework_name TEXT NOT NULL,
        version_label TEXT NOT NULL,
        description TEXT,
        embedding_model TEXT,
        vector_store_path TEXT NOT NULL,
        created_at TEXT NOT NULL,
        created_by TEXT,
        source_type TEXT,
        source_ref TEXT,
        chunk_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'ready',
        is_active INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_framework_versions_version_id
    ON framework_versions(version_id)
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_framework_versions_active
    ON framework_versions(is_active)
    """)

    # Backfill framework_versions from current config if possible
    cur.execute("SELECT * FROM framework_config WHERE id = 1")
    cfg = cur.fetchone()
    if cfg:
        cols = [d[0] for d in cur.description]
        cfg_map = dict(zip(cols, cfg))
        cfg_version_id = cfg_map.get("version_id") or "default"
        cfg_name = cfg_map.get("name") or "NIST CSF"
        cfg_version = cfg_map.get("version") or "unknown"
        cfg_path = cfg_map.get("vector_store_path")
        if cfg_path:
            cur.execute("SELECT COUNT(1) FROM framework_versions WHERE version_id = ?", (cfg_version_id,))
            if cur.fetchone()[0] == 0:
                cur.execute(
                    """
                    INSERT INTO framework_versions (
                        version_id, framework_name, version_label, description, embedding_model,
                        vector_store_path, created_at, created_by, source_type, source_ref,
                        chunk_count, status, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cfg_version_id,
                        cfg_name,
                        cfg_version,
                        cfg_map.get("description"),
                        cfg_map.get("embedding_model"),
                        cfg_path,
                        cfg_map.get("last_updated_at") or datetime.utcnow().isoformat(),
                        cfg_map.get("updated_by"),
                        "legacy",
                        None,
                        0,
                        cfg_map.get("status") or "ready",
                        1,
                    ),
                )

    # Ensure report table has framework audit stamp columns
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='report'")
    if cur.fetchone():
        _ensure_column(cur, "report", "framework_name", "TEXT")
        _ensure_column(cur, "report", "framework_version_id", "TEXT")
        _ensure_column(cur, "report", "framework_version_label", "TEXT")
        _ensure_column(cur, "report", "framework_used_at", "TEXT")

    # Audit log table for rebuilds
    cur.execute("""
    CREATE TABLE IF NOT EXISTS framework_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        message TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        performed_by TEXT
    )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    run()
