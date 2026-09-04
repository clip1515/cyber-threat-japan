"""旧スキーマ(last_run_id/run_id列が無いDB)からのマイグレーションを検証する。"""
import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from database import db as dbmod

# これは本プロジェクトの初回リリース時点(last_run_id/run_id列を追加する前)の
# schema.sqlをそのまま再現したもの。「既にこのバージョンで運用していたユーザーのDB」を
# 模擬するためのフィクスチャであり、意図的にテスト内に固定している。
LEGACY_SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    url             TEXT NOT NULL,
    trust_level     INTEGER NOT NULL,
    lang            TEXT,
    region          TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key               TEXT UNIQUE,
    title                   TEXT NOT NULL,
    first_seen_at           TEXT,
    published_at            TEXT,
    last_updated_at         TEXT,
    target_org              TEXT,
    sector                  TEXT,
    country                 TEXT,
    attack_vector           TEXT,
    cve_ids                 TEXT,
    cvss                    REAL,
    in_kev                  INTEGER DEFAULT 0,
    epss                    REAL,
    malware                 TEXT,
    threat_actor            TEXT,
    intrusion_vector        TEXT,
    impact                  TEXT,
    japan_relevance_score   INTEGER DEFAULT 0,
    japan_relevance_reasons TEXT,
    severity                TEXT,
    status                  TEXT DEFAULT 'NEW',
    recommended_actions     TEXT,
    confirmed_facts         TEXT,
    unconfirmed_info        TEXT,
    analysis_notes          TEXT,
    source_url              TEXT,
    source_name             TEXT,
    source_trust_level      INTEGER,
    raw_hash                TEXT,
    created_at              TEXT DEFAULT (datetime('now')),
    updated_at              TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_published_at ON incidents(published_at);
CREATE INDEX IF NOT EXISTS idx_incidents_japan_score ON incidents(japan_relevance_score);

CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_type        TEXT NOT NULL,
    ioc_value       TEXT NOT NULL,
    source_url      TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(incident_id, ioc_type, ioc_value)
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    cvss            REAL,
    epss            REAL,
    in_kev          INTEGER DEFAULT 0,
    kev_date_added  TEXT,
    description     TEXT,
    last_checked_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS status_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    old_status      TEXT,
    new_status      TEXT NOT NULL,
    reason          TEXT,
    changed_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS run_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT DEFAULT (datetime('now')),
    finished_at     TEXT,
    sources_ok      INTEGER DEFAULT 0,
    sources_failed  INTEGER DEFAULT 0,
    items_fetched   INTEGER DEFAULT 0,
    items_new       INTEGER DEFAULT 0,
    items_updated   INTEGER DEFAULT 0,
    notes           TEXT
);
"""


class TestDbMigration(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_db_path = Path(self._tmpdir.name) / "legacy.db"
        # 旧バージョン相当のDB(last_run_id/run_id列なし)を作っておく
        conn = sqlite3.connect(str(self.tmp_db_path))
        conn.executescript(LEGACY_SCHEMA_SQL)
        conn.commit()
        conn.close()
        dbmod.DB_PATH = self.tmp_db_path

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_init_db_adds_missing_columns_without_error(self):
        dbmod.init_db()  # 例外が出ないこと自体が主な検証ポイント
        with dbmod.connection() as conn:
            incident_cols = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)")}
            history_cols = {row["name"] for row in conn.execute("PRAGMA table_info(status_history)")}
        self.assertIn("last_run_id", incident_cols)
        self.assertIn("run_id", history_cols)

    def test_running_init_db_twice_is_idempotent(self):
        dbmod.init_db()
        dbmod.init_db()  # 2回目も列重複エラーにならないこと
        with dbmod.connection() as conn:
            incident_cols = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)")}
        self.assertIn("last_run_id", incident_cols)

    def test_existing_data_survives_migration(self):
        with dbmod.connection() as conn:
            conn.execute(
                "INSERT INTO incidents (dedup_key, title, status) VALUES (?, ?, ?)",
                ("legacy-key-1", "既存の事案", "ACTIVE"),
            )
        dbmod.init_db()
        with dbmod.connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE dedup_key = ?", ("legacy-key-1",)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["title"], "既存の事案")
        self.assertIsNone(row["last_run_id"])  # 新列はNULLで補完される


if __name__ == "__main__":
    unittest.main()