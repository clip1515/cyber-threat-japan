"""SQLite接続とCRUDヘルパー。

このモジュールだけがSQLiteに直接触れる。他のモジュールは必ずここを経由する。
"""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import DB_PATH, SOURCES_YAML

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def connection():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """スキーマを適用し、config/sources.yaml の内容をsourcesテーブルへ同期する。

    schema.sqlの CREATE TABLE IF NOT EXISTS は既存テーブルの列追加までは行わないため、
    以前のバージョンで作成済みのDBに対しては下の migrate 部分で不足列を後付けする。
    (新規列を追加した場合は必ずここにも ALTER TABLE を追加すること)
    """
    with connection() as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _migrate_legacy_schema()
    _sync_sources()


def _migrate_legacy_schema():
    """既存DB(旧バージョン)に不足している列を安全に追加する。列が既にあれば何もしない。"""
    migrations = [
        ("incidents", "last_run_id", "INTEGER"),
        ("status_history", "run_id", "INTEGER"),
        ("incidents", "kev_known_ransomware_use", "TEXT"),
        ("incidents", "kev_due_date", "TEXT"),
        ("incidents", "cvss_version", "TEXT"),
        ("incidents", "cvss_as_of", "TEXT"),
        ("incidents", "cvss_source_id", "TEXT"),
    ]
    with connection() as conn:
        for table, column, coltype in migrations:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e).lower():
                    raise
        # 列が(新規作成/ALTER TABLEどちらの経路でも)存在するようになった後でインデックスを作成する。
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_run_id ON incidents(last_run_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status_history_run_id ON status_history(run_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_kev_change_events_run_id ON kev_change_events(run_id)")


def _sync_sources():
    import yaml
    if not SOURCES_YAML.exists():
        return
    data = yaml.safe_load(SOURCES_YAML.read_text(encoding="utf-8")) or {}
    with connection() as conn:
        for s in data.get("sources", []):
            conn.execute(
                """INSERT INTO sources (id, name, type, url, trust_level, lang, region)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name, type=excluded.type, url=excluded.url,
                     trust_level=excluded.trust_level, lang=excluded.lang, region=excluded.region
                """,
                (s["id"], s["name"], s["type"], s["url"], s["trust_level"],
                 s.get("lang"), s.get("region")),
            )


def find_incident_by_dedup_key(conn, dedup_key):
    row = conn.execute("SELECT * FROM incidents WHERE dedup_key = ?", (dedup_key,)).fetchone()
    return row


def get_incident(conn, incident_id):
    return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()


def list_incidents(conn, limit=1000):
    return conn.execute(
        "SELECT * FROM incidents ORDER BY published_at DESC, id DESC LIMIT ?", (limit,)
    ).fetchall()


def upsert_incident(conn, incident: dict):
    """dedup_key が既存なら信頼度の高い方の内容を優先してマージ、無ければ新規作成。

    incident は database/schema.sql の incidents カラムに対応する dict。
    japan_relevance_reasons はリストで渡して良い(内部でJSON文字列化する)。
    戻り値: (incident_id, is_new: bool)
    """
    reasons = incident.get("japan_relevance_reasons")
    if isinstance(reasons, (list, tuple)):
        incident = {**incident, "japan_relevance_reasons": json.dumps(reasons, ensure_ascii=False)}

    existing = find_incident_by_dedup_key(conn, incident["dedup_key"])
    if existing is None:
        cols = list(incident.keys())
        placeholders = ",".join(["?"] * len(cols))
        conn.execute(
            f"INSERT INTO incidents ({','.join(cols)}) VALUES ({placeholders})",
            [incident[c] for c in cols],
        )
        new_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        return new_id, True
    else:
        # 既存より信頼度の高い(数値が小さい)情報源のみ本文を上書き。
        # それ以外は日本関連スコア・重要度・ステータスなど解析系フィールドのみ更新。
        incoming_trust = incident.get("source_trust_level", 99)
        existing_trust = existing["source_trust_level"] if existing["source_trust_level"] is not None else 99
        overwrite_body = incoming_trust <= existing_trust

        update_fields = {
            "status": incident.get("status", existing["status"]),
            "japan_relevance_score": incident.get("japan_relevance_score", existing["japan_relevance_score"]),
            "japan_relevance_reasons": incident.get("japan_relevance_reasons", existing["japan_relevance_reasons"]),
            "severity": incident.get("severity", existing["severity"]),
            "cve_ids": incident.get("cve_ids") or existing["cve_ids"],
            "cvss": incident.get("cvss") if incident.get("cvss") is not None else existing["cvss"],
            # cvss_version/cvss_as_of/cvss_source_idは、update.py のprocess_item()が
            # cvss本体と同じタイミング・同じ非後退ルールで既に決定した値がここに渡って
            # くる(cvssと必ず一緒に更新されるべきため、本文のtrust_level上書き判定とは
            # 別に、cvssと同じ扱いで常に反映する)。
            "cvss_version": incident.get("cvss_version") if "cvss_version" in incident else (existing["cvss_version"] if "cvss_version" in existing.keys() else None),
            "cvss_as_of": incident.get("cvss_as_of") if "cvss_as_of" in incident else (existing["cvss_as_of"] if "cvss_as_of" in existing.keys() else None),
            "cvss_source_id": incident.get("cvss_source_id") if "cvss_source_id" in incident else (existing["cvss_source_id"] if "cvss_source_id" in existing.keys() else None),
            "in_kev": max(incident.get("in_kev", 0), existing["in_kev"] or 0),
            # kev_known_ransomware_use/kev_due_date/recommended_actionsは、
            # update.py の process_item() 側で既にトラスト・後退防止込みでマージ済みの
            # 値がここに渡ってくる。本文(title等)のような「信頼度の高いソースのみ
            # 上書き」の対象ではなく、severityやin_kev同様、常に反映する。
            "kev_known_ransomware_use": incident.get("kev_known_ransomware_use", existing["kev_known_ransomware_use"] if "kev_known_ransomware_use" in existing.keys() else None),
            "kev_due_date": incident.get("kev_due_date", existing["kev_due_date"] if "kev_due_date" in existing.keys() else None),
            "recommended_actions": incident.get("recommended_actions", existing["recommended_actions"]),
            "last_updated_at": incident.get("last_updated_at", existing["last_updated_at"]),
            "last_run_id": incident.get("last_run_id", existing["last_run_id"] if "last_run_id" in existing.keys() else None),
            "updated_at": "now_placeholder",
        }
        if overwrite_body:
            for f in ["title", "target_org", "sector", "country", "attack_vector", "malware",
                      "threat_actor", "intrusion_vector", "impact",
                      "confirmed_facts", "unconfirmed_info", "analysis_notes",
                      "source_url", "source_name", "source_trust_level", "raw_hash",
                      "published_at", "first_seen_at"]:
                if incident.get(f) is not None:
                    update_fields[f] = incident[f]

        set_clause = ", ".join(f"{k} = ?" for k in update_fields if k != "updated_at")
        set_clause += ", updated_at = datetime('now')"
        values = [v for k, v in update_fields.items() if k != "updated_at"]
        conn.execute(
            f"UPDATE incidents SET {set_clause} WHERE id = ?",
            values + [existing["id"]],
        )
        return existing["id"], False


def add_status_history(conn, incident_id, old_status, new_status, reason, run_id=None):
    conn.execute(
        "INSERT INTO status_history (incident_id, old_status, new_status, reason, run_id) "
        "VALUES (?, ?, ?, ?, ?)",
        (incident_id, old_status, new_status, reason, run_id),
    )


def get_incidents_by_run(conn, run_id):
    """指定した run_id で新規作成/更新された(触れられた)incidentsを返す。daily_report用。"""
    return conn.execute(
        "SELECT * FROM incidents WHERE last_run_id = ? "
        "ORDER BY japan_relevance_score DESC, id DESC",
        (run_id,),
    ).fetchall()


def get_status_transitions_by_run(conn, run_id, new_status: str = None):
    """指定した run_id で発生したステータス遷移を返す(new_statusで絞り込み可)。daily_report用。"""
    if new_status:
        return conn.execute(
            "SELECT sh.*, i.title, i.severity, i.japan_relevance_score, i.source_url, i.source_name "
            "FROM status_history sh JOIN incidents i ON i.id = sh.incident_id "
            "WHERE sh.run_id = ? AND sh.new_status = ? ORDER BY i.japan_relevance_score DESC",
            (run_id, new_status),
        ).fetchall()
    return conn.execute(
        "SELECT sh.*, i.title, i.severity, i.japan_relevance_score, i.source_url, i.source_name "
        "FROM status_history sh JOIN incidents i ON i.id = sh.incident_id "
        "WHERE sh.run_id = ? ORDER BY i.japan_relevance_score DESC",
        (run_id,),
    ).fetchall()


def upsert_iocs(conn, incident_id, iocs: list, source_url: str):
    for ioc_type, ioc_value in iocs:
        conn.execute(
            """INSERT INTO iocs (incident_id, ioc_type, ioc_value, source_url)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(incident_id, ioc_type, ioc_value) DO NOTHING""",
            (incident_id, ioc_type, ioc_value, source_url),
        )


def upsert_cve(conn, cve_id, cvss=None, epss=None, in_kev=None, kev_date_added=None, description=None):
    conn.execute(
        """INSERT INTO cves (cve_id, cvss, epss, in_kev, kev_date_added, description)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(cve_id) DO UPDATE SET
             cvss=COALESCE(excluded.cvss, cves.cvss),
             epss=COALESCE(excluded.epss, cves.epss),
             in_kev=MAX(excluded.in_kev, cves.in_kev),
             kev_date_added=COALESCE(excluded.kev_date_added, cves.kev_date_added),
             description=COALESCE(excluded.description, cves.description),
             last_checked_at=datetime('now')
        """,
        (cve_id, cvss, epss, in_kev or 0, kev_date_added, description),
    )


def add_kev_change_event(conn, incident_id, run_id, change_type, old_value, new_value):
    """「touchedになった」だけでなく「実際に値が変わった」ことを記録する。
    reporting/daily_report.py の significant_change 判定の主たる根拠になる。
    """
    conn.execute(
        "INSERT INTO kev_change_events (incident_id, run_id, change_type, old_value, new_value) "
        "VALUES (?, ?, ?, ?, ?)",
        (incident_id, run_id, change_type, old_value, new_value),
    )


def get_kev_change_events_by_run(conn, run_id):
    return conn.execute(
        "SELECT e.*, i.title, i.severity, i.japan_relevance_score, i.source_url, i.source_name, i.cve_ids "
        "FROM kev_change_events e JOIN incidents i ON i.id = e.incident_id "
        "WHERE e.run_id = ? ORDER BY e.id",
        (run_id,),
    ).fetchall()


def record_source_health(conn, source_id, success: bool, item_count: int = 0,
                          error_type: str = None, error_message: str = None, http_status: int = None):
    """ソースごとの取得成否を記録する(GitHub Actionsのログに依存しない診断台帳)。

    update.py の実行後、この内容を data/collector_health.json としても書き出し、
    リポジトリから直接「どのソースが・いつから・どういう理由で」失敗しているかを
    確認できるようにする(2026-10監査: 実行ログへのアクセスが無い状態で原因特定
    できなかったため、その再発防止)。
    """
    row = conn.execute("SELECT * FROM source_health WHERE source_id = ?", (source_id,)).fetchone()
    consecutive_failures = 0 if success else ((row["consecutive_failures"] if row else 0) + 1)
    success_flag = 1 if success else 0
    conn.execute(
        """INSERT INTO source_health
               (source_id, last_attempt_at, last_success_at, last_item_count,
                last_error_type, last_error_message, last_http_status, consecutive_failures)
           VALUES (?, datetime('now'), CASE WHEN ? THEN datetime('now') ELSE NULL END, ?, ?, ?, ?, ?)
           ON CONFLICT(source_id) DO UPDATE SET
               last_attempt_at = excluded.last_attempt_at,
               last_success_at = CASE WHEN ? THEN excluded.last_attempt_at
                                       ELSE source_health.last_success_at END,
               last_item_count = excluded.last_item_count,
               last_error_type = excluded.last_error_type,
               last_error_message = excluded.last_error_message,
               last_http_status = excluded.last_http_status,
               consecutive_failures = excluded.consecutive_failures
        """,
        (
            source_id, success_flag, item_count,
            None if success else error_type,
            None if success else error_message,
            None if success else http_status,
            consecutive_failures,
            success_flag,
        ),
    )


def get_all_source_health(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM source_health ORDER BY source_id").fetchall()]


def start_run(conn):
    conn.execute("INSERT INTO run_log (started_at) VALUES (datetime('now'))")
    return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]


def finish_run(conn, run_id, sources_ok, sources_failed, items_fetched, items_new, items_updated, notes=""):
    conn.execute(
        """UPDATE run_log SET finished_at=datetime('now'), sources_ok=?, sources_failed=?,
           items_fetched=?, items_new=?, items_updated=?, notes=? WHERE id=?""",
        (sources_ok, sources_failed, items_fetched, items_new, items_updated, notes, run_id),
    )