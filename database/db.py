"""SQLite接続とCRUDヘルパー。

このモジュールだけがSQLiteに直接触れる。他のモジュールは必ずここを経由する。
"""
import json
import logging
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import DB_PATH, REPORTED_IOCS_YAML, SOURCES_YAML
from analyzers.severity import determine_severity, order_rank

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
    _sync_reported_iocs()


def _migrate_legacy_schema():
    """既存DB(旧バージョン)に不足している列を安全に追加する。列が既にあれば何もしない。"""
    migrations = [
        ("incidents", "last_run_id", "INTEGER"),
        ("incidents", "source_updated_at", "TEXT"),
        ("status_history", "run_id", "INTEGER"),
        ("cves", "kev_first_seen_run_id", "INTEGER"),
    ]
    with connection() as conn:
        conn.execute("BEGIN")
        for table, column, coltype in migrations:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e).lower():
                    raise
        # 列が(新規作成/ALTER TABLEどちらの経路でも)存在するようになった後でインデックスを作成する。
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_run_id ON incidents(last_run_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status_history_run_id ON status_history(run_id)")
        # Add aliases without deleting/merging legacy duplicate records.
        conn.execute(
            "INSERT OR IGNORE INTO incident_urls (source_url, incident_id) "
            "SELECT source_url, MIN(id) FROM incidents "
            "WHERE source_url IS NOT NULL AND source_url <> '' GROUP BY source_url"
        )


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


def _sync_reported_iocs():
    """config/reported_iocs.yaml の内容を reported_iocs に反映する(ファイルを正とする)。

    ファイル全体を検証してから、1つのトランザクションで反映する(既存の行は ID を保ったまま更新し、
    ファイルから消えた行だけを削除する)。ファイルの欠落・読み取り失敗・不正・DB書き込み失敗のときは
    既存の行を一切変更せず、収集処理も止めない。その代わり _warn_reported_iocs で警告する。
    """
    try:
        problem = _apply_reported_iocs()
    except Exception as e:  # noqa: BLE001  IOC同期の不具合で日次収集を止めない最後の防衛線
        problem = f"予期しないエラーが発生しました({type(e).__name__})"
    if problem:
        _warn_reported_iocs(problem + "。前回の内容を維持しました")


def _apply_reported_iocs():
    """反映できれば None、できなければ理由を返す。"""
    import yaml
    from parsers.reported_ioc import DuplicateKeyError, load_document, parse_document
    if not REPORTED_IOCS_YAML.exists():
        return "config/reported_iocs.yaml がありません"
    try:
        text = REPORTED_IOCS_YAML.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return f"config/reported_iocs.yaml を読めません({type(e).__name__})"
    try:
        data = load_document(text)
    except DuplicateKeyError as e:  # 重複キーを黙って後の値で上書きすると、既存の登録が消えることがある
        return f"config/reported_iocs.yaml に{e}"
    except yaml.YAMLError:
        return "config/reported_iocs.yaml がYAMLとして読めません"
    rows, errors = parse_document(data)
    if errors:
        more = f" ほか{len(errors) - 5}件" if len(errors) > 5 else ""
        return "config/reported_iocs.yaml に不正な項目があります: " + "; ".join(errors[:5]) + more
    try:
        _replace_reported_iocs(rows)
    except sqlite3.Error as e:  # 書き込みはトランザクションごと取り消される
        return f"reported_iocs への反映に失敗しました({type(e).__name__})"
    return None


def _one_line(text, limit=1000):
    """ログ・警告注釈に出す文字列から改行・制御文字を取り除く(ワークフローコマンドの偽装を防ぐ)。"""
    return re.sub(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]", lambda m: f"\\x{ord(m.group()):02x}", str(text))[:limit]


def _warn_reported_iocs(message):
    """ログに残し、GitHub Actions 上では実行結果のページに警告注釈として表示する。"""
    safe = _one_line(message)
    logging.getLogger("db").error("IOC同期失敗: %s", safe)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # 改行は _one_line で除いてある。メッセージ部分で特別な意味を持つ残りの文字は % だけ。
        print(f"::warning title=IOC同期失敗 (reported_iocs)::{safe.replace('%', '%25')}", flush=True)


REPORTED_IOC_KEY = ("ioc_type", "ioc_value", "source_url")
REPORTED_IOC_COLUMNS = ("ioc_type", "ioc_value", "source_url", "source_name", "source_kind", "source_trust_level",
                        "source_published_at", "observed_from", "observed_to", "source_checked_at", "confidence",
                        "usage", "context")


def _replace_reported_iocs(rows):
    """1つのトランザクションで反映する。同じ (ioc_type, ioc_value, source_url) の行は ID を保って更新する。"""
    columns = ", ".join(REPORTED_IOC_COLUMNS)
    values = ", ".join(f":{c}" for c in REPORTED_IOC_COLUMNS)
    updates = ", ".join(f"{c}=excluded.{c}" for c in REPORTED_IOC_COLUMNS if c not in REPORTED_IOC_KEY)
    keep = {tuple(r[k] for k in REPORTED_IOC_KEY) for r in rows}
    with connection() as conn:
        conn.executemany(
            f"INSERT INTO reported_iocs ({columns}) VALUES ({values}) "
            f"ON CONFLICT(ioc_type, ioc_value, source_url) DO UPDATE SET {updates}",
            rows,
        )
        stale = [(row["id"],) for row in conn.execute("SELECT id, ioc_type, ioc_value, source_url FROM reported_iocs")
                 if (row["ioc_type"], row["ioc_value"], row["source_url"]) not in keep]
        conn.executemany("DELETE FROM reported_iocs WHERE id = ?", stale)


def find_incident_by_dedup_key(conn, dedup_key):
    row = conn.execute("SELECT * FROM incidents WHERE dedup_key = ?", (dedup_key,)).fetchone()
    return row


def find_incident_by_url(conn, url):
    if not url:
        return None
    row = conn.execute(
        "SELECT i.* FROM incident_urls u JOIN incidents i ON i.id = u.incident_id "
        "WHERE u.source_url = ?", (url,),
    ).fetchone()
    return row or conn.execute(
        "SELECT * FROM incidents WHERE source_url = ? ORDER BY id LIMIT 1", (url,),
    ).fetchone()


def _remember_url(conn, incident_id, url):
    if url:
        conn.execute(
            "INSERT OR IGNORE INTO incident_urls (source_url, incident_id) VALUES (?, ?)",
            (url, incident_id),
        )


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
        _remember_url(conn, new_id, incident.get("source_url"))
        return new_id, True
    else:
        # 既存より信頼度の高い(数値が小さい)情報源のみ本文を上書き。
        # それ以外は日本関連スコア・重要度・ステータスなど解析系フィールドのみ更新。
        incoming_trust = incident.get("source_trust_level", 99)
        existing_trust = existing["source_trust_level"] if existing["source_trust_level"] is not None else 99
        overwrite_body = incoming_trust <= existing_trust

        cvss = max((score for score in (incident.get("cvss"), existing["cvss"])
                    if score is not None), default=None)
        in_kev = max(incident.get("in_kev", 0) or 0, existing["in_kev"] or 0)
        # Missing or shorter evidence must not silently downgrade historical risk.
        severity = max((existing["severity"], incident.get("severity"),
                        determine_severity(cvss=cvss, in_kev=bool(in_kev))), key=order_rank)

        update_fields = {
            "status": incident.get("status", existing["status"]),
            "japan_relevance_score": incident.get("japan_relevance_score", existing["japan_relevance_score"]),
            "japan_relevance_reasons": incident.get("japan_relevance_reasons", existing["japan_relevance_reasons"]),
            "severity": severity,
            "cve_ids": incident.get("cve_ids") or existing["cve_ids"],
            "cvss": cvss,
            "in_kev": in_kev,
            "last_updated_at": incident.get("last_updated_at", existing["last_updated_at"]),
            "last_run_id": incident.get("last_run_id", existing["last_run_id"] if "last_run_id" in existing.keys() else None),
            "updated_at": "now_placeholder",
        }
        if overwrite_body:
            for f in ["title", "target_org", "sector", "country", "attack_vector", "malware",
                      "threat_actor", "intrusion_vector", "impact", "recommended_actions",
                      "confirmed_facts", "unconfirmed_info", "analysis_notes",
                      "source_url", "source_name", "source_trust_level", "raw_hash",
                      "published_at", "source_updated_at"]:
                if incident.get(f) is not None:
                    update_fields[f] = incident[f]
            if incident.get("source_url") and incident["source_url"] != existing["source_url"]:
                # A different article must not inherit the old source's revision date.
                update_fields["published_at"] = incident.get("published_at")
                update_fields["source_updated_at"] = incident.get("source_updated_at")

        set_clause = ", ".join(f"{k} = ?" for k in update_fields if k != "updated_at")
        set_clause += ", updated_at = datetime('now')"
        values = [v for k, v in update_fields.items() if k != "updated_at"]
        conn.execute(
            f"UPDATE incidents SET {set_clause} WHERE id = ?",
            values + [existing["id"]],
        )
        _remember_url(conn, existing["id"], existing["source_url"])
        _remember_url(conn, existing["id"], incident.get("source_url"))
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


def upsert_cve(conn, cve_id, cvss=None, epss=None, in_kev=None, kev_date_added=None, description=None, run_id=None):
    kev_first_seen_run_id = run_id if in_kev else None
    conn.execute(
        """INSERT INTO cves (cve_id, cvss, epss, in_kev, kev_date_added, kev_first_seen_run_id, description)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(cve_id) DO UPDATE SET
             cvss=CASE WHEN excluded.cvss IS NULL THEN cves.cvss
                       WHEN cves.cvss IS NULL THEN excluded.cvss
                       ELSE MAX(excluded.cvss, cves.cvss) END,
             epss=COALESCE(excluded.epss, cves.epss),
             in_kev=MAX(excluded.in_kev, cves.in_kev),
             kev_date_added=COALESCE(excluded.kev_date_added, cves.kev_date_added),
             kev_first_seen_run_id=CASE
               WHEN cves.in_kev = 0 AND excluded.in_kev = 1
                 THEN COALESCE(cves.kev_first_seen_run_id, excluded.kev_first_seen_run_id)
               ELSE cves.kev_first_seen_run_id
             END,
             description=COALESCE(excluded.description, cves.description),
             last_checked_at=datetime('now')
        """,
        (cve_id, cvss, epss, in_kev or 0, kev_date_added, kev_first_seen_run_id, description),
    )


def start_run(conn):
    conn.execute("INSERT INTO run_log (started_at) VALUES (datetime('now'))")
    return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]


def finish_run(conn, run_id, sources_ok, sources_failed, items_fetched, items_new, items_updated, notes=""):
    conn.execute(
        """UPDATE run_log SET finished_at=datetime('now'), sources_ok=?, sources_failed=?,
           items_fetched=?, items_new=?, items_updated=?, notes=? WHERE id=?""",
        (sources_ok, sources_failed, items_fetched, items_new, items_updated, notes, run_id),
    )


def get_new_kev_cve_ids_by_run(conn, run_id):
    """Return CVEs whose KEV state changed from unknown/not-KEV to KEV in this run."""
    return {
        row["cve_id"] for row in conn.execute(
            "SELECT cve_id FROM cves WHERE kev_first_seen_run_id = ?",
            (run_id,),
        ).fetchall()
    }
