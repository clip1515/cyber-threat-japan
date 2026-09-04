"""docs/index.html (静的ダッシュボード) が読み込む JSON データを生成する。

update.py の実行完了時に自動的に呼ばれる。ここで作る docs/data/dashboard_data.json は
GitHub Pagesでそのまま配信できる静的ファイルであり、サーバー(Streamlitのようなプロセス)を
必要としない。iPhoneのSafari等からも直接閲覧できる。
"""
import collections
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR
from analyzers.severity import order_rank
from reporting.daily_report import build_report_data, _row_text, _matches_category

DOCS_DIR = BASE_DIR / "docs"
DASHBOARD_DATA_PATH = DOCS_DIR / "data" / "dashboard_data.json"

TOP_N_PRIORITY = 30      # Critical/High・日本関連・KEV各セクションの表示上限
TOP_N_ALL_INCIDENTS = 300  # 全事案一覧の表示上限(古いものはWebでは省略)
TREND_DAYS = 7

INCIDENT_PUBLIC_FIELDS = [
    "id", "title", "status", "severity", "japan_relevance_score", "japan_relevance_reasons",
    "cve_ids", "in_kev", "country", "sector", "attack_vector", "threat_actor", "malware",
    "published_at", "first_seen_at", "last_updated_at",
    "source_name", "source_url", "source_trust_level",
    "recommended_actions", "confirmed_facts", "unconfirmed_info", "analysis_notes",
]


def _sort_key(row):
    return (-order_rank(row.get("severity")), -(row.get("japan_relevance_score") or 0))


def _pick(rows, n):
    return [{k: r.get(k) for k in INCIDENT_PUBLIC_FIELDS} for r in rows[:n]]


def _cap_lists(d: dict, n: int) -> dict:
    """diff_since_last_run 内のリスト値を上限件数で切り詰める(JSONサイズ対策)。"""
    if not d:
        return d
    capped = dict(d)
    for k, v in list(capped.items()):
        if isinstance(v, list):
            capped[k] = v[:n]
    return capped


def build_dashboard_data(conn, run_id: int = None) -> dict:
    all_rows = [dict(r) for r in conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()]
    all_rows.sort(key=_sort_key)

    critical_high_all = [r for r in all_rows if r.get("severity") in ("Critical", "High")]
    japan_related_all = sorted(
        [r for r in all_rows if (r.get("japan_relevance_score") or 0) >= 40],
        key=lambda r: -(r.get("japan_relevance_score") or 0),
    )
    kev_all = [r for r in all_rows if r.get("in_kev")]
    ransomware_count = sum(1 for r in all_rows if _matches_category(_row_text(r), "ransomware"))
    apt_count = sum(1 for r in all_rows if _matches_category(_row_text(r), "apt"))

    sector_counts = collections.Counter((r.get("sector") or "不明") for r in all_rows)
    vector_counts = collections.Counter((r.get("attack_vector") or "不明") for r in all_rows)

    now = datetime.now(timezone.utc)
    trend = collections.OrderedDict()
    for i in range(TREND_DAYS - 1, -1, -1):
        trend[(now - timedelta(days=i)).date().isoformat()] = 0
    for r in all_rows:
        fs = r.get("first_seen_at")
        if not fs:
            continue
        try:
            d = datetime.fromisoformat(fs).date().isoformat()
        except ValueError:
            continue
        if d in trend:
            trend[d] += 1

    last_run_row = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
    last_run = dict(last_run_row) if last_run_row else None
    effective_run_id = run_id or (last_run["id"] if last_run else None)

    diff = None
    if effective_run_id:
        diff = _cap_lists(build_report_data(conn, effective_run_id), TOP_N_PRIORITY)

    sources = [dict(r) for r in conn.execute(
        "SELECT id, name, type, trust_level, lang, region FROM sources ORDER BY trust_level, name"
    ).fetchall()]

    return {
        "generated_at": now.isoformat(),
        "last_run": last_run,
        "summary": {
            "total_incidents": len(all_rows),
            "new_count": sum(1 for r in all_rows if r.get("status") == "NEW"),
            "active_count": sum(1 for r in all_rows if r.get("status") == "ACTIVE"),
            "critical_high_count": len(critical_high_all),
            "japan_related_count": len(japan_related_all),
            "kev_count": len(kev_all),
            "ransomware_count": ransomware_count,
            "apt_count": apt_count,
        },
        "diff_since_last_run": diff,
        "top_critical_high": _pick(critical_high_all, TOP_N_PRIORITY),
        "top_japan_related": _pick(japan_related_all, TOP_N_PRIORITY),
        "top_kev": _pick(kev_all, TOP_N_PRIORITY),
        "sector_counts": dict(sector_counts.most_common()),
        "vector_counts": dict(vector_counts.most_common()),
        "trend_7d": trend,
        "all_incidents": _pick(all_rows, TOP_N_ALL_INCIDENTS),
        "sources": sources,
    }


def generate_and_save(conn, run_id: int = None) -> Path:
    data = build_dashboard_data(conn, run_id=run_id)
    DASHBOARD_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    DASHBOARD_DATA_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return DASHBOARD_DATA_PATH