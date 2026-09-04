"""daily_report.md 生成モジュール。

update.py の1回の実行(run_id)ごとに「その回で新規作成/更新された事案」を集計し、
差分ベースのMarkdownレポートを生成する。前回から重要な変化が無い場合は、
その旨を冒頭で明示する(「重要な新規変化なし」)。

このモジュールはDBを読むだけで、収集や解析は行わない。
"""
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from config.settings import (
    REPORTS_DIR, DAILY_REPORT_PATH, CATEGORY_KEYWORDS, JAPAN_VICTIM_REASON_MARKERS,
    REPORT_TOP_N_PER_SECTION,
)
from analyzers.severity import order_rank
from database import db as dbmod


def _row_text(row) -> str:
    """カテゴリ分類/キーワード判定用に、事案1件分のテキストを結合する。"""
    parts = [
        row["title"] or "",
        row["confirmed_facts"] or "",
        row["unconfirmed_info"] or "",
        row["attack_vector"] or "",
        row["malware"] or "",
    ]
    return "\n".join(parts)


def _matches_category(text: str, category: str) -> bool:
    text_lower = text.lower()
    return any(k in text or k in text_lower for k in CATEGORY_KEYWORDS[category])


def _sort_key(row):
    return (-order_rank(row["severity"]), -(row["japan_relevance_score"] or 0))


def _fmt_incident_line(row, extra: str = "") -> str:
    cve = row["cve_ids"] or "-"
    src = f"{row['source_name']}" if row["source_name"] else "-"
    url = row["source_url"] or ""
    return (
        f"- **[{row['severity'] or '不明'}] {row['title']}** "
        f"(Japan Risk Score: {row['japan_relevance_score']}, ステータス: {row['status']}, CVE: {cve})"
        f"{extra}\n  - 情報源: {src} — {url}"
    )


def _latest_transitions_by_incident(history_rows):
    latest = {}
    for row in history_rows:
        iid = row["incident_id"]
        if iid not in latest or row["id"] > latest[iid]["id"]:
            latest[iid] = row
    return latest


def build_report_data(conn, run_id):
    """レポートに必要な集計データをdictで返す(テストしやすいようMarkdown化と分離)。"""
    touched = [dict(r) for r in dbmod.get_incidents_by_run(conn, run_id)]
    history_rows = dbmod.get_status_transitions_by_run(conn, run_id)
    latest_transition = _latest_transitions_by_incident(history_rows)

    new_ids = {iid for iid, r in latest_transition.items() if r["old_status"] is None}
    escalated_ids = {iid for iid, r in latest_transition.items() if r["new_status"] == "ESCALATED"}

    touched.sort(key=_sort_key)

    new_incidents = [r for r in touched if r["id"] in new_ids]
    critical_high = [r for r in touched if r["severity"] in ("Critical", "High")]
    japan_victims = [
        r for r in touched
        if r["country"] == "日本"
        and r["japan_relevance_reasons"]
        and any(m in r["japan_relevance_reasons"] for m in JAPAN_VICTIM_REASON_MARKERS)
    ]
    kev_items = [r for r in touched if r["in_kev"]]
    escalated = [r for r in touched if r["id"] in escalated_ids]

    ransomware_items, apt_items, ddos_items = [], [], []
    for r in touched:
        text = _row_text(r)
        if _matches_category(text, "ransomware"):
            ransomware_items.append(r)
        if _matches_category(text, "apt"):
            apt_items.append(r)
        if _matches_category(text, "ddos"):
            ddos_items.append(r)

    recommended_actions = sorted({
        r["recommended_actions"] for r in touched if r["recommended_actions"]
    })

    primary_sources = sorted({
        (r["source_name"], r["source_url"]) for r in touched
        if r["source_trust_level"] == 1 and r["source_name"]
    })

    significant = bool(
        [r for r in new_incidents if r["severity"] in ("Critical", "High")]
        or escalated
        or japan_victims
        or kev_items
    )

    return {
        "touched": touched,
        "new_incidents": new_incidents,
        "critical_high": critical_high,
        "japan_victims": japan_victims,
        "kev_items": kev_items,
        "escalated": escalated,
        "ransomware_items": ransomware_items,
        "apt_items": apt_items,
        "ddos_items": ddos_items,
        "recommended_actions": recommended_actions,
        "primary_sources": primary_sources,
        "significant_change": significant,
    }


def _section(title: str, rows: list, empty_msg: str) -> str:
    lines = [f"## {title}", ""]
    if not rows:
        lines.append(empty_msg)
    else:
        for r in rows[:REPORT_TOP_N_PER_SECTION]:
            lines.append(_fmt_incident_line(r))
        if len(rows) > REPORT_TOP_N_PER_SECTION:
            lines.append(f"\n(他 {len(rows) - REPORT_TOP_N_PER_SECTION} 件、ダッシュボードで確認してください)")
    lines.append("")
    return "\n".join(lines)


def build_report_markdown(conn, run_id, run_meta: dict) -> str:
    data = build_report_data(conn, run_id)

    lines = [
        "# 日本向けサイバー脅威 デイリーレポート",
        "",
        f"- 実行日時: {run_meta.get('started_at')} 〜 {run_meta.get('finished_at')} (run_id={run_id})",
        f"- 収集結果: 成功ソース {run_meta.get('sources_ok')} / 失敗ソース {run_meta.get('sources_failed')}"
        f" / 新規 {run_meta.get('items_new')}件 / 更新 {run_meta.get('items_updated')}件",
        "- 本レポートは公開情報のみに基づく自動集計です。断定的表現は一次情報(情報源URL)で必ず確認してください。",
        "",
    ]

    if not data["significant_change"]:
        lines += [
            "> **本日は前回から重要な新規変化はありません。**"
            "(Critical/Highの新規案件・重要度上昇・日本組織への実被害・新規KEV掲載のいずれも検出されませんでした)",
            "",
        ]
    else:
        lines += ["> ⚠️ **重要な変化を検出しました。** 詳細は各セクションを確認してください。", ""]

    lines.append(_section(
        "本日の新規脅威",
        data["new_incidents"],
        "本日新規に検出された事案はありません。",
    ))
    lines.append(_section(
        "Critical / High",
        data["critical_high"],
        "本日検出・更新されたCritical/High案件はありません。",
    ))
    lines.append(_section(
        "日本企業・日本組織への実被害",
        data["japan_victims"],
        "本日、日本組織への実被害を示す一次/準一次情報は確認されていません。",
    ))

    kev_lines = [f"## 悪用確認済みCVE (CISA KEV等)", ""]
    if not data["kev_items"]:
        kev_lines.append("本日新たに悪用確認済みとして扱われたCVEはありません。")
    else:
        cve_seen = set()
        for r in data["kev_items"]:
            for cve in (r["cve_ids"] or "").split(","):
                cve = cve.strip()
                if cve and cve not in cve_seen:
                    cve_seen.add(cve)
                    kev_lines.append(f"- {cve} — {r['title']} (情報源: {r['source_name']})")
    kev_lines.append("")
    lines.append("\n".join(kev_lines))

    cat_lines = ["## APT / ランサムウェア / DDoS", ""]
    for label, key in [("ランサムウェア", "ransomware_items"), ("APT", "apt_items"), ("DDoS", "ddos_items")]:
        cat_lines.append(f"### {label}")
        if not data[key]:
            cat_lines.append(f"該当する事案はありません。")
        else:
            for r in data[key][:REPORT_TOP_N_PER_SECTION]:
                cat_lines.append(_fmt_incident_line(r))
        cat_lines.append("")
    lines.append("\n".join(cat_lines))

    lines.append(_section(
        "前日から重要度が上がった事案 (ESCALATED)",
        data["escalated"],
        "重要度が上昇した事案はありません。",
    ))

    actions_lines = ["## 推奨対策", ""]
    if not data["recommended_actions"]:
        actions_lines.append("情報源に明記された推奨対策の記載はありません。各事案の情報源URLを直接確認してください。")
    else:
        for a in data["recommended_actions"][:REPORT_TOP_N_PER_SECTION]:
            actions_lines.append(f"- {a}")
    actions_lines.append("")
    lines.append("\n".join(actions_lines))

    src_lines = ["## 一次情報源", ""]
    if not data["primary_sources"]:
        src_lines.append("本日、一次情報源(公式機関/ベンダー)からの新規/更新事案はありません。")
    else:
        for name, url in data["primary_sources"]:
            src_lines.append(f"- {name}: {url}")
    src_lines.append("")
    lines.append("\n".join(src_lines))

    lines.append(
        "---\n"
        "本レポートは公開情報(RSS/公式API/公開JSON)のみを収集した自動集計です。"
        "第三者システムへのスキャン・侵入・認証回避・脆弱性の能動的悪用は一切行っていません。\n"
    )

    return "\n".join(lines)


def generate_and_save(conn, run_id, run_meta: dict) -> Path:
    """daily_report.md(プロジェクト直下、常に最新)と reports/ 配下の日付付きアーカイブに保存する。"""
    markdown = build_report_markdown(conn, run_id, run_meta)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    date_str = (run_meta.get("started_at") or "")[:10] or "unknown-date"
    dated_path = REPORTS_DIR / f"daily_report_{date_str}_run{run_id}.md"
    dated_path.write_text(markdown, encoding="utf-8")

    DAILY_REPORT_PATH.write_text(markdown, encoding="utf-8")
    return DAILY_REPORT_PATH