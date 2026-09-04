#!/usr/bin/env python3
"""通知(メール/ntfy等)向けの短いプレーンテキスト要約を、
docs/data/dashboard_data.json から生成して標準出力に書き出す。

GitHub Actionsのワークフローから
    python reporting/notify_summary.py > /tmp/notify_body.txt
のように呼び出し、その内容をメール本文やプッシュ通知の本文として使う想定。
"""
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import BASE_DIR

DATA_PATH = BASE_DIR / "docs" / "data" / "dashboard_data.json"


def build_summary_text() -> str:
    if not DATA_PATH.exists():
        return "cyber-threat-japan: ダッシュボードデータ(docs/data/dashboard_data.json)が見つかりません。"

    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    diff = data.get("diff_since_last_run") or {}
    summary = data.get("summary", {})

    if not diff.get("significant_change"):
        return (
            "cyber-threat-japan: 本日は重要な新規変化はありません\n"
            f"総事案 {summary.get('total_incidents', 0)}件 / "
            f"Critical・High {summary.get('critical_high_count', 0)}件 / "
            f"日本関連 {summary.get('japan_related_count', 0)}件 / "
            f"悪用確認済みCVE {summary.get('kev_count', 0)}件"
        )

    new_n = len(diff.get("new_incidents", []))
    escalated_n = len(diff.get("escalated", []))
    victim_n = len(diff.get("japan_victims", []))
    kev_n = len(diff.get("kev_items", []))
    return (
        "【要確認】cyber-threat-japan: 重要な変化を検出しました\n"
        f"新規 {new_n}件 / 重要度上昇 {escalated_n}件 / "
        f"日本組織への実被害 {victim_n}件 / 新規の悪用確認済みCVE {kev_n}件\n"
        "詳細はダッシュボード(GitHub Pages)または daily_report.md を確認してください。"
    )


if __name__ == "__main__":
    print(build_summary_text())