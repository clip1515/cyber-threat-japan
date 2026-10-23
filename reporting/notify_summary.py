#!/usr/bin/env python3
"""通知(メール/ntfy等)向けの短いプレーンテキスト要約を、
docs/data/dashboard_data.json から生成して標準出力に書き出す。

GitHub Actionsのワークフローから
    python reporting/notify_summary.py > /tmp/notify_body.txt
のように呼び出し、その内容をメール本文やプッシュ通知の本文として使う想定。

本文を出力する前に、JSONが DB の最新 run を表していることを確認する。古いJSON(生成失敗時)や
全ソース取得失敗の回の要約、差分情報が欠損・破損・矛盾したJSONを「重要な変化なし」として通知しないよう、
不一致なら非ゼロ終了する。
"""
import json
import sqlite3
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import BASE_DIR, DB_PATH

DATA_PATH = BASE_DIR / "docs" / "data" / "dashboard_data.json"

# run_id は DB の復元で再利用され得るため、取得できる実行識別情報をすべて照合する。
RUN_IDENTITY = ("id", "started_at", "finished_at", "sources_ok", "sources_failed")
# 取得に失敗した場合に、要約から「変化なし」と断定してはならない監視ソースの種類。
CRITICAL_SOURCE_TYPES = {"kev_json": "悪用確認済みCVE", "nvd_api": "CVE・CVSS"}


DIFF_LIST_KEYS = ("new_incidents", "escalated", "japan_victims", "kev_items")


def diff_problem(diff):
    """diff_since_last_run が通知の判断に使える形式で、significant_change が中身と整合していれば None。

    significant_change の判定は reporting/daily_report.build_report_data と同じ規則で照合する。
    """
    if not isinstance(diff, dict):
        return "差分情報(diff_since_last_run)がありません"
    if type(diff.get("significant_change")) is not bool:
        return "差分情報の significant_change が真偽値ではありません"
    for key in DIFF_LIST_KEYS:
        if not (isinstance(diff.get(key), list) and all(isinstance(r, dict) for r in diff[key])):
            return f"差分情報の {key} がありません(または一覧ではありません)"
    expected = bool(
        any(r.get("severity") in ("Critical", "High") for r in diff["new_incidents"])
        or diff["escalated"] or diff["japan_victims"] or diff["kev_items"]
    )
    if diff["significant_change"] != expected:
        return "差分情報の significant_change が差分の内容と一致しません"
    return None


def check_dashboard_is_current():
    """JSONが DB の最新runを表していれば None、そうでなければ理由の文字列を返す。"""
    try:
        data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"ダッシュボードJSONを読めません: {type(e).__name__}"
    last_run = data.get("last_run") if isinstance(data, dict) else None
    json_run_id = last_run.get("id") if isinstance(last_run, dict) else None
    if not isinstance(json_run_id, int):
        return "ダッシュボードJSONに run_id がありません"
    try:
        with sqlite3.connect(DB_PATH.resolve().as_uri() + "?mode=ro", uri=True) as conn:
            row = conn.execute(f"SELECT {', '.join(RUN_IDENTITY)} FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
            new_kev = conn.execute("SELECT COUNT(*) FROM cves WHERE kev_first_seen_run_id = ?",
                                   (json_run_id,)).fetchone()[0]
    except sqlite3.Error as e:
        return f"DBを読めません: {type(e).__name__}"
    if row is None or row[0] != json_run_id:
        return f"ダッシュボードJSONの run_id={json_run_id} が DB の最新 run_id={row[0] if row else None} と一致しません"
    mismatched = [key for key, value in zip(RUN_IDENTITY, row) if last_run.get(key) != value]
    if mismatched:
        return f"run_id={json_run_id} の実行情報がDBと一致しません: {', '.join(mismatched)}"
    if not last_run.get("finished_at"):
        return f"run_id={json_run_id} は完了していません"
    if not last_run.get("sources_ok"):
        return f"run_id={json_run_id} は1ソースも取得できていません"
    diff = data.get("diff_since_last_run")
    problem = diff_problem(diff)
    if problem:
        return f"run_id={json_run_id} の{problem}"
    # 差分のKEV一覧が欠けると、新規KEVがあっても「変化なし」と通知してしまう。DBと照合する。
    if bool(new_kev) != bool(diff["kev_items"]):
        return (f"run_id={json_run_id} の新規KEVがDBでは{new_kev}件ですが、"
                f"差分情報では{len(diff['kev_items'])}件です")
    return None


QUALITY_VERSION = 1
QUALITY_KEYS = {"version", "failed_sources", "incomplete_sources", "items_failed"}
SOURCE_KEYS = {"id", "name", "type"}
INCOMPLETE_SOURCE_KEYS = SOURCE_KEYS | {"reason"}
QUALITY_UNKNOWN = ("⚠️ 収集品質を確認できません(品質情報の欠損・破損・旧形式・件数矛盾)。"
                   "KEV・NVDを含む全ソースの取得状況は未確認です。")
NO_CHANGE_HEADLINES = {
    "complete": "本日は重要な新規変化はありません",
    "partial": "取得できた範囲では重要な新規変化は検出されませんでした(部分収集のため断定できません)",
    "unknown": "重要な新規変化は検出されませんでしたが、収集品質が未確認のため断定できません",
}


def _reject_constant(name):
    raise ValueError(f"非有限の数値 {name}")


def _is_source_record(s, keys):
    return (
        isinstance(s, dict) and set(s) == keys
        and isinstance(s["id"], str) and s["id"] != "" and isinstance(s["type"], str) and s["type"] != ""
        and (s["name"] is None or isinstance(s["name"], str))
        and ("reason" not in keys or (isinstance(s["reason"], str) and s["reason"] != ""))
    )


def parse_quality(last_run):
    """run_log.notes の quality を返す。version 1 の形式(キー・型が完全一致)で run_log と矛盾しない場合だけ
    dict を返し、それ以外(欠損・破損・旧形式・未知のキー・NaN・件数矛盾・ID重複)は None。"""
    notes = last_run.get("notes") if isinstance(last_run, dict) else None
    if not isinstance(notes, str) or " quality=" not in notes:
        return None
    try:
        quality = json.loads(notes.split(" quality=", 1)[1], parse_constant=_reject_constant)
    except ValueError:
        return None
    if not (isinstance(quality, dict) and set(quality) == QUALITY_KEYS):
        return None
    failed, incomplete, items_failed = quality["failed_sources"], quality["incomplete_sources"], quality["items_failed"]
    sources_ok, sources_failed = last_run.get("sources_ok"), last_run.get("sources_failed")
    well_formed = (
        type(quality["version"]) is int and quality["version"] == QUALITY_VERSION
        and isinstance(failed, list) and all(_is_source_record(s, SOURCE_KEYS) for s in failed)
        and isinstance(incomplete, list) and all(_is_source_record(s, INCOMPLETE_SOURCE_KEYS) for s in incomplete)
        and type(items_failed) is int and items_failed >= 0
        and type(sources_failed) is int and len(failed) == sources_failed
        and type(sources_ok) is int and len(incomplete) <= sources_ok
        and len({s["id"] for s in failed + incomplete}) == len(failed) + len(incomplete)
    )
    return quality if well_formed else None


def collection_quality(last_run):
    """(state, 警告行) を返す。state は complete / partial / unknown。

    品質情報を確認できない場合は監視品質を推定せず unknown とする(parse_quality を参照)。
    """
    quality = parse_quality(last_run)
    if quality is None:
        return "unknown", [QUALITY_UNKNOWN]
    failed, incomplete, items_failed = quality["failed_sources"], quality["incomplete_sources"], quality["items_failed"]
    if not failed and not incomplete and not items_failed:
        return "complete", []
    lines = [
        f"⚠️ 部分収集: 成功{last_run['sources_ok']} / 失敗{len(failed)}ソース、"
        f"アイテム処理失敗{items_failed}件。取得できた範囲の結果です。",
    ]
    if failed:
        lines.append("取得に失敗したソース: " + ", ".join(s["name"] or s["id"] for s in failed))
    if incomplete:
        lines.append("全件を取得できなかったソース: "
                     + ", ".join(f"{s['name'] or s['id']}({s['reason']})" for s in incomplete))
    for s in failed:
        if s["type"] in CRITICAL_SOURCE_TYPES:
            lines.append(f"⚠️ 重要ソース {s['name'] or s['id']} の取得に失敗したため、"
                         f"{CRITICAL_SOURCE_TYPES[s['type']]}の変化は確認できていません。")
    for s in incomplete:
        if s["type"] in CRITICAL_SOURCE_TYPES:
            lines.append(f"⚠️ 重要ソース {s['name'] or s['id']} は全件を取得できなかったため、"
                         f"{CRITICAL_SOURCE_TYPES[s['type']]}の変化は一部しか確認できていません。")
    return "partial", lines


def build_summary_text() -> str:
    if not DATA_PATH.exists():
        return "cyber-threat-japan: ダッシュボードデータ(docs/data/dashboard_data.json)が見つかりません。"

    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    diff = data.get("diff_since_last_run")
    summary = data.get("summary", {})
    quality_state, warning = collection_quality(data.get("last_run"))
    prefix = "".join(line + "\n" for line in warning)

    problem = diff_problem(diff)
    if problem:
        # main() は通知自体を中止するが、この関数単体でも「変化なし」とは書かない。
        return prefix + f"⚠️ cyber-threat-japan: 重要な変化の有無を判断できません({problem})"

    if not diff["significant_change"]:
        headline = NO_CHANGE_HEADLINES[quality_state]
        return (
            prefix + f"cyber-threat-japan: {headline}\n"
            f"総事案 {summary.get('total_incidents', 0)}件 / "
            f"Critical・High {summary.get('critical_high_count', 0)}件 / "
            f"日本関連 {summary.get('japan_related_count', 0)}件 / "
            f"悪用確認済みCVE {summary.get('kev_count', 0)}件"
        )

    new_n = len(diff["new_incidents"])
    escalated_n = len(diff["escalated"])
    victim_n = len(diff["japan_victims"])
    kev_n = len(diff["kev_items"])
    return (
        prefix + "【要確認】cyber-threat-japan: 重要な変化を検出しました\n"
        f"新規 {new_n}件 / 重要度上昇 {escalated_n}件 / "
        f"日本組織への実被害 {victim_n}件 / 新規の悪用確認済みCVE {kev_n}件\n"
        "詳細はダッシュボード(GitHub Pages)または daily_report.md を確認してください。"
    )


def main():
    problem = check_dashboard_is_current()
    if problem:
        print(f"通知を中止します: {problem}", file=sys.stderr)
        return 1
    print(build_summary_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())