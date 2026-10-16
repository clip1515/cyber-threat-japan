#!/usr/bin/env python3
"""収集→解析→保存を1回実行するパイプライン。1日1回の定時実行を想定したエントリーポイント。

使い方:
    python update.py                # 全ソースを収集
    python update.py --source jpcert_alert   # 特定ソースのみ(デバッグ用)

障害耐性: 1つの情報源の取得失敗、あるいは1件のアイテムの解析失敗があっても、
例外はこのモジュール内で握りつぶしてログに記録し、他の情報源/アイテムの処理は継続する。
実行完了後、その回の実行(run_id)で新規検出・更新された事案を集計し、
reporting/daily_report.py 経由で daily_report.md を生成する。

安全上の制約: 本スクリプトが行うのは公開されているRSS/JSON/APIへの
読み取り専用アクセスのみ。スキャン・認証回避・ペイロード送信は一切行わない。
"""
import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.append(str(Path(__file__).resolve().parent))

from config.settings import (
    SOURCES_YAML, LOG_DIR, CATEGORY_KEYWORDS,
    JAPAN_RISK_SCORE_SIGNIFICANT_JUMP, KEV_RANSOMWARE_UNCONFIRMED_VALUES,
    CVSS_VERSION_RANK,
)
from collectors import build_collector
from parsers.cve_extractor import extract_cve_ids, extract_iocs
from parsers.normalizer import make_dedup_key, parse_date_safe
from analyzers.japan_relevance import analyze_japan_relevance
from analyzers.severity import determine_severity
from analyzers.dedup import find_fuzzy_duplicate
from analyzers.status import compute_status
from database import db as dbmod

MITIGATION_WORDS = [
    "patch", "パッチ", "fixed in", "修正版", "アップデート", "回避策",
    "mitigation", "workaround", "対策版", "セキュリティ更新",
]
RANSOM_APT_WORDS = CATEGORY_KEYWORDS["ransomware"] + CATEGORY_KEYWORDS["apt"]
JP_SECTOR_KEYWORDS = None  # settings.SECTOR_KEYWORDS を使う


def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"update_{datetime.now().strftime('%Y%m%d')}.log"
    root = logging.getLogger()
    # 同一プロセス内でmain()が複数回呼ばれても(テスト等)ハンドラが積み重ならないようにする。
    for h in list(root.handlers):
        h.close()
        root.removeHandler(h)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler()],
        force=True,
    )


def guess_sector(text: str) -> str:
    from config.settings import SECTOR_KEYWORDS
    text_lower = (text or "").lower()
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(k.lower() in text_lower or k in text for k in keywords):
            return sector
    return None


def guess_country(text: str, source_region: str) -> str:
    from config.settings import JAPAN_KEYWORDS_JA, JAPAN_KEYWORDS_EN
    text_lower = (text or "").lower()
    if source_region == "jp" or any(k in text for k in JAPAN_KEYWORDS_JA) or \
            any(k in text_lower for k in JAPAN_KEYWORDS_EN):
        return "日本"
    return None


def _is_ransomware_confirmed(value) -> bool:
    return value not in KEV_RANSOMWARE_UNCONFIRMED_VALUES


def _cvss_version_rank(version) -> int:
    """バージョン文字列を比較可能な優先度に変換する。不明/未知の値は最低優先度(0)。"""
    if not version:
        return 0
    return CVSS_VERSION_RANK.get(str(version), 0)


def build_incident_dict(item, cve_ids, dedup_key, sector, country, cvss, in_kev,
                         is_ransom_apt, severity, score, reasons, status,
                         kev_known_ransomware_use=None, kev_due_date=None, run_id=None,
                         cvss_version=None, cvss_as_of=None, cvss_source_id=None):
    now_iso = datetime.now(timezone.utc).isoformat()
    published_at = parse_date_safe(item.published_at) or now_iso

    if item.source_trust_level == 1:
        confirmed_facts = item.summary or item.title
        unconfirmed_info = None
    else:
        confirmed_facts = None
        unconfirmed_info = item.summary or item.title

    analysis_notes = (
        "本システムによる自動判定: Japan Risk Score/重要度/ステータスはヒューリスティックです。"
        "確定判断の前に source_url の一次情報を確認してください。"
    )

    return {
        "dedup_key": dedup_key,
        "title": item.title,
        "first_seen_at": published_at,
        "published_at": published_at,
        "last_updated_at": now_iso,
        "target_org": None,
        "sector": sector,
        "country": country,
        "attack_vector": None,
        "cve_ids": ",".join(cve_ids) if cve_ids else None,
        "cvss": cvss,
        "in_kev": 1 if in_kev else 0,
        "epss": None,
        "malware": None,
        "threat_actor": None,
        "intrusion_vector": None,
        "impact": None,
        "japan_relevance_score": score,
        "japan_relevance_reasons": reasons,
        "severity": severity,
        "status": status,
        "kev_known_ransomware_use": kev_known_ransomware_use,
        "kev_due_date": kev_due_date,
        "cvss_version": cvss_version,
        "cvss_as_of": cvss_as_of,
        "cvss_source_id": cvss_source_id,
        "recommended_actions": item.extra.get("required_action"),
        "confirmed_facts": confirmed_facts,
        "unconfirmed_info": unconfirmed_info,
        "analysis_notes": analysis_notes,
        "source_url": item.url,
        "source_name": item.source_name,
        "source_trust_level": item.source_trust_level,
        "raw_hash": item.raw_hash(),
        "last_run_id": run_id,
    }


def process_item(conn, item, run_id=None):
    cve_ids = item.extra.get("cve_ids") or extract_cve_ids(item.raw_text)
    cve_ids = [c for c in cve_ids if c]

    if cve_ids:
        dedup_key = make_dedup_key(cve_ids, item.title)
    else:
        published_iso = parse_date_safe(item.published_at)
        fuzzy_key = find_fuzzy_duplicate(conn, item.title, published_iso)
        dedup_key = fuzzy_key or make_dedup_key([], item.title)

    existing = dbmod.find_incident_by_dedup_key(conn, dedup_key)
    is_new_record = existing is None

    # --- 既知の情報(DB上の既存値)と、今回のitem単体の情報をトラスト考慮でマージする ---
    # 複数ソースから同じ事案(dedup_key)が別々に届くことがあり、そのソース単体には
    # in_kev/cvss/KEV属性が無い(欠落している)ケースがある。これを「後退」として
    # 取り込んでしまうと、次回より情報の多いソース経由で再処理された際に
    # severityが見かけ上「上昇」してしまい、実際には何も変化していないのに
    # ESCALATEDが繰り返し記録される(2026-10に確認した誤検知の原因)。
    #
    # 一方、公式情報源(trust_level=1)自身が値を訂正した場合は、その訂正を
    # 正しく反映できなければならない。そのため「値が無い(欠落)」ことと
    # 「同等以上に信頼できるソースが明示的に別の値を出している(訂正)」ことを
    # 区別する。欠落は既存値を保持し、訂正は採用する。
    existing_in_kev = bool(existing["in_kev"]) if existing else False
    existing_cvss = existing["cvss"] if existing else None
    existing_cvss_version = existing["cvss_version"] if existing and "cvss_version" in existing.keys() else None
    existing_cvss_as_of = existing["cvss_as_of"] if existing and "cvss_as_of" in existing.keys() else None
    existing_cvss_source_id = existing["cvss_source_id"] if existing and "cvss_source_id" in existing.keys() else None
    existing_trust = existing["source_trust_level"] if existing and existing["source_trust_level"] is not None else 99
    existing_known_ransom = existing["kev_known_ransomware_use"] if existing and "kev_known_ransomware_use" in existing.keys() else None
    existing_due_date = existing["kev_due_date"] if existing and "kev_due_date" in existing.keys() else None
    existing_recommended_actions = existing["recommended_actions"] if existing else None
    existing_score = (existing["japan_relevance_score"] if existing else 0) or 0
    existing_reasons_raw = existing["japan_relevance_reasons"] if existing else None

    cvss = item.extra.get("cvss")
    cvss_version = item.extra.get("cvss_version")
    cvss_as_of = item.extra.get("cvss_as_of")
    cvss_source_id = item.source_id
    in_kev = bool(item.extra.get("in_kev"))
    if existing is not None:
        # KEV掲載フラグは現状「trueの明示」しか無い(CISAのKEVカタログ取得は
        # 常に「掲載されているものだけ」を列挙するため、「掲載されていない」という
        # 明示的な訂正信号は今のところモデル化されていない)。したがって
        # in_kevは単純にOR(一度trueになったら、欠落で後退しない)で良い。
        in_kev = in_kev or existing_in_kev

        def _keep_existing_cvss():
            return existing_cvss, existing_cvss_version, existing_cvss_as_of, existing_cvss_source_id

        if cvss is None:
            # このソースはcvss情報自体を持たない(欠落) → 既存値を維持。
            cvss, cvss_version, cvss_as_of, cvss_source_id = _keep_existing_cvss()
        elif existing_cvss is not None:
            if item.source_trust_level > existing_trust:
                # より信頼度の低いソースが異なる値を出している → 「訂正」とは見なさず、
                # 既に分かっている、より信頼できる値を維持する(Round1/2で確立済み)。
                cvss, cvss_version, cvss_as_of, cvss_source_id = _keep_existing_cvss()
            elif item.source_trust_level == existing_trust:
                # 2026-10監査Round3②: trust_levelが同じソース同士が競合する場合は
                # trust_levelだけでは決められない。(a)CVSSのバージョン(手法自体が
                # 異なるため、新しい/高いバージョンの値を優先)→(b)バージョンが同じ
                # なら更新日時(cvss_as_of)がより新しい方だけを「訂正」として採用する
                # ことで、古い情報による上書きを防ぐ。日時が片方でも無い/ISO8601形式で
                # 比較不能な場合は、従来通り「明示的な値は訂正として受け入れる」側に
                # フォールバックする(既知の限界として明記。日時なしソースを恒久的に
                # 拒否すると、タイムスタンプを提供しないソースの訂正が一切効かなくなる
                # ため)。
                incoming_rank = _cvss_version_rank(cvss_version)
                existing_rank = _cvss_version_rank(existing_cvss_version)
                if incoming_rank < existing_rank:
                    cvss, cvss_version, cvss_as_of, cvss_source_id = _keep_existing_cvss()
                elif incoming_rank == existing_rank and cvss_as_of and existing_cvss_as_of \
                        and str(cvss_as_of) < str(existing_cvss_as_of):
                    cvss, cvss_version, cvss_as_of, cvss_source_id = _keep_existing_cvss()
                # それ以外(incoming側のバージョンが新しい/日時が新しい/比較不能)は
                # 訂正として受け入れる。
            # incoming側がexistingより信頼度が高い(数値が小さい)場合は、
            # 上昇・下降のいずれであっても常に「訂正」として受け入れる(Round2で確立済み)。

    incoming_known_ransom = item.extra.get("known_ransomware_use")
    if incoming_known_ransom is None:
        kev_known_ransomware_use = existing_known_ransom
    elif existing_known_ransom is not None and _is_ransomware_confirmed(existing_known_ransom) \
            and not _is_ransomware_confirmed(incoming_known_ransom):
        # 既に「悪用確認済み」と分かっている状態を、未確認を示す値で後退させない。
        kev_known_ransomware_use = existing_known_ransom
    else:
        kev_known_ransomware_use = incoming_known_ransom

    incoming_due_date = item.extra.get("due_date")
    kev_due_date = incoming_due_date if incoming_due_date is not None else existing_due_date

    incoming_required_action = item.extra.get("required_action")
    recommended_actions = incoming_required_action if incoming_required_action is not None else existing_recommended_actions

    text_lower = item.raw_text.lower()
    is_ransom_apt = any(w in text_lower for w in RANSOM_APT_WORDS)
    has_mitigation = any(w in item.raw_text or w in text_lower for w in MITIGATION_WORDS)

    severity = determine_severity(cvss=cvss, in_kev=in_kev, is_ransomware_or_apt=is_ransom_apt)
    score, reasons = analyze_japan_relevance(
        item.raw_text, getattr(item, "source_region", None),
        item.source_trust_level, item.extra,
    )
    # 2026-10監査Round4⑥: 本番DBコピーに対する統合リハーサル(process_item()を
    # 実データ規模で実行)で発見。japan_relevance_scoreは「今回処理中のitem単独」
    # から毎回ゼロベースで再計算され、無条件に上書きされていた。CVEが複数ソース
    # (例: KEV経由とNVD経由)から別々に届く場合、KEVのitemを処理した回はKEV由来の
    # 加点(+35程度)が付くが、翌日NVDのitemだけを処理した回はKEV由来の加点が無い
    # item.extraしか見ないため0に戻ってしまう。実際に本番DB(threat_intel.db)上で
    # in_kev=1かつjapan_relevance_score=0の実在する事案を複数件確認した
    # (例: CVE-2017-12149, CVE-2015-5477等。いずれも最後にNVD経由でtouchされたため
    # KEV由来の加点が消えていた)。CVSSと異なり、japan_relevance_scoreは
    # 「複数ソースから観測されたシグナルの蓄積」であり、「古い情報を公式に訂正する」
    # という概念が無いため、単純な非後退(一度ついた最高値を下回らない)で十分かつ
    # 安全(CVSSのような公式な下方訂正を許す必要は無い)。
    if existing is not None and (score or 0) < existing_score:
        score = existing_score
        try:
            reasons = json.loads(existing_reasons_raw) if existing_reasons_raw else reasons
        except (TypeError, ValueError):
            pass
    sector = guess_sector(item.raw_text)
    country = guess_country(item.raw_text, getattr(item, "source_region", None))

    existing_status = existing["status"] if existing else None
    existing_severity = existing["severity"] if existing else None
    first_seen_at = existing["first_seen_at"] if existing else None

    status, status_reason = compute_status(
        is_new_record=is_new_record,
        existing_status=existing_status,
        existing_severity=existing_severity,
        new_severity=severity,
        has_mitigation_info=has_mitigation,
        first_seen_at=first_seen_at,
        last_updated_at=existing["last_updated_at"] if existing else None,
    )

    incident = build_incident_dict(
        item, cve_ids, dedup_key, sector, country, cvss, in_kev,
        is_ransom_apt, severity, score, reasons, status,
        kev_known_ransomware_use=kev_known_ransomware_use, kev_due_date=kev_due_date,
        run_id=run_id,
        cvss_version=cvss_version, cvss_as_of=cvss_as_of, cvss_source_id=cvss_source_id,
    )
    incident["recommended_actions"] = recommended_actions
    incident_id, inserted = dbmod.upsert_incident(conn, incident)

    if not is_new_record and existing_status != status:
        dbmod.add_status_history(conn, incident_id, existing_status, status, status_reason, run_id=run_id)
    elif is_new_record:
        dbmod.add_status_history(conn, incident_id, None, status, status_reason, run_id=run_id)

    # --- KEV変更イベントの検出・記録(既存事案のみ。新規事案は「新規検出」として別途可視化される) ---
    if not is_new_record:
        if in_kev and not existing_in_kev:
            dbmod.add_kev_change_event(conn, incident_id, run_id, "newly_kev_listed", "0", "1")
        if _is_ransomware_confirmed(kev_known_ransomware_use) and not _is_ransomware_confirmed(existing_known_ransom):
            dbmod.add_kev_change_event(
                conn, incident_id, run_id, "ransomware_use_confirmed",
                str(existing_known_ransom), str(kev_known_ransomware_use),
            )
        if kev_due_date and existing_due_date and kev_due_date != existing_due_date:
            dbmod.add_kev_change_event(conn, incident_id, run_id, "kev_due_date_changed", existing_due_date, kev_due_date)
        elif kev_due_date and not existing_due_date:
            dbmod.add_kev_change_event(conn, incident_id, run_id, "kev_due_date_changed", None, kev_due_date)
        if recommended_actions and existing_recommended_actions and recommended_actions != existing_recommended_actions:
            dbmod.add_kev_change_event(
                conn, incident_id, run_id, "kev_required_action_changed",
                existing_recommended_actions, recommended_actions,
            )
        if cvss is not None and existing_cvss is not None and cvss != existing_cvss:
            change_type = "cvss_corrected_up" if cvss > existing_cvss else "cvss_corrected_down"
            dbmod.add_kev_change_event(conn, incident_id, run_id, change_type, str(existing_cvss), str(cvss))
        # 2026-10監査Round4①: CVSSのバージョン自体が変わった場合(例: v3.1→v4.0への
        # 移行)は、スコアの数値が同じ/近い場合でも別途記録する。v3.1とv4.0は採点手法が
        # 異なり「新しい方が常に正しい」とは言い切れないため(本報告の[1]参照)、
        # 自動で安全性を判定するのではなく、バージョン移行の事実と前後の値を
        # kev_change_eventsに必ず残し、人間が後から確認できるようにする
        # (「訂正履歴を保持する」ための最小実装)。cvss_corrected_up/downと重複して
        # 発生することもあるが、どのバージョン間の変化かは this イベントでのみ分かる。
        if cvss_version != existing_cvss_version and existing_cvss_version is not None:
            dbmod.add_kev_change_event(
                conn, incident_id, run_id, "cvss_version_changed",
                f"v{existing_cvss_version} score={existing_cvss}",
                f"v{cvss_version} score={cvss}",
            )
        if (score or 0) - existing_score >= JAPAN_RISK_SCORE_SIGNIFICANT_JUMP:
            dbmod.add_kev_change_event(
                conn, incident_id, run_id, "japan_relevance_jump", str(existing_score), str(score),
            )

    iocs = extract_iocs(item.raw_text)
    if iocs:
        dbmod.upsert_iocs(conn, incident_id, iocs, item.url)

    for cve_id in cve_ids:
        dbmod.upsert_cve(
            conn, cve_id, cvss=cvss,
            in_kev=1 if in_kev else 0,
            kev_date_added=item.extra.get("kev_date_added"),
            description=item.summary[:500] if item.summary else None,
        )

    return is_new_record


def safe_collect_from_source(source_conf, logger):
    """collectorの構築〜収集までを丸ごとtry/exceptで保護する。

    未インストールの依存ライブラリ・設定不備・ネットワークエラー等、
    どのような例外が起きてもここで止め、空リストを返して他のソースの処理を続行させる。

    戻り値: (items: list, failed: bool, error_detail: dict|None)
    failed=True は「取得自体が失敗した」ことを示す。items=[] かつ failed=False は
    「取得は成功したが、今回は正当に0件だった」ことを示し、これらは呼び出し側で
    区別して集計すること(空データと正常な0件を同じ扱いにすると、ソースが
    静かに壊れていても毎日の失敗数として見分けられなくなる)。
    error_detail は {"type", "message", "http_status"} で、
    data/collector_health.json 診断台帳に書き出すために使う。
    """
    try:
        collector = build_collector(source_conf)
        items = collector.safe_collect()
        error_detail = getattr(collector, "last_error_detail", None)
        return items, (getattr(collector, "last_error", None) is not None), error_detail
    except Exception as e:  # noqa: BLE001
        logger.warning("source %s の初期化/収集に失敗したためスキップ: %s", source_conf.get("id"), e)
        return [], True, {"type": type(e).__name__, "message": str(e)[:500], "http_status": None}


def _write_report_failure_notice(run_id, error):
    """daily_report.md生成が失敗した際に、古い内容を残したままにせず失敗を明示する。

    2026-09-08頃、レポート生成内部の例外(unhashable type / NoneType比較)が
    ここで握りつぶされ続けた結果、daily_report.mdが数日間 run_id=7 のまま
    更新されずに「今日のデータであるかのように」表示され続けていた。
    今後同様の未知のバグが起きても、少なくとも「更新に失敗している」ことが
    ファイルを見ればすぐ分かるようにする。
    """
    try:
        from config.settings import DAILY_REPORT_PATH
        DAILY_REPORT_PATH.write_text(
            "# 日本向けサイバー脅威 デイリーレポート\n\n"
            f"⚠️ 今回(run_id={run_id})はレポートの生成中にエラーが発生したため、"
            "内容を更新できませんでした。\n\n"
            f"エラー: {type(error).__name__}: {error}\n\n"
            "情報の収集自体(データベースへの保存)は完了しています。"
            "このエラーはコード側の不具合の可能性が高いため、確認・修正が必要です。\n",
            encoding="utf-8",
        )
    except Exception:
        logging.getLogger("update").exception("レポート失敗通知の書き込み自体にも失敗しました")


def _write_collector_health_json(degraded_sources=None):
    """ソースごとの取得成否をリポジトリに書き出す(2026-10監査①)。

    GitHub Actionsの実行ログは第三者が後から見返すことができない
    (このセッションでも認証の都合で取得できなかった)。data/配下に
    コミットされるこのファイルを見れば、「どのソースが・いつから・
    何回連続で・どういう理由で」失敗しているかをリポジトリの履歴
    (git log -p data/collector_health.json)だけで追えるようにする。

    2026-10監査Round4②: record_source_health()自体の書き込みが一部の
    ソースで失敗していた場合(main()側でtry/exceptして処理は継続するが)、
    このJSONにはその事実が一切残らず、「診断台帳そのものが一部欠落している」
    ことが外から分からなかった(=監視の質が下がったことが見えない静かな
    劣化)。degraded_sources(そのrunでrecord_source_health呼び出し自体が
    失敗したsource_idのリスト)を受け取り、空でなければJSONにその旨を
    明示するフィールドを追加する。
    """
    import json
    from config.settings import DATA_DIR

    with dbmod.connection() as conn:
        rows = dbmod.get_all_source_health(conn)
    path = DATA_DIR / "collector_health.json"
    degraded_sources = degraded_sources or []
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": rows,
        # 診断台帳自体の信頼性フラグ。falseの場合、sourcesの一部(または全部)の
        # 行が「今回の実際の結果」ではなく「前回までの古い値」である可能性がある
        # (そのsourceのrecord_source_health呼び出し自体が今回失敗したため)。
        "diagnostics_degraded": bool(degraded_sources),
        "diagnostics_degraded_sources": degraded_sources,
    }
    if degraded_sources:
        payload["diagnostics_note"] = (
            f"{len(degraded_sources)}件のソース({', '.join(degraded_sources)})で"
            "source_healthの記録自体に失敗したため、これらのsourcesエントリは"
            "今回の実行結果を反映していない可能性があります(監視品質の低下)。"
        )
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def main():
    parser = argparse.ArgumentParser(description="cyber-threat-japan 収集パイプライン")
    parser.add_argument("--source", help="このsource idのみ実行(デバッグ用)")
    parser.add_argument("--no-report", action="store_true", help="daily_report.mdの生成をスキップ(デバッグ用)")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("update")
    dbmod.init_db()

    sources_conf = yaml.safe_load(SOURCES_YAML.read_text(encoding="utf-8"))["sources"]
    if args.source:
        sources_conf = [s for s in sources_conf if s["id"] == args.source]

    with dbmod.connection() as conn:
        run_id = dbmod.start_run(conn)

    sources_ok, sources_failed = 0, 0
    items_fetched, items_new, items_updated, items_failed = 0, 0, 0, 0
    health_record_failures = []  # 2026-10監査Round4②: record_source_health自体が失敗したsource_id

    for source_conf in sources_conf:
        items, failed, error_detail = safe_collect_from_source(source_conf, logger)
        try:
            # 2026-10監査Round3①: record_source_health自体のDB書き込みが失敗した場合
            # (DBロック・ディスク逼迫等)、ここが素通しの例外を投げると、診断記録の
            # 失敗だけでそのソースの本来のアイテム処理(さらには残りの全ソースの処理)
            # まで止まってしまう。診断台帳への書き込み失敗は「静かな失敗」を無くす
            # ための付帯機能であり、本体のパイプラインを止める理由にしてはならない。
            with dbmod.connection() as conn:
                dbmod.record_source_health(
                    conn, source_conf.get("id"), success=not failed, item_count=len(items),
                    error_type=(error_detail or {}).get("type"),
                    error_message=(error_detail or {}).get("message"),
                    http_status=(error_detail or {}).get("http_status"),
                )
        except Exception:  # noqa: BLE001
            logger.exception(
                "source %s: source_healthの記録に失敗しましたが、本処理は継続します",
                source_conf.get("id"),
            )
            # 2026-10監査Round4②: 「処理は継続する」だけでは、診断台帳(source_health/
            # collector_health.json)の該当ソースの情報が古いまま沈黙してしまい、
            # 「監視の質が下がったこと」自体が見えなくなる。失敗したsource_idを控えて
            # おき、後で_write_collector_health_json()に渡して明示する。
            health_record_failures.append(source_conf.get("id"))
        if failed:
            # 取得自体が失敗した(ネットワークエラー・例外等)。
            sources_failed += 1
            continue
        # 取得は成功。0件はソース側の正当な結果である可能性があるため
        # sources_failedには数えない(ログにだけ残す)。
        sources_ok += 1
        if not items:
            logger.info("source %s: 取得は成功したが0件でした(正常な0件の可能性)", source_conf.get("id"))
            continue

        for item in items:
            item.source_region = source_conf.get("region")
            try:
                with dbmod.connection() as conn:
                    is_new = process_item(conn, item, run_id=run_id)
                items_fetched += 1
                if is_new:
                    items_new += 1
                else:
                    items_updated += 1
            except Exception as e:  # noqa: BLE001
                # 1件のアイテムの解析/保存失敗で他のアイテムやソースの処理を止めない。
                items_failed += 1
                logger.warning(
                    "source %s のアイテム処理に失敗したためスキップ: %s (title=%r)",
                    source_conf.get("id"), e, getattr(item, "title", ""),
                )

    # 2026-10監査Round4②: collector_health.jsonの書き出し自体がここで失敗した場合も、
    # run_log.notesに明示できるよう、finish_run()より前に実行し、結果を記録しておく。
    diagnostics_write_failed = False
    try:
        _write_collector_health_json(degraded_sources=health_record_failures)
    except Exception:  # noqa: BLE001
        logger.exception("data/collector_health.json の書き出しに失敗しました")
        diagnostics_write_failed = True

    notes = (
        f"{len(sources_conf)}ソース中 成功{sources_ok}/失敗{sources_failed}"
        + (f" (アイテム処理失敗{items_failed}件)" if items_failed else "")
        # 2026-10監査Round4②: 診断台帳(source_health/collector_health.json)自体の
        # 記録・書き出し失敗は、run_log.notes(既存の可視化経路)にも明示する。
        # 収集パイプライン本体は正常終了していても、「どのソースが失敗したかを
        # 特定する能力」自体がその回については一部(または全部)欠けていたことを、
        # run一覧を見るだけで分かるようにする(=監視品質の低下を隠さない)。
        + (f" [診断記録失敗: {','.join(health_record_failures)}]" if health_record_failures else "")
        + (" [⚠️collector_health.json書き出し失敗: 診断台帳全体が古い状態のまま]" if diagnostics_write_failed else "")
    )
    with dbmod.connection() as conn:
        dbmod.finish_run(
            conn, run_id, sources_ok, sources_failed,
            items_fetched, items_new, items_updated,
            notes=notes,
        )

    logger.info(
        "完了: fetched=%d new=%d updated=%d failed_items=%d ok_sources=%d failed_sources=%d",
        items_fetched, items_new, items_updated, items_failed, sources_ok, sources_failed,
    )

    if not args.no_report:
        try:
            from reporting.daily_report import generate_and_save
            with dbmod.connection() as conn:
                run_meta = conn.execute("SELECT * FROM run_log WHERE id = ?", (run_id,)).fetchone()
                report_path = generate_and_save(conn, run_id, dict(run_meta))
            logger.info("daily_report.md を生成しました: %s", report_path)
        except Exception as e:  # noqa: BLE001
            # レポート生成の失敗は収集パイプライン自体の成否には影響させないが、
            # 古い内容がそのまま残って「今日のデータ」のように見え続けるのを防ぐため、
            # 失敗した事実そのものをdaily_report.mdに書き込んでおく。
            logger.exception("daily_report.md の生成に失敗しました")
            _write_report_failure_notice(run_id, e)

        try:
            from reporting.dashboard_export import generate_and_save as export_dashboard_data
            with dbmod.connection() as conn:
                data_path = export_dashboard_data(conn, run_id=run_id)
            logger.info("docs/index.html 用データを生成しました: %s", data_path)
        except Exception as e:  # noqa: BLE001
            logger.exception("ダッシュボード用JSONの生成に失敗しました")


if __name__ == "__main__":
    main()
