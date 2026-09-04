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
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.append(str(Path(__file__).resolve().parent))

from config.settings import SOURCES_YAML, LOG_DIR, CATEGORY_KEYWORDS
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


def build_incident_dict(item, cve_ids, dedup_key, sector, country, cvss, in_kev,
                         is_ransom_apt, severity, score, reasons, status, run_id=None):
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

    cvss = item.extra.get("cvss")
    in_kev = bool(item.extra.get("in_kev"))
    text_lower = item.raw_text.lower()
    is_ransom_apt = any(w in text_lower for w in RANSOM_APT_WORDS)
    has_mitigation = any(w in item.raw_text or w in text_lower for w in MITIGATION_WORDS)

    severity = determine_severity(cvss=cvss, in_kev=in_kev, is_ransomware_or_apt=is_ransom_apt)
    score, reasons = analyze_japan_relevance(
        item.raw_text, getattr(item, "source_region", None),
        item.source_trust_level, item.extra,
    )
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
        is_ransom_apt, severity, score, reasons, status, run_id=run_id,
    )
    incident_id, inserted = dbmod.upsert_incident(conn, incident)

    if not is_new_record and existing_status != status:
        dbmod.add_status_history(conn, incident_id, existing_status, status, status_reason, run_id=run_id)
    elif is_new_record:
        dbmod.add_status_history(conn, incident_id, None, status, status_reason, run_id=run_id)

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
    """
    try:
        collector = build_collector(source_conf)
        return collector.safe_collect()
    except Exception as e:  # noqa: BLE001
        logger.warning("source %s の初期化/収集に失敗したためスキップ: %s", source_conf.get("id"), e)
        return []


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

    for source_conf in sources_conf:
        items = safe_collect_from_source(source_conf, logger)
        if items:
            sources_ok += 1
        else:
            sources_failed += 1
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

    notes = (
        f"{len(sources_conf)}ソース中 成功{sources_ok}/失敗{sources_failed}"
        + (f" (アイテム処理失敗{items_failed}件)" if items_failed else "")
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
            # レポート生成の失敗は収集パイプライン自体の成否には影響させない。
            logger.warning("daily_report.md の生成に失敗しました: %s", e)

        try:
            from reporting.dashboard_export import generate_and_save as export_dashboard_data
            with dbmod.connection() as conn:
                data_path = export_dashboard_data(conn, run_id=run_id)
            logger.info("docs/index.html 用データを生成しました: %s", data_path)
        except Exception as e:  # noqa: BLE001
            logger.warning("ダッシュボード用JSONの生成に失敗しました: %s", e)


if __name__ == "__main__":
    main()