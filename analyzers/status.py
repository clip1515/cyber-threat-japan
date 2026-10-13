"""ステータス(NEW/ACTIVE/ESCALATED/MITIGATED/CLOSED)の遷移ロジック。"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import (
    STATUS_NEW, STATUS_ACTIVE, STATUS_ESCALATED, STATUS_MITIGATED, STATUS_CLOSED,
    DAYS_UNTIL_CLOSED_CANDIDATE, DAYS_AS_NEW,
)
from analyzers.severity import order_rank


def compute_status(is_new_record: bool, existing_status: str, existing_severity: str,
                    new_severity: str, has_mitigation_info: bool,
                    first_seen_at: str, last_updated_at: str) -> tuple:
    """戻り値: (new_status, reason)"""
    if is_new_record:
        return STATUS_NEW, "新規検出"

    if existing_status == STATUS_CLOSED:
        # 収束済みの事案に新しい動きがあれば再アクティブ化
        return STATUS_ACTIVE, "収束済み事案に新規更新を検出したため再アクティブ化"

    if existing_severity and new_severity and order_rank(new_severity) > order_rank(existing_severity):
        return STATUS_ESCALATED, f"重要度が {existing_severity} → {new_severity} に上昇"

    if has_mitigation_info:
        return STATUS_MITIGATED, "パッチ/回避策等の対策情報を検出"

    if first_seen_at:
        try:
            first_dt = datetime.fromisoformat(first_seen_at)
            age_days = (datetime.now(timezone.utc) - first_dt.astimezone(timezone.utc)).days
            if age_days <= DAYS_AS_NEW and existing_status == STATUS_NEW:
                return STATUS_NEW, "検出から日が浅いためNEW継続"
        except ValueError:
            pass

    # 2026-10監査Round4⑥: 本番DBコピーに対する統合リハーサル(process_item()を
    # 実データ規模で実行)で発見した実バグの修正。ここより上のどの条件にも
    # 当たらない(=今回新たな変化は無い)場合、従来は無条件にACTIVEへ「格下げ」
    # していたため、過去に一度ESCALATED(重要度上昇を検出)やMITIGATED(対策情報を
    # 検出)になった事案が、無関係な日次の再取得(例: CISA KEVカタログの全件再同期で
    # 同じCVEが何の変化も無く再度touchされる)が起きるたびにACTIVEへ戻ってしまい、
    # 「この事案は重要度が上昇した/対策情報がある」という履歴上重要なステータスが
    # 消えていた。実際に本番DBコピー上で、KEVカタログの無害な全件再同期だけで
    # ESCALATED→ACTIVE / MITIGATED→ACTIVEの退行が多数件(リハーサルで確認した
    # 範囲で40件超)発生することを確認した。変化が無い場合はACTIVEへ格下げせず、
    # 既存のESCALATED/MITIGATEDステータスを維持する。
    if existing_status in (STATUS_ESCALATED, STATUS_MITIGATED):
        return existing_status, "変化なし(既存のESCALATED/MITIGATEDステータスを維持)"

    return STATUS_ACTIVE, "継続中(状態変化なし)"


def check_closable(conn):
    """一定期間更新の無い ACTIVE/MITIGATED 事案を CLOSED 候補として一覧化する。
    自動ではCLOSEDにせず、人間の確認を挟むための候補リストを返す(誤って収束扱いにしないため)。
    """
    rows = conn.execute(
        "SELECT id, title, status, updated_at FROM incidents "
        "WHERE status IN (?, ?) ORDER BY updated_at ASC",
        (STATUS_ACTIVE, STATUS_MITIGATED),
    ).fetchall()
    candidates = []
    now = datetime.now(timezone.utc)
    for row in rows:
        try:
            updated_dt = datetime.fromisoformat(row["updated_at"].replace(" ", "T")).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if (now - updated_dt).days >= DAYS_UNTIL_CLOSED_CANDIDATE:
            candidates.append(dict(row))
    return candidates