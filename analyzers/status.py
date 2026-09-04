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