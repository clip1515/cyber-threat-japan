"""テキスト正規化・日付パースのユーティリティ。"""
import hashlib
import re
import unicodedata

from dateutil import parser as dateparser


def normalize_title(title: str) -> str:
    if not title:
        return ""
    t = unicodedata.normalize("NFKC", title).lower()
    t = re.sub(r"[\W_]+", "", t)  # 記号・空白除去
    return t


def parse_date_safe(value) -> str:
    """任意フォーマットの日付文字列をISO8601に正規化。失敗したらNoneを返す。"""
    if not value:
        return None
    try:
        dt = dateparser.parse(value)
        return dt.isoformat()
    except (ValueError, OverflowError, TypeError):
        return None


def make_dedup_key(cve_ids: list, title: str) -> str:
    """CVEがあればCVE基準、無ければ正規化タイトル基準でdedup_keyを作る。"""
    if cve_ids:
        basis = "cve:" + ",".join(sorted(cve_ids))
    else:
        basis = "title:" + normalize_title(title)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()