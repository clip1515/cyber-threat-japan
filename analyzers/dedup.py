"""重複排除ロジック。

1. CVE番号が一致すれば同一事案 (parsers/normalizer.make_dedup_key が担当)
2. CVEが無い場合はタイトルの正規化+ファジーマッチ+日付近傍で同一事案候補を探す
"""
import sys
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import DEDUP_TITLE_SIMILARITY_THRESHOLD, DEDUP_DATE_WINDOW_DAYS
from parsers.normalizer import normalize_title


def title_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, normalize_title(a), normalize_title(b)).ratio()


def find_fuzzy_duplicate(conn, title: str, published_at: str):
    """CVEなしの新規記事について、既存incidentsの中から
    タイトル類似度としきい値・日付近傍で重複候補を探す。
    見つかればその incident の dedup_key を返す(=それに統合する)。
    """
    if not title:
        return None
    try:
        pub_dt = datetime.fromisoformat(published_at) if published_at else None
    except ValueError:
        pub_dt = None

    rows = conn.execute(
        "SELECT id, title, dedup_key, published_at FROM incidents "
        "WHERE dedup_key LIKE 'title:%' OR dedup_key IS NOT NULL "
        "ORDER BY id DESC LIMIT 500"
    ).fetchall()

    for row in rows:
        if pub_dt and row["published_at"]:
            try:
                other_dt = datetime.fromisoformat(row["published_at"])
                if abs((pub_dt - other_dt).days) > DEDUP_DATE_WINDOW_DAYS:
                    continue
            except ValueError:
                pass
        sim = title_similarity(title, row["title"])
        if sim >= DEDUP_TITLE_SIMILARITY_THRESHOLD:
            return row["dedup_key"]
    return None