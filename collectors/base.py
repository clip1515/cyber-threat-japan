"""collectors共通のベースクラスとHTTPヘルパー。

安全上の制約: ここで行うのは公開されているRSS/JSON/APIへのGETリクエストのみ。
スキャン・認証回避・ペイロード送信等は一切行わない。
"""
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

import requests

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import HTTP_TIMEOUT_SECONDS, USER_AGENT

logger = logging.getLogger("collectors")


@dataclass
class RawItem:
    """collectorが返す、まだ解析前の生アイテム。"""
    source_id: str
    source_name: str
    source_trust_level: int
    title: str
    url: str
    published_at: Optional[str] = None   # ISO8601文字列 or None
    summary: str = ""
    raw_text: str = ""                    # CVE抽出等に使う本文(タイトル+summary+追加情報)
    extra: dict = field(default_factory=dict)  # collector固有の構造化情報(CVSS, KEV日付など)

    def raw_hash(self) -> str:
        h = hashlib.sha256()
        h.update((self.title + self.url + self.summary).encode("utf-8", errors="ignore"))
        return h.hexdigest()


def http_get(url: str, params: dict = None, headers: dict = None, timeout: int = None):
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    resp = requests.get(url, params=params, headers=hdrs, timeout=timeout or HTTP_TIMEOUT_SECONDS)
    resp.raise_for_status()
    return resp


class BaseCollector:
    """全collectorの基底クラス。サブクラスは collect() を実装する。"""

    def __init__(self, source_conf: dict):
        self.source_conf = source_conf
        self.source_id = source_conf["id"]
        self.source_name = source_conf["name"]
        self.trust_level = source_conf["trust_level"]
        self.url = source_conf["url"]

    def collect(self) -> list:
        raise NotImplementedError

    def safe_collect(self) -> list:
        """例外を握りつぶさずログに残しつつ、パイプライン全体は止めない。"""
        try:
            items = self.collect()
            logger.info("collected %d items from %s", len(items), self.source_id)
            return items
        except Exception as e:  # noqa: BLE001
            logger.warning("collector %s failed: %s", self.source_id, e)
            return []