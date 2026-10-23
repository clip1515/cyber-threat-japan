"""汎用RSS/Atom collector。config/sources.yaml の type: rss に対応する。"""
from datetime import datetime, timezone
import calendar
import logging
import re
from urllib.parse import urlsplit

import feedparser
from bs4 import BeautifulSoup

from collectors.base import BaseCollector, InvalidResponse, RawItem, http_get

logger = logging.getLogger("collectors")


class RssCollector(BaseCollector):
    def collect(self) -> list:
        # feedparserは自前でHTTP取得もできるが、User-Agent制御とタイムアウトのためrequestsで取得する。
        resp = http_get(self.url)
        parsed = feedparser.parse(resp.content)
        # HTMLのエラーページ等は例外にならず「0件」になるため、フィードとして認識できない応答は失敗とする。
        # 壊れていても記事を含むフィード(bozo=1 かつ entries あり)は取得できた記事を使う。
        if not parsed.get("version"):
            raise InvalidResponse("Response is not a recognized RSS/Atom feed")
        if parsed.bozo and not parsed.entries:
            raise InvalidResponse(f"Malformed feed with no entries: {type(parsed.get('bozo_exception')).__name__}")
        items = []
        for entry in parsed.entries:
            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()
            summary = entry.get("summary", "") or entry.get("description", "")
            published_at = _extract_date(entry)
            if not title or not link:
                continue
            item = RawItem(
                source_id=self.source_id,
                source_name=self.source_name,
                source_trust_level=self.trust_level,
                title=title,
                url=link,
                published_at=published_at,
                summary=summary,
                raw_text=f"{title}\n{summary}",
            )
            parts = urlsplit(link)
            if (parts.scheme == "https" and parts.netloc == "www.jpcert.or.jp"
                    and parts.path.startswith("/at/")):
                # These feeds use dc:date for revisions too. Do not label a
                # revision as the first publication when the article is absent.
                item.extra["source_updated_at"] = _extract_date(entry, ("updated_parsed",)) or published_at
                if "更新" in title and not entry.get("published_parsed"):
                    item.published_at = None
                try:
                    _enrich_jpcert_advisory(item)
                except Exception as exc:
                    # Keep the feed item if this individual article is unavailable.
                    logger.warning("article enrichment failed for %s: %s", link, exc)
            items.append(item)
        return items


def _enrich_jpcert_advisory(item):
    soup = BeautifulSoup(http_get(item.url).content, "html.parser")
    article = soup.select_one("article .at") or soup.find("article")
    if article is None:
        raise ValueError("JPCERT advisory body not found")
    for node in article.select("script, style, nav, footer"):
        node.decompose()
    text = article.get_text("\n", strip=True)
    # Only the header identifies first publication; revision history and other
    # advisory dates later in the text must not replace it.
    header = text.split("I. 概要", 1)[0]
    published = re.search(r"(\d{4}-\d{2}-\d{2})\s*[（(]公開[）)]", header)
    updated = re.findall(r"(\d{4}-\d{2}-\d{2})\s*[（(]更新[）)]", header)
    if published:
        item.published_at = published.group(1)  # Date precision: no invented time.
    if updated:
        item.extra["source_updated_at"] = updated[-1]
    item.raw_text += "\n" + text


def _extract_date(entry, keys=("published_parsed", "updated_parsed")) -> str:
    for key in keys:
        val = entry.get(key)
        if val:
            ts = calendar.timegm(val)
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return None
