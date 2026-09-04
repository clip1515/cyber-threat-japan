"""汎用RSS/Atom collector。config/sources.yaml の type: rss に対応する。"""
from datetime import datetime, timezone
import calendar

import feedparser

from collectors.base import BaseCollector, RawItem, http_get


class RssCollector(BaseCollector):
    def collect(self) -> list:
        # feedparserは自前でHTTP取得もできるが、User-Agent制御とタイムアウトのためrequestsで取得する。
        resp = http_get(self.url)
        parsed = feedparser.parse(resp.content)
        items = []
        for entry in parsed.entries:
            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()
            summary = entry.get("summary", "") or entry.get("description", "")
            published_at = _extract_date(entry)
            if not title or not link:
                continue
            items.append(
                RawItem(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    source_trust_level=self.trust_level,
                    title=title,
                    url=link,
                    published_at=published_at,
                    summary=summary,
                    raw_text=f"{title}\n{summary}",
                )
            )
        return items


def _extract_date(entry) -> str:
    for key in ("published_parsed", "updated_parsed"):
        val = entry.get(key)
        if val:
            ts = calendar.timegm(val)
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return None