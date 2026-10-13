"""汎用RSS/Atom collector。config/sources.yaml の type: rss に対応する。"""
import logging
from datetime import datetime, timezone
import calendar

import feedparser

from collectors.base import BaseCollector, RawItem, http_get

logger = logging.getLogger("collectors")


class RssCollector(BaseCollector):
    def collect(self) -> list:
        # feedparserは自前でHTTP取得もできるが、User-Agent制御とタイムアウトのためrequestsで取得する。
        resp = http_get(self.url)
        parsed = feedparser.parse(resp.content)

        # 2026-10監査: msrc_blog(https://msrc.microsoft.com/blog/feed)が302で
        # フィードではないHTMLページにリダイレクトされており、HTTPとしては200
        # 成功・feedparserも例外を出さない(entries=[])ため、safe_collect()の
        # 例外ベースの失敗検知では一切検出できず、「正常に0件」として永久に
        # 埋もれていた。これはステータスコードからも例外からも分からないので、
        # ここで明示的にチェックしてログに残す(data/collector_health.jsonにも
        # last_error_detailとして反映される)。
        if not parsed.entries:
            final_url = getattr(resp, "url", self.url)
            if final_url != self.url:
                logger.warning(
                    "source %s: フィードURLがリダイレクトされ(%s → %s)、"
                    "0件でフィードとして解釈できなかった可能性があります。"
                    "URLの更新を検討してください。",
                    self.source_id, self.url, final_url,
                )
            elif getattr(parsed, "bozo", 0):
                logger.warning(
                    "source %s: フィードのパースに失敗(bozo_exception=%s)。"
                    "フィード形式が変更された可能性があります。",
                    self.source_id, getattr(parsed, "bozo_exception", "unknown"),
                )

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