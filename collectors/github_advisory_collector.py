"""GitHub Security Advisories (GHSA) collector。

未認証でも直近のグローバルアドバイザリを取得できる(レート制限は低い)。
GITHUB_TOKEN環境変数があればレート制限が緩和される。
"""
import os

from collectors.base import BaseCollector, RawItem, http_get


class GithubAdvisoryCollector(BaseCollector):
    def __init__(self, source_conf: dict, per_page: int = 50):
        super().__init__(source_conf)
        self.per_page = per_page

    def collect(self) -> list:
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        params = {"per_page": self.per_page, "sort": "published", "direction": "desc"}
        resp = http_get(self.url, params=params, headers=headers)
        data = resp.json()
        items = []
        for a in data:
            cve_id = a.get("cve_id")
            title = a.get("summary", "")
            severity = a.get("severity", "")
            desc = a.get("description", "") or ""
            items.append(
                RawItem(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    source_trust_level=self.trust_level,
                    title=title or (cve_id or a.get("ghsa_id", "")),
                    url=a.get("html_url", ""),
                    published_at=a.get("published_at"),
                    summary=desc[:2000],
                    raw_text=f"{title}\n{desc}",
                    extra={"cve_ids": [cve_id] if cve_id else [], "github_severity": severity},
                )
            )
        return items