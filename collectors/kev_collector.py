"""CISA Known Exploited Vulnerabilities (KEV) カタログ collector。

JSON形式で公開されている一次情報。悪用確認済み脆弱性のリストなので、
severity判定・Japan Risk Scoreの「悪用確認済み」加点にそのまま使う。
"""
from collectors.base import BaseCollector, RawItem, http_get


class KevCollector(BaseCollector):
    def collect(self) -> list:
        resp = http_get(self.url)
        data = resp.json()
        items = []
        for v in data.get("vulnerabilities", []):
            cve_id = v.get("cveID", "")
            title = f"[KEV] {cve_id}: {v.get('vulnerabilityName', '')}"
            summary = v.get("shortDescription", "")
            items.append(
                RawItem(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    source_trust_level=self.trust_level,
                    title=title,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_at=_to_iso(v.get("dateAdded")),
                    summary=summary,
                    raw_text=f"{title}\n{summary}",
                    extra={
                        "cve_ids": [cve_id],
                        "in_kev": True,
                        "kev_date_added": v.get("dateAdded"),
                        "required_action": v.get("requiredAction"),
                        "due_date": v.get("dueDate"),
                        "known_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                    },
                )
            )
        return items


def _to_iso(date_str):
    if not date_str:
        return None
    # KEVの日付は YYYY-MM-DD 形式
    return f"{date_str}T00:00:00+00:00"