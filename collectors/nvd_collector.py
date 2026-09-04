"""NVD CVE API 2.0 collector。直近更新されたCVEを取得する。

NVDは未認証だと厳しめのレート制限があるため、直近 lastModStartDate/lastModEndDate
の範囲(デフォルト過去8日)のみ取得する。API keyがあれば環境変数 NVD_API_KEY で渡せる。
"""
import os
from datetime import datetime, timedelta, timezone

from collectors.base import BaseCollector, RawItem, http_get


class NvdCollector(BaseCollector):
    def __init__(self, source_conf: dict, days_back: int = 8):
        super().__init__(source_conf)
        self.days_back = days_back

    def collect(self) -> list:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.days_back)
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z"),
            "resultsPerPage": 200,
        }
        headers = {}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key

        resp = http_get(self.url, params=params, headers=headers)
        data = resp.json()
        items = []
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            cvss = _extract_cvss(cve)
            title = f"{cve_id}"
            items.append(
                RawItem(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    source_trust_level=self.trust_level,
                    title=title,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_at=cve.get("published"),
                    summary=desc_en,
                    raw_text=f"{title}\n{desc_en}",
                    extra={"cve_ids": [cve_id], "cvss": cvss},
                )
            )
        return items


def _extract_cvss(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            return arr[0]["cvssData"].get("baseScore")
    return None