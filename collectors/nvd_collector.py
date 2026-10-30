"""NVD CVE API 2.0 collector。直近更新されたCVEを取得する。

NVDは未認証だと厳しめのレート制限があるため、直近 lastModStartDate/lastModEndDate
の範囲(デフォルト過去8日)のみ取得する。API keyがあれば環境変数 NVD_API_KEY で渡せる。

結果は startIndex / resultsPerPage でページングされる(1ページ最大2000件)。totalResults に達するまで
全ページを取得し、各ページの totalResults・startIndex・件数を検証する。途中ページの取得失敗や応答の
矛盾(件数の変動・重複・空ページ)は取得失敗として扱い、一部だけを完全な収集結果として返さない。
ページ数の上限に達した場合は取得できた分を返し、incomplete に理由を残す(部分収集として通知される)。
上限を超えた分が次回の実行で回収される保証はない(同じ期間を再取得しても、どの範囲が返るかはNVDの
応答順に依存し、期間を超えて更新がなければ対象外になる)。回収方法は運用手順側で決める。
"""
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from collectors.base import BaseCollector, InvalidResponse, RawItem, http_get

logger = logging.getLogger("collectors")

PAGE_SIZE = 2000  # API 2.0 の resultsPerPage 上限
# 1回の取得上限(MAX_PAGES * PAGE_SIZE 件)。DBファイルを毎日commitするため、件数の増加を抑える安全側の値。
# 超えた場合は部分収集として記録・警告する。
MAX_PAGES = 1
# 公開されているレート制限(未認証: 30秒に5リクエスト、APIキーあり: 30秒に50リクエスト)に合わせたページ間隔。
PAGE_DELAY_SECONDS = 6.0
PAGE_DELAY_WITH_KEY_SECONDS = 0.6


class NvdCollector(BaseCollector):
    def __init__(self, source_conf: dict, days_back: int = 8, page_size: int = PAGE_SIZE,
                 max_pages: int = MAX_PAGES, page_delay: float = None):
        super().__init__(source_conf)
        self.days_back = days_back
        self.page_size = page_size
        self.max_pages = max_pages
        self.page_delay = page_delay

    def collect(self) -> list:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.days_back)
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000%z").replace("+0000", "Z"),
            "resultsPerPage": self.page_size,
        }
        headers = {}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        delay = self.page_delay
        if delay is None:
            delay = PAGE_DELAY_WITH_KEY_SECONDS if api_key else PAGE_DELAY_SECONDS

        vulnerabilities, seen_ids = [], set()
        next_index, total = 0, None
        for page in range(self.max_pages):
            if page:
                time.sleep(delay)
            data = http_get(self.url, params={**params, "startIndex": next_index}, headers=headers).json()
            page_vulns = _validated_page(data, next_index, total)
            total = data["totalResults"]
            for v in page_vulns:
                cve_id = v.get("cve", {}).get("id")
                if cve_id in seen_ids:
                    raise InvalidResponse(f"NVD returned {cve_id} on more than one page")
                seen_ids.add(cve_id)
            vulnerabilities.extend(page_vulns)
            next_index += len(page_vulns)
            if next_index >= total:
                break
        else:
            self.incomplete = (f"取得上限({self.max_pages}ページ・{self.max_pages * self.page_size}件)に達したため"
                               f"{total}件中{next_index}件のみ取得。残りは未取得")
            logger.warning("collector %s: %s", self.source_id, self.incomplete)

        items = []
        for v in vulnerabilities:
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


def _validated_page(data, expected_start: int, expected_total) -> list:
    """1ページ分の応答を検証し、vulnerabilities を返す。矛盾があれば InvalidResponse。"""
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulnerabilities, list):
        raise InvalidResponse("NVD response has no 'vulnerabilities' list")
    for key in ("totalResults", "startIndex", "resultsPerPage"):
        if type(data.get(key)) is not int or data[key] < 0:
            raise InvalidResponse(f"NVD response has no valid '{key}'")
    total, count = data["totalResults"], len(vulnerabilities)
    if data["startIndex"] != expected_start:
        raise InvalidResponse(f"NVD returned startIndex {data['startIndex']} for request {expected_start}")
    if expected_total is not None and total != expected_total:
        raise InvalidResponse(f"NVD totalResults changed between pages ({expected_total} -> {total})")
    if count > data["resultsPerPage"] or expected_start + count > total:
        raise InvalidResponse("NVD returned more results than its resultsPerPage/totalResults")
    if count == 0 and expected_start < total:
        raise InvalidResponse(f"NVD returned an empty page at {expected_start} of {total}")
    if not all(isinstance(v, dict) and isinstance(v.get("cve"), dict) for v in vulnerabilities):
        raise InvalidResponse("NVD response has a malformed vulnerability entry")
    return vulnerabilities


def _extract_cvss(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            return arr[0]["cvssData"].get("baseScore")
    return None
