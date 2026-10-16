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
            cvss, cvss_version = _extract_cvss(cve)
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
                    extra={
                        "cve_ids": [cve_id],
                        "cvss": cvss,
                        # 2026-10監査Round3: cvssの値だけでなく「どのバージョン(手法)の
                        # CVSSか」「NVD上でいつ最終更新されたか」を併せて持ち回る。
                        # trust_levelが同じ複数ソース間でのCVSS競合時に、新しい/高
                        # バージョンの情報が古い/低バージョンの情報に上書きされないようにする
                        # (update.py::process_item()のマージロジックで使用)。
                        "cvss_version": cvss_version,
                        "cvss_as_of": cve.get("lastModified"),
                    },
                )
            )
        return items


def _extract_cvss(cve: dict):
    """CVSSのベーススコアと、それがどのバージョンのCVSSかを返す。

    戻り値: (base_score: float|None, version: str|None)

    2026-10監査Round4: 従来は cvssMetricV40(CVSS v4.0)を一切見ていなかった
    (v3.1 > v3.0 > v2 のみ)。NVD CVE API 2.0 の実レスポンスを確認した結果、
    cvssMetricV40 は既に存在し(例: CVE-2026-19820, CVE-2026-65643)、
    config/settings.py の CVSS_VERSION_RANK は元々4.0を最上位としていたにも
    関わらず、収集側がv4.0を一切拾っていなかったため、このランク付けが
    実質機能していなかった(確認済みの実装バグ)。v4.0 > v3.1 > v3.0 > v2 の
    優先順にする。

    また、同一バージョンの配列内に複数エントリが存在する場合がある
    (実例: CVE-2026-65643 は cvssMetricV31[0].type="Primary"/source=
    "nvd@nist.gov" と、別CVEのcvssMetricV40[0].type="Secondary"/source=
    "support@hackerone.com" のように、NVD自身の一次評価[Primary]と
    third-party[Secondary]が混在する)。従来は配列の先頭[0]を無条件に
    採用していたため、Secondaryしか無いバージョンがPrimaryより優先される
    経路があった。type=="Primary"のエントリを優先し、無ければ先頭にフォール
    バックする(Primaryが無いこと自体は珍しくないため、完全拒否はしない)。
    """
    metrics = cve.get("metrics", {})
    for key, version in (
        ("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"),
    ):
        arr = metrics.get(key)
        if arr:
            entry = next((e for e in arr if e.get("type") == "Primary"), arr[0])
            return entry["cvssData"].get("baseScore"), version
    return None, None