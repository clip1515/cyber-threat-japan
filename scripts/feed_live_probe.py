"""Bounded, read-only, one-shot HTTPS feed diagnostics for PR #10.

Never imports update.py, accesses SQLite, commits files, or sends notifications.
Explicitly configured public feed URLs only. No redirect following, auth,
cookies, retries, user-supplied URLs, content logging or artifact uploads.
"""
import json
from urllib.parse import urlparse

import requests
import yaml

from scripts.feed_response_probe import classify_response, MAX_BODY_BYTES

SOURCE_IDS = (
    "ipa_security",
    "mandiant_blog",
    "cisa_advisories",
    "trendmicro_research",
    "msrc_blog",
)
# No destinations outside of these reviewed endpoints.
ALLOWED = {
    "ipa_security": "https://www.ipa.go.jp/security/alert-rss.rdf",
    "mandiant_blog": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
    "cisa_advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "trendmicro_research": "https://www.trendmicro.com/en_us/research/rss.xml",
    "msrc_blog": "https://msrc.microsoft.com/blog/feed",
}


def _read_limited(response):
    chunks = []
    size = 0
    for chunk in response.iter_content(chunk_size=16384):
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def probe(source_id, url, transport=requests.get):
    """Make one GET to one verified HTTPS destination, never follow redirects."""
    if source_id not in ALLOWED or url != ALLOWED[source_id]:
        raise ValueError("Refusing unreviewed feed URL")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("Only reviewed HTTPS feeds allowed")
    try:
        with transport(url, timeout=(5, 12), allow_redirects=False,
                       stream=True, headers={
                           "User-Agent": "cyber-threat-japan-source-diagnostic/1.0",
                           "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
                       }) as response:
            status = response.status_code
            if 300 <= status < 400:
                # Never follow an external redirect. Do not print Location.
                return {"source": source_id, "state": "redirect", "http_status": status}
            if not 200 <= status < 300:
                result = classify_response(status, None)
            else:
                result = classify_response(status, _read_limited(response))
            result["source"] = source_id
            return result
    except requests.RequestException as exc:
        # Exception messages may contain host/user input. Do not print them.
        return {"source": source_id, "state": "transport_error",
                "error_type": type(exc).__name__}


def main():
    from pathlib import Path
    conf = yaml.safe_load((Path(__file__).resolve().parents[1] /
                           "config" / "sources.yaml").read_text(encoding="utf-8"))
    configs = {item["id"]: item["url"] for item in conf["sources"]}
    for source_id in SOURCE_IDS:
        print(json.dumps(probe(source_id, configs[source_id]),
                         ensure_ascii=False, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
