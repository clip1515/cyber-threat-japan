"""Offline regression tests for source URLs reviewed against official feed links.

These tests mock all HTTP; they never fetch upstream feeds or run update.py.
Live reachability from GitHub Actions is deliberately not asserted.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from collectors.rss_collector import RssCollector


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "config" / "sources.yaml"


def source(source_id):
    entries = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))["sources"]
    return next(item for item in entries if item["id"] == source_id)


def test_ipa_uses_official_security_alert_rdf():
    conf = source("ipa_security")
    assert conf["url"] == "https://www.ipa.go.jp/security/alert-rss.rdf"
    # RDF/RSS 1.0 is a supported feed type; no network required.
    body = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
      xmlns="http://purl.org/rss/1.0/">
      <channel rdf:about="https://example.invalid/"><title>Security alerts</title>
        <link>https://example.invalid/</link><description>Test</description>
      </channel>
      <item rdf:about="https://example.invalid/alert">
        <title>Synthetic alert</title>
        <link>https://example.invalid/alert</link>
        <description>Fixture only</description>
      </item>
    </rdf:RDF>"""
    with patch("collectors.rss_collector.http_get",
               return_value=SimpleNamespace(content=body)):
        items = RssCollector(conf).collect()
    assert len(items) == 1
    assert items[0].title == "Synthetic alert"


def test_mandiant_uses_link_from_google_threat_intelligence_page():
    conf = source("mandiant_blog")
    assert conf["url"] == "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v"
    body = b"""<rss version="2.0"><channel>
    <title>Google Threat Intelligence</title>
    <link>https://cloud.google.com/blog/topics/threat-intelligence</link>
    <description>Fixture</description>
    <item><title>Synthetic advisory</title>
    <link>https://example.invalid/gtig</link>
    <description>Fixture only</description></item>
    </channel></rss>"""
    with patch("collectors.rss_collector.http_get",
               return_value=SimpleNamespace(content=body)):
        items = RssCollector(conf).collect()
    assert len(items) == 1
    assert items[0].source_id == "mandiant_blog"


def test_unverified_sources_are_not_rewritten():
    for source_id, expected in {
        "cisa_advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "msrc_blog": "https://msrc.microsoft.com/blog/feed",
    }.items():
        assert source(source_id)["url"] == expected


def test_trend_micro_newsroom_research_is_explicitly_scoped():
    conf = source("trendmicro_research")
    assert conf["url"] == (
        "https://newsroom.trendmicro.com/news-releases"
        "?pagetemplate=rss&category=787"
    )
    assert "Newsroom" in conf["name"]
    assert "Press Releases" in conf["name"]
    body = b"""<rss version="2.0"><channel><title>Trend Micro Newsroom (Research)</title>
    <link>https://newsroom.trendmicro.com/</link><description>Fixture</description>
    <item><title>Synthetic security research release</title>
    <link>https://example.invalid/trend-research</link></item></channel></rss>"""
    with patch("collectors.rss_collector.http_get",
               return_value=SimpleNamespace(content=body)):
        items = RssCollector(conf).collect()
    assert len(items) == 1
    assert items[0].source_id == "trendmicro_research"
