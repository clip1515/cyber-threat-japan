"""Synthetic-only regression tests for scripts/feed_response_probe.py."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "feed_response_probe.py"
spec = importlib.util.spec_from_file_location("offline_feed_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

RSS_ITEM = b"""<rss version="2.0"><channel><title>Fixture</title>
<link>https://example.invalid/</link><description>Fixture</description>
<item><title>Advisory</title><link>https://example.invalid/item</link></item>
</channel></rss>"""
RSS_EMPTY = b"""<rss version="2.0"><channel><title>Fixture</title>
<link>https://example.invalid/</link><description>Fixture</description>
</channel></rss>"""
ATOM_EMPTY = b"""<feed xmlns="http://www.w3.org/2005/Atom">
<title>Fixture</title><id>urn:fixture:feed</id>
<updated>2026-10-21T00:00:00Z</updated></feed>"""
RDF_ITEM = b"""<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
xmlns="http://purl.org/rss/1.0/"><channel rdf:about="https://example.invalid/">
<title>Fixture</title><link>https://example.invalid/</link>
<description>Fixture</description></channel>
<item rdf:about="https://example.invalid/item">
<title>Advisory</title><link>https://example.invalid/item</link></item>
</rdf:RDF>"""


def test_http_status_is_distinct_from_feed_parsing():
    for code in (403, 404, 429, 500):
        result = probe.classify_response(code, RSS_ITEM)
        assert result["state"] == "http_error"
        assert result["http_status"] == code
        assert result["entry_count"] is None


def test_transport_error_is_distinct():
    assert probe.classify_response(None, None)["state"] == "transport_error"


def test_valid_rss_atom_rdf_with_and_without_entries():
    for body, expected in [(RSS_ITEM, "valid_nonempty_feed"),
                           (RDF_ITEM, "valid_nonempty_feed"),
                           (RSS_EMPTY, "valid_empty_feed"),
                           (ATOM_EMPTY, "valid_empty_feed")]:
        result = probe.classify_response(200, body)
        assert result["state"] == expected
        assert result["format"]


def test_invalid_200_html_is_not_a_valid_empty_feed():
    for body in (b"<html><body>Unavailable</body></html>", b"", b"not rss",
                 b"<rss><channel><title>truncated"):
        result = probe.classify_response(200, body)
        assert result["state"] == "invalid_feed"


def test_oversize_is_rejected_without_parsing():
    assert probe.classify_response(200, b"x" * (probe.MAX_BODY_BYTES + 1))["state"] == "invalid_feed"


def test_cli_reads_only_local_fixture_and_prints_metadata(tmp_path):
    body = tmp_path / "saved-response.xml"
    body.write_bytes(RSS_ITEM)
    run = subprocess.run([sys.executable, str(SCRIPT), "--body-file", str(body),
                          "--status", "200"], capture_output=True, text=True,
                         cwd=tmp_path, check=True)
    result = json.loads(run.stdout)
    assert result["state"] == "valid_nonempty_feed"
    assert result["entry_count"] == 1
    assert "example.invalid" not in run.stdout
    assert "Advisory" not in run.stdout
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "logs").exists()
