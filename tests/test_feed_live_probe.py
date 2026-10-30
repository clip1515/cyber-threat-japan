"""Synthetic tests for the opt-in, HTTPS-only connectivity probe."""
from unittest.mock import Mock

import pytest
import requests

from scripts.feed_live_probe import ALLOWED, probe


class FakeResponse:
    def __init__(self, status, body=b"", location=None):
        self.status_code = status
        self.body = body
        self.headers = {"Location": location} if location else {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size=16384):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start:start+chunk_size]


RSS = b"""<rss version="2.0"><channel><title>Synthetic</title>
<link>https://example.invalid</link><description>Synthetic</description>
<item><title>Item</title><link>https://example.invalid/1</link></item>
</channel></rss>"""
EMPTY = b"""<rss version="2.0"><channel><title>Synthetic</title>
<link>https://example.invalid</link><description>Synthetic</description>
</channel></rss>"""


def mock_get(status, body=b"", location=None):
    fn = Mock(return_value=FakeResponse(status, body, location))
    return fn


def test_successful_feed_only_reports_count():
    transport = mock_get(200, RSS)
    result = probe("ipa_security", ALLOWED["ipa_security"], transport=transport)
    assert result["state"] == "valid_nonempty_feed"
    assert result["entry_count"] == 1
    assert "body" not in result and "url" not in result
    kwargs = transport.call_args.kwargs
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True


def test_successful_empty_feed_is_distinct_from_failure():
    result = probe("msrc_blog", ALLOWED["msrc_blog"], transport=mock_get(200, EMPTY))
    assert result["state"] == "valid_empty_feed"


@pytest.mark.parametrize("http_status", [403, 404, 429, 500])
def test_status_errors_are_reported_without_bodies(http_status):
    result = probe("cisa_advisories", ALLOWED["cisa_advisories"],
                   transport=mock_get(http_status, b"do not store"))
    assert result["state"] == "http_error"
    assert result["http_status"] == http_status
    assert "do not store" not in str(result)


def test_redirect_is_not_followed():
    transport = mock_get(302, location="https://unapproved.example/endpoint")
    result = probe("msrc_blog", ALLOWED["msrc_blog"], transport)
    assert result == {"source": "msrc_blog", "state": "redirect", "http_status": 302}
    assert transport.call_count == 1


def test_html_200_is_invalid_feed():
    result = probe("trendmicro_research", ALLOWED["trendmicro_research"],
                   transport=mock_get(200, b"<html>blocked</html>"))
    assert result["state"] == "invalid_feed"


def test_oversize_response_is_rejected():
    from scripts.feed_response_probe import MAX_BODY_BYTES
    result = probe("ipa_security", ALLOWED["ipa_security"],
                   transport=mock_get(200, b"x" * (MAX_BODY_BYTES+1)))
    assert result["state"] == "invalid_feed"


def test_reject_unreviewed_endpoint_before_http():
    network = Mock()
    with pytest.raises(ValueError, match="unreviewed"):
        probe("ipa_security", "https://attacker.example/collect", network)
    network.assert_not_called()


def test_transport_error_does_not_disclose_exception_details():
    def fail(*args, **kwargs):
        raise requests.exceptions.ConnectTimeout("sensitive-secret")
    result = probe("ipa_security", ALLOWED["ipa_security"], transport=fail)
    assert result == {"source": "ipa_security", "state": "transport_error",
                      "error_type": "ConnectTimeout"}
