"""URL normalization used only for candidate generation and collision checks.

The original URL stays the identity of an article. The normalized form must
never be used to merge articles on its own (see docs/phase2-data-model-design.md).
"""
from urllib.parse import urlsplit, urlunsplit

TRACKING_PARAMS = {"fbclid", "gclid", "mc_cid", "mc_eid"}
DEFAULT_PORTS = {"http": 80, "https": 443}


def _is_tracking(pair: str) -> bool:
    key = pair.split("=", 1)[0].lower()
    return key.startswith("utm_") or key in TRACKING_PARAMS


def normalize_url(url):
    """Lower-case scheme/host, drop default ports and tracking parameters.

    The fragment, path case, trailing slash and the order/encoding of the
    remaining query parameters are preserved: JPCERT Weekly Report items differ
    only by fragment. Unparseable input is returned stripped but otherwise as-is.
    """
    if url is None:
        return None
    raw = url.strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return raw
    if not parts.scheme or not parts.netloc or parts.hostname is None:
        return raw
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    userinfo = parts.netloc.rpartition("@")[0]
    netloc = (userinfo + "@" if userinfo else "") + host
    if port is not None and DEFAULT_PORTS.get(scheme) != port:
        netloc += f":{port}"
    query = "&".join(p for p in parts.query.split("&") if p and not _is_tracking(p))
    return urlunsplit((scheme, netloc, parts.path or "/", query, parts.fragment))
