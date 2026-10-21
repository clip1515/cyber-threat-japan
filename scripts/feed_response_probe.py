"""Offline-only RSS response classifier; no HTTP client, DB, or publication.

A saved response body and caller-supplied HTTP status can be inspected locally.
Deliberately does not include response bodies, URLs, cookies, or headers in output.
"""
import argparse
import json
from pathlib import Path

import feedparser

MAX_BODY_BYTES = 2_000_000


def classify_response(status_code: int | None, body: bytes | None, content_type: str = "") -> dict:
    """Classify an already obtained response, never fetch it."""
    if status_code is None:
        return {"state": "transport_error", "entry_count": None, "format": None}
    if not 200 <= status_code < 300:
        return {"state": "http_error", "http_status": status_code,
                "entry_count": None, "format": None}
    if body is None or not body or len(body) > MAX_BODY_BYTES:
        return {"state": "invalid_feed", "entry_count": None, "format": None}

    # feedparser can recover invalid feeds. For an audit, only a recognized,
    # well-formed RSS/Atom response counts as valid; error pages do not.
    try:
        parsed = feedparser.parse(body)
    except Exception:
        return {"state": "invalid_feed", "entry_count": None, "format": None}
    version = str(parsed.get("version", "") or "")
    if not version or parsed.get("bozo"):
        return {"state": "invalid_feed", "entry_count": None, "format": version or None}
    entries = parsed.get("entries") or []
    if not isinstance(entries, list):
        return {"state": "invalid_feed", "entry_count": None, "format": version}
    return {"state": "valid_nonempty_feed" if entries else "valid_empty_feed",
            "entry_count": len(entries), "format": version}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Classify a saved feed response without network access")
    parser.add_argument("--body-file", type=Path, required=True,
                        help="Local saved RSS/Atom response (never fetched by this tool)")
    parser.add_argument("--status", type=int, required=True,
                        help="HTTP status from the saved response")
    args = parser.parse_args(argv)
    try:
        if args.body_file.stat().st_size > MAX_BODY_BYTES:
            raise ValueError("saved response exceeds offline probe size limit")
        body = args.body_file.read_bytes()
    except (OSError, ValueError) as exc:
        parser.error(f"Cannot read saved response: {type(exc).__name__}")
    print(json.dumps(classify_response(args.status, body), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
