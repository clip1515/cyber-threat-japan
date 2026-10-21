"""Isolated database regression checks for the proposed feed URL transition.

Only synthetic RawItem objects and a pytest temporary SQLite database are
used. This deliberately does not invoke the daily runner or external URLs.
"""
from collectors.base import RawItem
from database import db
import update


def item(title, url, source_id, source_name, cve_ids=()):
    value = RawItem(
        source_id=source_id, source_name=source_name,
        source_trust_level=2, title=title, url=url,
        published_at="2026-10-21T00:00:00+00:00",
        summary="Synthetic evidence only",
        raw_text=title + " Synthetic evidence only",
        extra={"cve_ids": list(cve_ids)},
    )
    value.source_region = "global"
    return value


def test_same_article_url_remains_one_incident_across_source_renaming(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "threats.db")
    db.init_db()
    url = "https://example.invalid/news/research-advisory"
    old = item("Research advisory", url, "trendmicro_research", "Trend Micro Research")
    updated = item("Research advisory revised", url, "trendmicro_research",
                   "Trend Micro Newsroom - Research (Press Releases)")
    with db.connection() as conn:
        assert update.process_item(conn, old) is True
        assert update.process_item(conn, updated) is False
        assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


def test_same_cve_merges_even_if_article_url_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "threats.db")
    db.init_db()
    old = item("CVE-2026-12345 old research URL",
               "https://example.invalid/research/old",
               "trendmicro_research", "Trend Micro Research",
               ["CVE-2026-12345"])
    new = item("CVE-2026-12345 research announcement",
               "https://example.invalid/news/new",
               "trendmicro_research",
               "Trend Micro Newsroom - Research (Press Releases)",
               ["CVE-2026-12345"])
    with db.connection() as conn:
        assert update.process_item(conn, old) is True
        assert update.process_item(conn, new) is False
        assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


def test_without_cve_different_article_urls_are_not_silently_merged(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "threats.db")
    db.init_db()
    old = item("Security research bulletin", "https://example.invalid/old",
               "trendmicro_research", "Trend Micro Research")
    new = item("Security research bulletin", "https://example.invalid/new",
               "trendmicro_research", "Trend Micro Newsroom - Research (Press Releases)")
    with db.connection() as conn:
        assert update.process_item(conn, old) is True
        assert update.process_item(conn, new) is True
        assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 2
