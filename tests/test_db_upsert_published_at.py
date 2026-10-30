"""Regression tests for published_at handling in database.db.upsert_incident.

All writes go to an in-memory SQLite database built from database/schema.sql;
the production DB is never opened.
"""
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import RawItem
from database import db
import update

KEY = "synthetic-dedup-key"
URL_A = "https://example.test/advisory-a"
URL_B = "https://example.test/advisory-b"
URL_C = "https://example.test/advisory-c"
URL_D = "https://example.test/advisory-d"
DATE_OLD = "2026-09-01T00:00:00+00:00"
DATE_NEW = "2026-09-15T00:00:00+00:00"


def make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def incident(url, published_at, trust=2, source_updated_at=None, **extra):
    return {
        "dedup_key": KEY,
        "title": "Synthetic advisory",
        "published_at": published_at,
        "source_updated_at": source_updated_at,
        "source_url": url,
        "source_name": "Synthetic source",
        "source_trust_level": trust,
        "severity": "Low",
        "status": "new",
        **extra,
    }


def raw_item(url, text, published_at=DATE_OLD):
    return RawItem("synthetic", "Synthetic source", 2, "Synthetic advisory", url,
                   published_at=published_at, raw_text=text)


class UpsertPublishedAtTest(unittest.TestCase):
    def setUp(self):
        self.conn = make_conn()
        db.upsert_incident(self.conn, incident(URL_A, DATE_OLD))

    def tearDown(self):
        self.conn.close()

    def row(self):
        rows = self.conn.execute("SELECT * FROM incidents").fetchall()
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_01_same_url_with_date_updates(self):
        db.upsert_incident(self.conn, incident(URL_A, DATE_NEW))
        self.assertEqual(self.row()["published_at"], DATE_NEW)

    def test_02_different_url_with_date_updates(self):
        db.upsert_incident(self.conn, incident(URL_B, DATE_NEW))
        row = self.row()
        self.assertEqual(row["published_at"], DATE_NEW)
        self.assertEqual(row["source_url"], URL_B)

    def test_03_different_url_without_date_keeps_existing(self):
        db.upsert_incident(self.conn, incident(URL_B, None))
        row = self.row()
        self.assertEqual(row["published_at"], DATE_OLD)
        self.assertEqual(row["source_url"], URL_B)

    def test_04_same_url_without_date_keeps_existing(self):
        db.upsert_incident(self.conn, incident(URL_A, None))
        self.assertEqual(self.row()["published_at"], DATE_OLD)

    def test_05_lower_trust_does_not_overwrite(self):
        db.upsert_incident(self.conn, incident(URL_B, DATE_NEW, trust=3))
        db.upsert_incident(self.conn, incident(URL_C, None, trust=3))
        row = self.row()
        self.assertEqual(row["published_at"], DATE_OLD)
        self.assertEqual(row["source_url"], URL_A)

    def test_06_new_incident_without_date_allows_null(self):
        new_id, is_new = db.upsert_incident(
            self.conn, {**incident(URL_D, None), "dedup_key": "another-key"})
        self.assertTrue(is_new)
        self.assertIsNone(db.get_incident(self.conn, new_id)["published_at"])

    def test_07_repeated_undated_different_urls_keep_existing(self):
        for url in (URL_B, URL_C, URL_D):
            db.upsert_incident(self.conn, incident(url, None))
        row = self.row()
        self.assertEqual(row["published_at"], DATE_OLD)
        self.assertEqual(row["source_url"], URL_D)

    def test_08_source_updated_at_still_resets_on_different_url(self):
        db.upsert_incident(self.conn, incident(URL_A, DATE_OLD, source_updated_at=DATE_NEW))
        self.assertEqual(self.row()["source_updated_at"], DATE_NEW)
        db.upsert_incident(self.conn, incident(URL_B, None))
        row = self.row()
        self.assertIsNone(row["source_updated_at"])
        self.assertEqual(row["published_at"], DATE_OLD)


class PipelineDedupTest(unittest.TestCase):
    """Current dedup behaviour through update.process_item, on an in-memory DB."""

    def setUp(self):
        self.conn = make_conn()

    def tearDown(self):
        self.conn.close()

    def count(self):
        return self.conn.execute("SELECT count(*) FROM incidents").fetchone()[0]

    def test_09_same_url_merges_into_one(self):
        update.process_item(self.conn, raw_item(URL_A, "Synthetic advisory"))
        update.process_item(self.conn, raw_item(URL_A, "Synthetic advisory revised"))
        self.assertEqual(self.count(), 1)

    def test_10_same_cve_different_url_merges_into_one(self):
        update.process_item(self.conn, raw_item(URL_A, "CVE-2026-90001"))
        update.process_item(self.conn, raw_item(URL_B, "CVE-2026-90001"))
        self.assertEqual(self.count(), 1)
        self.assertEqual(db.find_incident_by_url(self.conn, URL_A)["id"],
                         db.find_incident_by_url(self.conn, URL_B)["id"])

    def test_11_partially_overlapping_cves_stay_separate(self):
        update.process_item(self.conn, raw_item(URL_A, "CVE-2026-90001 CVE-2026-90002"))
        update.process_item(self.conn, raw_item(URL_B, "CVE-2026-90002 CVE-2026-90003"))
        self.assertEqual(self.count(), 2)


if __name__ == "__main__":
    unittest.main()
