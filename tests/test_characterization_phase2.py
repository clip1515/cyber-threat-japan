"""Characterization tests: pin the CURRENT dedup / severity / status / reporting behaviour.

These tests document how the code behaves at commit 05f7aab so that Phase 2 changes
are deliberate. A test marked "PHASE2-CHANGE" pins behaviour the Phase 2 design
intends to change; when that change lands, the test must be updated in the same
commit together with the reason. Finding IDs (F1..F14) refer to the Phase 2-A audit.

All writes go to in-memory SQLite (or a temporary file for the rollback test);
the production database is never opened.
"""
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parent.parent))

from analyzers.dedup import find_fuzzy_duplicate, title_similarity
from collectors.base import RawItem
from database import db
from reporting.daily_report import build_report_data
import update

PUB = "2026-10-01T00:00:00+00:00"


def make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def item(url, text="", title="Synthetic advisory", trust=2, published_at=PUB,
         summary="", **extra):
    return RawItem("synthetic", "Synthetic source", trust, title, url,
                   published_at=published_at, summary=summary,
                   raw_text=text or title, extra=extra)


class Base(unittest.TestCase):
    def setUp(self):
        self.conn = make_conn()

    def tearDown(self):
        self.conn.close()

    def process(self, *items, run_id=None):
        return [update.process_item(self.conn, i, run_id=run_id) for i in items]

    def incidents(self):
        return self.conn.execute("SELECT * FROM incidents ORDER BY id").fetchall()

    def history(self):
        return [tuple(r) for r in self.conn.execute(
            "SELECT incident_id, old_status, new_status FROM status_history ORDER BY id")]


class ArticleIdentity(Base):
    def test_c01_same_url_updates_same_incident(self):
        self.process(item("https://a.test/1", "first"), item("https://a.test/1", "second"))
        self.assertEqual(len(self.incidents()), 1)

    def test_c02_url_fragments_are_distinct_articles(self):
        # update.py:141 / db.py:100-111: exact URL match; fragments are part of identity
        # (JPCERT Weekly Report items differ only by fragment).
        self.process(item("https://a.test/wr.html#1", title="Weekly Report: A"),
                     item("https://a.test/wr.html#2", title="Weekly Report: A"))
        self.assertEqual(len(self.incidents()), 2)

    def test_c03_one_url_maps_to_one_incident(self):
        # F13 schema.sql:68-71: source_url is the PRIMARY KEY of incident_urls.
        cols = {r["name"]: r["pk"] for r in self.conn.execute("PRAGMA table_info(incident_urls)")}
        self.assertEqual(cols, {"source_url": 1, "incident_id": 0})


class CveMatching(Base):
    def test_c04_subject_and_mentioned_cves_are_unioned(self):
        # F1 update.py:135: collector metadata CVEs and body CVEs are merged.
        self.process(item("https://nvd.test/X", "CVE-2026-91001 differs from CVE-2026-91002",
                          cve_ids=["CVE-2026-91001"]))
        self.assertEqual(self.incidents()[0]["cve_ids"], "CVE-2026-91001,CVE-2026-91002")

    def test_c05_exact_cve_set_from_other_url_is_auto_merged(self):
        # PHASE2-CHANGE (policy 1): update.py:142-148 merges on exact CVE-set string match.
        self.process(item("https://a.test/1", "CVE-2026-91011 CVE-2026-91012"),
                     item("https://b.test/2", "CVE-2026-91012 CVE-2026-91011"))
        self.assertEqual(len(self.incidents()), 1)

    def test_c05b_url_keyed_incident_found_by_exact_cve_string(self):
        # update.py:142-148 is the only path for an incident whose dedup_key is URL-based
        # (created without CVEs) and which later gained CVEs.
        self.process(item("https://a.test/1", "no cve yet"),
                     item("https://a.test/1", "CVE-2026-91015"),
                     item("https://b.test/2", "CVE-2026-91015"))
        self.assertEqual(len(self.incidents()), 1)

    def test_c06_distinct_subject_cves_with_same_mentions_are_merged(self):
        # PHASE2-CHANGE (F2): two NVD-like records about different CVEs that mention
        # each other end up with identical cve_ids and are merged into one incident.
        self.process(
            item("https://nvd.test/A", "CVE-2026-91021 differs from CVE-2026-91022",
                 cve_ids=["CVE-2026-91021"]),
            item("https://nvd.test/B", "CVE-2026-91022 differs from CVE-2026-91021",
                 cve_ids=["CVE-2026-91022"]),
        )
        self.assertEqual(len(self.incidents()), 1)

    def test_c07_partial_and_superset_overlap_create_separate_incidents(self):
        # F2 update.py:152-153: a new CVE set gets a new dedup_key; no candidate is recorded.
        self.process(item("https://a.test/1", "CVE-2026-91031 CVE-2026-91032"),
                     item("https://b.test/2", "CVE-2026-91032"),
                     item("https://c.test/3", "CVE-2026-91032 CVE-2026-91033"))
        self.assertEqual([r["cve_ids"] for r in self.incidents()],
                         ["CVE-2026-91031,CVE-2026-91032", "CVE-2026-91032",
                          "CVE-2026-91032,CVE-2026-91033"])

    def test_c08_same_url_gaining_cves_keeps_identity_and_unions(self):
        # update.py:149-151
        self.process(item("https://a.test/1", "CVE-2026-91041"),
                     item("https://a.test/1", "CVE-2026-91041 CVE-2026-91042"))
        rows = self.incidents()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve_ids"], "CVE-2026-91041,CVE-2026-91042")


class TitleSimilarity(Base):
    def test_c09_similar_titles_without_cve_are_not_merged(self):
        # F3: find_fuzzy_duplicate is not called by process_item (update.py:154-156).
        self.process(item("https://a.test/1", title="Ransomware attack hits Osaka hospital"),
                     item("https://b.test/2", title="Ransomware attack hits Osaka hospital, systems down"))
        self.assertEqual(len(self.incidents()), 2)

    def test_c10_fuzzy_query_scans_real_sha256_keys(self):
        # F3 dedup.py:39-43: "LIKE 'title:%'" never matches real keys, but
        # "OR dedup_key IS NOT NULL" makes every row eligible anyway.
        self.process(item("https://a.test/1", title="Ransomware attack hits Osaka hospital"))
        key = self.incidents()[0]["dedup_key"]
        self.assertFalse(key.startswith("title:"))
        self.assertEqual(find_fuzzy_duplicate(
            self.conn, "Ransomware attack hits Osaka hospital!", PUB), key)

    def test_c11_missing_date_bypasses_date_window(self):
        # F4 dedup.py:46-52: the window is only applied when both dates exist.
        self.process(item("https://a.test/1", title="Ransomware attack hits Osaka hospital",
                          published_at=None))
        self.assertIsNotNone(find_fuzzy_duplicate(
            self.conn, "Ransomware attack hits Osaka hospital", "2020-01-01T00:00:00+00:00"))

    def test_c12_template_titles_exceed_threshold(self):
        # F5: JPCERT template titles about different products reach the 0.8 threshold.
        self.assertGreaterEqual(title_similarity("Weekly Report: OpenSSLに複数の脆弱性",
                                                 "Weekly Report: WordPressに複数の脆弱性"), 0.8)

    def test_c13_candidate_scan_is_limited_to_500_newest_rows(self):
        # F14 dedup.py:42: ORDER BY id DESC LIMIT 500.
        self.conn.execute("INSERT INTO incidents (dedup_key, title, published_at) VALUES "
                          "('old', 'Ransomware attack hits Osaka hospital', ?)", (PUB,))
        self.conn.executemany("INSERT INTO incidents (dedup_key, title, published_at) VALUES (?, ?, ?)",
                              [(f"k{i}", f"Unrelated filler {i}", PUB) for i in range(500)])
        self.assertIsNone(find_fuzzy_duplicate(self.conn, "Ransomware attack hits Osaka hospital", PUB))


class SeverityAndStatus(Base):
    def test_c14_unchanged_refetch_reactivates_closed_incident(self):
        # PHASE2-CHANGE (policy 3, F6) status.py:21-23.
        same = item("https://a.test/1", "CVE-2026-91051")
        self.process(same)
        self.conn.execute("UPDATE incidents SET status = 'CLOSED'")
        self.process(same)
        self.assertEqual(self.incidents()[0]["status"], "ACTIVE")
        self.assertEqual(self.history()[-1], (1, "CLOSED", "ACTIVE"))

    def test_c14b_unchanged_refetch_moves_mitigated_to_active(self):
        # PHASE2-CHANGE (policy 3): status.py:28-40 falls through to ACTIVE when the
        # refetched text has no mitigation keyword, even though nothing changed.
        same = item("https://a.test/1", "CVE-2026-91055")
        self.process(same)
        self.conn.execute("UPDATE incidents SET status = 'MITIGATED'")
        self.process(same)
        self.assertEqual(self.history()[-1], (1, "MITIGATED", "ACTIVE"))

    def test_c15_low_trust_keyword_escalates_severity(self):
        # PHASE2-CHANGE (F7) update.py:169, severity.py:105-106, status.py:25-26.
        self.process(item("https://primary.test/1", "CVE-2026-91061 bug", trust=1, cvss=5.0))
        self.assertEqual(self.incidents()[0]["severity"], "Medium")
        self.process(item("https://sns.test/1", "CVE-2026-91061 ransomware use claimed", trust=4))
        row = self.incidents()[0]
        self.assertEqual((row["severity"], row["status"]), ("High", "ESCALATED"))

    def test_c16_severity_never_decreases_after_denial(self):
        # PHASE2-CHANGE (F8) db.py:159-164, update.py:172-174.
        self.process(item("https://primary.test/1", "CVE-2026-91071 bug", trust=1, cvss=5.0),
                     item("https://sns.test/1", "CVE-2026-91071 ransomware use claimed", trust=4),
                     item("https://primary.test/1", "CVE-2026-91071 vendor: no ransomware use",
                          trust=1, cvss=5.0))
        self.assertEqual(self.incidents()[0]["severity"], "High")

    def test_c17_incident_kev_flag_is_sticky_or_aggregate(self):
        # F10 db.py:161: incident in_kev is max(); cves.in_kev is per metadata CVE only.
        self.process(item("https://kev.test/1", "CVE-2026-91081 CVE-2026-91082",
                          cve_ids=["CVE-2026-91081"], in_kev=True),
                     item("https://kev.test/1", "CVE-2026-91081 CVE-2026-91082",
                          cve_ids=["CVE-2026-91081"], in_kev=False))
        self.assertEqual(self.incidents()[0]["in_kev"], 1)
        self.assertEqual(dict(self.conn.execute("SELECT cve_id, in_kev FROM cves").fetchall()),
                         {"CVE-2026-91081": 1, "CVE-2026-91082": 0})

    def test_c18_confirmed_facts_follow_trust_level_only(self):
        # F11 update.py:87-92: trust 1 summary -> confirmed_facts, otherwise unconfirmed_info.
        self.process(item("https://p.test/1", "x", trust=1, summary="vendor says breached"),
                     item("https://m.test/2", "y", trust=3, summary="media says breached"))
        a, b = self.incidents()
        self.assertEqual((a["confirmed_facts"], a["unconfirmed_info"]), ("vendor says breached", None))
        self.assertEqual((b["confirmed_facts"], b["unconfirmed_info"]), (None, "media says breached"))


class Dates(Base):
    def test_c19_first_seen_at_is_first_article_publication(self):
        # F9 update.py:102: first_seen_at = published_at; db.py:179-183 never overwrites it.
        self.process(item("https://a.test/1", "CVE-2026-91091", published_at="2026-01-01T00:00:00+00:00"),
                     item("https://b.test/2", "CVE-2026-91091", trust=1,
                          published_at="2026-10-01T00:00:00+00:00"))
        row = self.incidents()[0]
        self.assertEqual(row["first_seen_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(row["published_at"], "2026-10-01T00:00:00+00:00")
        self.assertEqual(row["source_url"], "https://b.test/2")

    def test_c20_first_seen_at_falls_back_to_collection_time(self):
        before = datetime.now(timezone.utc)
        self.process(item("https://a.test/1", "x", published_at=None))
        first_seen = datetime.fromisoformat(self.incidents()[0]["first_seen_at"])
        self.assertGreaterEqual(first_seen, before)


class RunsAndReports(Base):
    def test_c21_unchanged_refetch_is_counted_as_update_and_touched(self):
        # PHASE2-CHANGE (policy 3, F12) update.py:200, db.py:175.
        same = item("https://a.test/1", "CVE-2026-91101", cvss=9.8)
        self.assertEqual(self.process(same, run_id=1), [True])
        self.assertEqual(self.process(same, run_id=2), [False])
        self.assertEqual(len(db.get_incidents_by_run(self.conn, 2)), 1)

    def test_c22_unchanged_refetch_of_critical_is_not_significant(self):
        # daily_report.py:132-137: significance uses new/escalated/victim/new-KEV only.
        same = item("https://a.test/1", "CVE-2026-91111", cvss=9.8)
        self.process(same, run_id=1)
        self.process(same, run_id=2)
        data = build_report_data(self.conn, 2)
        self.assertEqual([r["severity"] for r in data["critical_high"]], ["Critical"])
        self.assertFalse(data["significant_change"])

    def test_c23_kev_is_reported_only_in_first_kev_run(self):
        # db.py upsert_cve kev_first_seen_run_id; daily_report.py:99-104.
        kev = item("https://kev.test/1", "CVE-2026-91121", cve_ids=["CVE-2026-91121"], in_kev=True)
        self.process(kev, run_id=1)
        self.assertEqual(len(build_report_data(self.conn, 1)["kev_items"]), 1)
        self.process(kev, run_id=2)
        self.assertEqual(build_report_data(self.conn, 2)["kev_items"], [])

    def test_c24_iocs_are_deduplicated_per_incident(self):
        # schema.sql:80 UNIQUE(incident_id, ioc_type, ioc_value); first source_url kept.
        self.process(item("https://a.test/1", "CVE-2026-91131 203.0.113.7"),
                     item("https://b.test/2", "CVE-2026-91131 203.0.113.7"))
        rows = self.conn.execute("SELECT ioc_value, source_url FROM iocs").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("203.0.113.7", "https://a.test/1")])


class Atomicity(unittest.TestCase):
    def test_c25_failure_inside_item_rolls_back_all_item_writes(self):
        # update.py:272-273 + db.py:27-33: one connection per item, commit only on success.
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(db, "DB_PATH", Path(tmp) / "t.db"):
            db.init_db()
            with patch.object(db, "upsert_iocs", side_effect=RuntimeError("synthetic")):
                with self.assertRaises(RuntimeError):
                    with db.connection() as conn:
                        update.process_item(conn, item("https://a.test/1", "CVE-2026-91141 203.0.113.9"))
            with db.connection() as conn:
                counts = [conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                          for t in ("incidents", "incident_urls", "status_history", "iocs", "cves")]
            self.assertEqual(counts, [0, 0, 0, 0, 0])


if __name__ == "__main__":
    unittest.main()
