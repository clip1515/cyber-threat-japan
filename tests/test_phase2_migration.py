"""Phase 2-C: additive schema and explicit migration.

Only synthetic data in in-memory or temporary-file SQLite is used. The
production database is never opened by these tests.
"""
import contextlib
import hashlib
import io
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import RawItem
from database import db
from database import migrate_phase2 as mig
from parsers.url_normalizer import normalize_url
import update

SOURCES = [
    ("cisa_kev", "CISA Known Exploited Vulnerabilities Catalog", 1),
    ("nvd_cve", "NVD CVE API 2.0", 1),
    ("jpcert_alert", "JPCERT/CC 注意喚起", 1),
    ("jpcert_all", "JPCERT/CC 全記事", 1),
    ("scan_netsecurity", "ScanNetSecurity", 3),
]
NAME = {sid: name for sid, name, _ in SOURCES}
PUB = "2026-10-01T00:00:00+00:00"
NVD_URL = "https://nvd.nist.gov/vuln/detail/CVE-2026-92001"
WR_URL = "https://www.jpcert.or.jp/wr/2026/wr261001.html#4"
COLLIDE_A = "HTTPS://Example.test:443/news?id=1&utm_source=feed"
COLLIDE_B = "https://example.test/news?id=1"


def legacy_schema(conn):
    conn.row_factory = sqlite3.Row
    conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.executemany("INSERT INTO sources (id, name, type, url, trust_level) VALUES (?, ?, 'rss', 'https://s.test', ?)",
                     SOURCES)
    conn.commit()


def raw(source_id, url, text="", title="Synthetic advisory", published_at=PUB, **extra):
    trust = dict((s, t) for s, _, t in SOURCES)[source_id]
    return RawItem(source_id, NAME[source_id], trust, title, url,
                   published_at=published_at, raw_text=text or title, extra=extra)


def populate(conn):
    """Legacy data produced by the real pipeline plus hand-made legacy edge cases."""
    run1 = db.start_run(conn)
    for item in (
        raw("cisa_kev", NVD_URL, "CVE-2026-92001", cve_ids=["CVE-2026-92001"], in_kev=True,
            kev_date_added="2026-09-30"),
        raw("nvd_cve", NVD_URL, "CVE-2026-92001", cve_ids=["CVE-2026-92001"], cvss=9.8),
        raw("jpcert_alert", WR_URL, title="Weekly Report: A"),
        raw("scan_netsecurity", "https://news.test/undated", title="Undated", published_at=None),
        raw("scan_netsecurity", COLLIDE_A, title="Collision A"),
        raw("scan_netsecurity", COLLIDE_B, title="Collision B"),
    ):
        update.process_item(conn, item, run_id=run1)
    # Legacy edge cases that the current pipeline can no longer create.
    conn.execute("INSERT INTO incidents (dedup_key, title, source_url) VALUES ('nourl-null', 'No URL', NULL)")
    conn.execute("INSERT INTO incidents (dedup_key, title, source_url) VALUES ('nourl-blank', 'Blank URL', '')")
    conn.execute("INSERT INTO incidents (dedup_key, title, source_url, source_name, source_trust_level) "
                 "VALUES ('shared-dup', 'Same URL, other feed', ?, ?, 1)", (WR_URL, NAME["jpcert_all"]))
    alias_owner = conn.execute("SELECT id FROM incidents WHERE source_url = ?", (COLLIDE_B,)).fetchone()[0]
    conn.execute("INSERT INTO incident_urls (source_url, incident_id) VALUES ('https://alias.test/old', ?)",
                 (alias_owner,))
    conn.commit()


def legacy_snapshot(conn):
    tables = {t: [tuple(r) for r in conn.execute(f"SELECT rowid, * FROM {t} ORDER BY rowid")]
              for t in mig.LEGACY_TABLES}
    tables["sqlite_sequence"] = [tuple(r) for r in conn.execute(
        "SELECT name, seq FROM sqlite_sequence WHERE name IN (%s) ORDER BY name"
        % ",".join("?" * len(mig.LEGACY_TABLES)), mig.LEGACY_TABLES)]
    return tables


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def user_version(conn):
    return conn.execute("PRAGMA user_version").fetchone()[0]


class MemoryCase(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        legacy_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def count(self, table, where="1"):
        return self.conn.execute(f"SELECT count(*) FROM {table} WHERE {where}").fetchone()[0]


class FileCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "legacy.db"
        conn = sqlite3.connect(self.path)
        legacy_schema(conn)
        populate(conn)
        conn.close()

    def tearDown(self):
        self._tmp.cleanup()

    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn


class T01SchemaCreation(MemoryCase):
    def test_empty_legacy_db_gets_all_tables_and_version(self):
        report = mig.migrate(self.conn)
        self.assertTrue(set(mig.PHASE2_TABLES) <= tables(self.conn))
        self.assertEqual(user_version(self.conn), 2)
        self.assertFalse(report["noop"])
        self.assertEqual(set(report["inserted"].values()), {0})
        self.assertEqual(self.count("phase2_migrations"), 1)
        self.assertEqual(self.conn.execute("PRAGMA quick_check").fetchone()[0], "ok")

    def test_refuses_db_without_legacy_tables(self):
        blank = sqlite3.connect(":memory:")
        with self.assertRaises(mig.MigrationError):
            mig.migrate(blank)
        self.assertEqual((tables(blank), user_version(blank)), (set(), 0))

    def test_refuses_open_transaction(self):
        self.conn.execute("INSERT INTO run_log (notes) VALUES ('pending')")
        self.assertTrue(self.conn.in_transaction)
        with self.assertRaises(mig.MigrationError):
            mig.migrate(self.conn)
        self.assertNotIn("articles", tables(self.conn))

    def test_refuses_existing_foreign_key_violations(self):
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self.conn.execute("INSERT INTO incident_urls (source_url, incident_id) VALUES ('https://x.test', 999)")
        self.conn.commit()
        with self.assertRaises(mig.MigrationError):
            mig.migrate(self.conn)
        self.assertNotIn("articles", tables(self.conn))


class T02Backfill(MemoryCase):
    def setUp(self):
        super().setUp()
        populate(self.conn)
        self.before = legacy_snapshot(self.conn)
        self.report = mig.migrate(self.conn)

    def article(self, url):
        return self.conn.execute("SELECT * FROM articles WHERE original_url = ?", (url,)).fetchone()

    def test_t06_legacy_rows_ids_and_content_unchanged(self):
        self.assertEqual(legacy_snapshot(self.conn), self.before)

    def test_every_legacy_url_is_an_article_and_linked(self):
        for url, incident_id in self.conn.execute("SELECT source_url, incident_id FROM incident_urls"):
            article = self.article(url)
            self.assertIsNotNone(article, url)
            self.assertEqual(self.count("incident_articles",
                                        f"incident_id = {incident_id} AND article_id = {article['id']}"), 1)
        self.assertEqual(self.count("incident_articles", "decided_by <> 'migration'"), 0)

    def test_alias_url_is_kept_without_invented_dates(self):
        alias = self.article("https://alias.test/old")
        self.assertEqual((alias["provenance"], alias["date_basis"], alias["published_at"]),
                         ("migrated_alias", "unknown", None))

    def test_shared_url_article_links_both_legacy_incidents(self):
        article = self.article(WR_URL)
        incidents = [r[0] for r in self.conn.execute(
            "SELECT incident_id FROM incident_articles WHERE article_id = ? ORDER BY 1", (article["id"],))]
        self.assertEqual(len(incidents), 2)
        sightings = {r[0] for r in self.conn.execute(
            "SELECT source_id FROM article_sightings WHERE article_id = ?", (article["id"],))}
        self.assertEqual(sightings, {"jpcert_alert", "jpcert_all"})
        self.assertEqual(self.report["shared_articles"], 1)

    def test_t07_null_published_at_stays_null(self):
        undated = self.article("https://news.test/undated")
        self.assertEqual((undated["published_at"], undated["date_basis"]), (None, "unknown"))
        dated = self.article(WR_URL)
        self.assertEqual((dated["published_at"], dated["date_basis"]), (PUB, "legacy_representative"))

    def test_t08_url_less_incidents_get_no_article_but_an_observation(self):
        ids = [r[0] for r in self.conn.execute(
            "SELECT id FROM incidents WHERE dedup_key IN ('nourl-null', 'nourl-blank') ORDER BY id")]
        self.assertEqual(self.report["url_less_incidents"], ids)
        for incident_id in ids:
            self.assertEqual(self.count("incident_articles", f"incident_id = {incident_id}"), 0)
            self.assertEqual(self.count("incident_observations", f"incident_id = {incident_id}"), 1)
        self.assertEqual(self.count("articles", "trim(original_url) = ''"), 0)

    def test_observations_use_created_at(self):
        self.assertEqual(self.count("incident_observations"), self.count("incidents"))
        mismatched = self.conn.execute(
            "SELECT count(*) FROM incident_observations o JOIN incidents i ON i.id = o.incident_id "
            "WHERE o.basis <> 'legacy_created_at' OR o.first_observed_at IS NOT i.created_at").fetchone()[0]
        self.assertEqual(mismatched, 0)

    def test_subject_cve_only_from_nvd_detail_url(self):
        rows = [tuple(r) for r in self.conn.execute(
            "SELECT a.original_url, c.cve_id, c.role FROM article_cves c JOIN articles a ON a.id = c.article_id")]
        self.assertEqual(rows, [(NVD_URL, "CVE-2026-92001", "subject")])

    def test_kev_evidence_from_cves_table(self):
        row = self.conn.execute("SELECT * FROM evidence").fetchone()
        self.assertEqual(self.count("evidence"), 1)
        self.assertEqual((row["cve_id"], row["claim"], row["statement_type"], row["source_role"],
                          row["verification"], row["published_at"], row["observed_basis"], row["provenance"]),
                         ("CVE-2026-92001", "kev_listed", "catalog_listing", "catalog",
                          "unverified", "2026-09-30", "run_log_kev_first_seen", "migrated_cves"))

    def test_t10_normalized_url_collision_is_reported_not_merged(self):
        a, b = self.article(COLLIDE_A), self.article(COLLIDE_B)
        self.assertNotEqual(a["id"], b["id"])
        self.assertEqual(a["normalized_url"], b["normalized_url"])
        self.assertIn(sorted([COLLIDE_A, COLLIDE_B]), [sorted(g) for g in self.report["normalized_url_collisions"]])
        owners = {r[0] for r in self.conn.execute(
            "SELECT incident_id FROM incident_articles WHERE article_id IN (?, ?)", (a["id"], b["id"]))}
        self.assertEqual(len(owners), 2)

    def test_t05_foreign_keys_hold_and_protect_history(self):
        self.assertEqual(self.conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO incident_articles (incident_id, article_id, link_reason, decided_by, "
                              "linked_at) VALUES (99999, 1, 'migrated', 'migration', 't')")
        linked = self.conn.execute("SELECT incident_id FROM incident_articles LIMIT 1").fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM incidents WHERE id = ?", (linked,))
        self.conn.rollback()

    def test_t12_report_and_log_record_versions(self):
        self.assertEqual((self.report["schema_version_before"], self.report["schema_version_after"]), (0, 2))
        log = self.conn.execute("SELECT * FROM phase2_migrations").fetchone()
        self.assertEqual(log["schema_version"], 2)
        self.assertEqual(log["legacy_fingerprint"], mig.legacy_fingerprint(self.conn)[0])


class T03Idempotency(FileCase):
    def test_second_run_is_a_byte_identical_noop(self):
        with contextlib.closing(self.connect()) as conn:
            mig.migrate(conn)
        after_first = file_sha(self.path)
        with contextlib.closing(self.connect()) as conn:
            report = mig.migrate(conn)
            self.assertEqual(conn.execute("SELECT count(*) FROM phase2_migrations").fetchone()[0], 1)
        self.assertTrue(report["noop"])
        self.assertEqual(set(report["inserted"].values()), {0})
        self.assertEqual(file_sha(self.path), after_first)

    def test_catch_up_inserts_only_rows_added_by_legacy_pipeline(self):
        with contextlib.closing(self.connect()) as conn:
            mig.migrate(conn)
            update.process_item(conn, raw("jpcert_alert", "https://new.test/1", title="New after migration"))
            conn.commit()
            report = mig.migrate(conn)
        self.assertFalse(report["noop"])
        self.assertEqual(report["inserted"], {
            "articles": 1, "article_revisions": 1, "article_sightings": 1, "incident_articles": 1,
            "article_cves": 0, "incident_observations": 1, "evidence": 0})


class T04Rollback(FileCase):
    def assert_untouched(self, before_sha):
        self.assertEqual(file_sha(self.path), before_sha)
        with contextlib.closing(self.connect()) as conn:
            self.assertEqual(user_version(conn), 0)
            self.assertNotIn("articles", tables(conn))

    def test_failure_after_each_step_rolls_back_everything(self):
        before = file_sha(self.path)
        for index, step in enumerate(mig.STEPS):
            def failing(conn, report, now, _step=step):
                _step(conn, report, now)  # let the step write first
                raise RuntimeError(f"synthetic failure after {_step.__name__}")
            steps = mig.STEPS[:index] + (failing,) + mig.STEPS[index + 1:]
            with self.subTest(step=step.__name__), patch.object(mig, "STEPS", steps):
                with contextlib.closing(self.connect()) as conn, self.assertRaises(RuntimeError):
                    mig.migrate(conn)
                self.assert_untouched(before)

    def test_failure_after_user_version_is_set_rolls_back_version(self):
        before = file_sha(self.path)
        with patch.object(mig.json, "dumps", side_effect=RuntimeError("log write failed")):
            with contextlib.closing(self.connect()) as conn, self.assertRaises(RuntimeError):
                mig.migrate(conn)
        self.assert_untouched(before)

    def test_negative_control_legacy_update_is_detected_and_rolled_back(self):
        before = file_sha(self.path)

        def tamper(conn, report, now):
            conn.execute("UPDATE incidents SET title = 'tampered' WHERE id = 1")
        with patch.object(mig, "STEPS", mig.STEPS + (tamper,)):
            with contextlib.closing(self.connect()) as conn, self.assertRaises(mig.MigrationError):
                mig.migrate(conn)
        self.assert_untouched(before)

    def test_negative_control_executescript_breaks_the_transaction(self):
        # Why the migration executes statements one by one.
        with contextlib.closing(sqlite3.connect(self.path, isolation_level=None)) as conn:
            conn.execute("BEGIN")
            conn.executescript("CREATE TABLE leaked (a);")
            self.assertFalse(conn.in_transaction)
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("ROLLBACK")
            self.assertIn("leaked", tables(conn))


class T09HistoryConstraints(MemoryCase):
    def setUp(self):
        super().setUp()
        populate(self.conn)
        mig.migrate(self.conn)
        self.article_id = self.conn.execute("SELECT id FROM articles WHERE original_url = ?",
                                            (WR_URL,)).fetchone()[0]
        self.incident_id = self.conn.execute("SELECT incident_id FROM incident_articles WHERE article_id = ? "
                                             "ORDER BY 1 LIMIT 1", (self.article_id,)).fetchone()[0]

    def revision(self, no, content_hash, kind):
        return self.conn.execute(
            "INSERT INTO article_revisions (article_id, revision_no, observed_at, content_hash, change_kind) "
            "VALUES (?, ?, 't', ?, ?)", (self.article_id, no, content_hash, kind)).lastrowid

    def evidence(self, polarity, revision_id, supersedes=None, claim="compromise", provenance="collected",
                 verification="unverified"):
        return self.conn.execute(
            "INSERT INTO evidence (incident_id, claim, polarity, statement_type, source_role, verification, "
            "article_revision_id, source_url, observed_at, observed_basis, supersedes_id, provenance) "
            "VALUES (?, ?, ?, 'first_party_statement', 'victim_org', ?, ?, ?, 't', 'collected', ?, ?)",
            (self.incident_id, claim, polarity, verification, revision_id, WR_URL, supersedes, provenance)
        ).lastrowid

    def test_revert_to_earlier_version_is_recorded(self):
        self.revision(2, "hash-B", "content")
        self.revision(3, "hash-A", "content")
        self.revision(4, "hash-B", "reverted")
        self.assertEqual(self.count("article_revisions", f"article_id = {self.article_id}"), 4)
        with self.assertRaises(sqlite3.IntegrityError):
            self.revision(4, "hash-C", "content")

    def test_negative_control_previous_design_blocked_reverts(self):
        self.conn.execute("CREATE TEMP TABLE old_revisions (article_id, content_hash, published_at, source_updated_at)")
        self.conn.execute("CREATE UNIQUE INDEX temp.ux_old ON old_revisions(article_id, COALESCE(content_hash,''), "
                          "COALESCE(published_at,''), COALESCE(source_updated_at,''))")
        for content in ("hash-A", "hash-B"):
            self.conn.execute("INSERT INTO old_revisions VALUES (1, ?, NULL, NULL)", (content,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO old_revisions VALUES (1, 'hash-A', NULL, NULL)")

    def test_history_tables_are_append_only(self):
        rev = self.revision(2, "hash-B", "content")
        ev = self.evidence("asserted", rev)
        for sql in ("UPDATE article_revisions SET content_hash = 'x' WHERE id = %d" % rev,
                    "DELETE FROM article_revisions WHERE id = %d" % rev,
                    "UPDATE evidence SET polarity = 'denied' WHERE id = %d" % ev,
                    "DELETE FROM evidence WHERE id = %d" % ev,
                    "DELETE FROM phase2_migrations"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(sql)

    def test_correction_chain_assert_deny_reassert(self):
        e1 = self.evidence("asserted", self.revision(2, "h2", "content"))
        e2 = self.evidence("denied", self.revision(3, "h3", "content"), supersedes=e1)
        e3 = self.evidence("asserted", self.revision(4, "h4", "content"), supersedes=e2)
        chain = [tuple(r) for r in self.conn.execute(
            "SELECT id, polarity, supersedes_id FROM evidence WHERE incident_id = ? ORDER BY id", (self.incident_id,))]
        self.assertEqual(chain, [(e1, "asserted", None), (e2, "denied", e1), (e3, "asserted", e2)])

    def test_reprocessing_same_revision_is_rejected(self):
        rev = self.revision(2, "h2", "content")
        self.evidence("asserted", rev)
        with self.assertRaises(sqlite3.IntegrityError):
            self.evidence("asserted", rev)

    def test_negative_control_previous_design_blocked_reassertion(self):
        self.conn.execute("CREATE TEMP TABLE old_evidence (incident_id, cve_id, claim, polarity, article_id, published_at)")
        self.conn.execute("CREATE UNIQUE INDEX temp.ux_old_ev ON old_evidence(COALESCE(incident_id,-1), "
                          "COALESCE(cve_id,''), claim, polarity, COALESCE(article_id,-1), COALESCE(published_at,''))")
        self.conn.execute("INSERT INTO old_evidence VALUES (1, NULL, 'compromise', 'asserted', 7, ?)", (PUB,))
        self.conn.execute("INSERT INTO old_evidence VALUES (1, NULL, 'compromise', 'denied', 7, ?)", (PUB,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO old_evidence VALUES (1, NULL, 'compromise', 'asserted', 7, ?)", (PUB,))

    def test_supersede_must_target_same_subject_and_claim(self):
        e1 = self.evidence("asserted", self.revision(2, "h2", "content"))
        with self.assertRaises(sqlite3.IntegrityError):
            self.evidence("denied", self.revision(3, "h3", "content"), supersedes=e1, claim="patch_available")

    def test_trust_alone_cannot_mark_evidence_verified(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.evidence("asserted", self.revision(2, "h2", "content"), verification="corroborated")
        with self.assertRaises(sqlite3.IntegrityError):
            self.evidence("asserted", None)  # collected evidence needs an article revision

    def test_candidate_constraints(self):
        a, b = sorted(r[0] for r in self.conn.execute("SELECT id FROM incidents LIMIT 2"))
        insert = ("INSERT INTO incident_candidates (incident_id, article_id, other_incident_id, reason, state, "
                  "created_at, decided_at, decided_by) VALUES (?, ?, ?, ?, ?, 't', ?, ?)")
        self.conn.execute(insert, (a, None, b, "subject_cve_partial", "open", None, None))
        rejected = [
            (b, None, a, "subject_cve_partial", "open", None, None),            # reversed pair
            (a, None, b, "subject_cve_partial", "open", None, None),            # duplicate
            (a, self.article_id, b, "title_similar", "open", None, None),       # both targets
            (a, None, None, "title_similar", "open", None, None),               # no target
            (a, self.article_id, None, "title_similar", "open", "t", "human"),  # open but decided
            (a, self.article_id, None, "title_similar", "accepted", "t", None), # decided without who
            (a, None, a, "title_similar", "open", None, None),                  # self pair
        ]
        for values in rejected:
            with self.subTest(values=values), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(insert, values)

    def test_incident_article_link_rules(self):
        other = self.conn.execute("SELECT id FROM incidents WHERE id <> ? LIMIT 1", (self.incident_id,)).fetchone()[0]
        new_article = self.conn.execute(
            "INSERT INTO articles (original_url, normalized_url, date_basis, recorded_at, provenance) "
            "VALUES ('https://n.test/x', 'https://n.test/x', 'collected', 't', 'collected')").lastrowid
        link = ("INSERT INTO incident_articles (incident_id, article_id, link_reason, decided_by, candidate_id, "
                "linked_at) VALUES (?, ?, ?, ?, ?, 't')")
        self.conn.execute(link, (self.incident_id, new_article, "created_incident", "auto", None))
        with self.assertRaises(sqlite3.IntegrityError):  # second automatic link for one article
            self.conn.execute(link, (other, new_article, "same_original_url", "auto", None))
        with self.assertRaises(sqlite3.IntegrityError):  # human link needs an approved candidate
            self.conn.execute(link, (other, new_article, "human_approved", "human", None))
        with self.assertRaises(sqlite3.IntegrityError):  # reason/decider mismatch
            self.conn.execute(link, (other, new_article, "migrated", "auto", None))

    def test_notification_and_assessment_constraints(self):
        self.conn.execute("INSERT INTO notification_events VALUES ('e1', NULL, 'escalated', 1, 't')")
        log = "INSERT INTO notification_log (event_key, channel, state, attempts, last_error) VALUES (?, ?, ?, ?, ?)"
        self.conn.execute(log, ("e1", "ntfy", "planned", 0, None))
        for values in (("e1", "ntfy", "planned", 0, None),   # duplicate channel row
                       ("e1", "email", "planned", 1, None),  # planned but attempted
                       ("e1", "email", "sent", 0, None),     # sent without attempt
                       ("e1", "email", "failed", 1, None),   # failure without error
                       ("e2", "email", "planned", 0, None)): # unknown event
            with self.subTest(values=values), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(log, values)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO assessment_history (incident_id, field, old_value, new_value, "
                              "evidence_ids, decided_by, changed_at) VALUES (?, 'severity', 'High', 'Low', '[]', "
                              "'human', 't')", (self.incident_id,))


class T10UrlNormalizer(unittest.TestCase):
    def test_rules(self):
        cases = {
            "HTTPS://Example.TEST:443/Path/?b=2&utm_source=x&a=1#Frag": "https://example.test/Path/?b=2&a=1#Frag",
            "http://example.test:80": "http://example.test/",
            "http://example.test:8080/x": "http://example.test:8080/x",
            "https://example.test/x?fbclid=1&GCLID=2": "https://example.test/x",
            "  https://example.test/x  ": "https://example.test/x",
            "https://www.jpcert.or.jp/wr/2026/wr261001.html#4": "https://www.jpcert.or.jp/wr/2026/wr261001.html#4",
            "https://[2001:DB8::1]:443/x": "https://[2001:db8::1]/x",
            "not a url": "not a url",
            "https://example.test:badport/x": "https://example.test:badport/x",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_url(value), expected)
        self.assertIsNone(normalize_url(None))

    def test_fragments_and_path_case_are_not_collapsed(self):
        self.assertNotEqual(normalize_url("https://a.test/wr.html#1"), normalize_url("https://a.test/wr.html#2"))
        self.assertNotEqual(normalize_url("https://a.test/A"), normalize_url("https://a.test/a"))


class T11Compatibility(FileCase):
    def test_legacy_init_db_and_pipeline_work_after_migration(self):
        with contextlib.closing(self.connect()) as conn:
            mig.migrate(conn)
            phase2_counts = {t: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in mig.PHASE2_TABLES}
        with patch.object(db, "DB_PATH", self.path):
            db.init_db()
            with db.connection() as conn:
                update.process_item(conn, raw("jpcert_all", "https://after.test/1", title="Legacy write"))
        with contextlib.closing(self.connect()) as conn:
            self.assertEqual(user_version(conn), 2)
            self.assertEqual({t: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                              for t in mig.PHASE2_TABLES}, phase2_counts)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_init_db_never_creates_phase2_tables(self):
        with patch.object(db, "DB_PATH", self.path):
            db.init_db()
        with contextlib.closing(self.connect()) as conn:
            self.assertFalse(set(mig.PHASE2_TABLES) & tables(conn))
            self.assertEqual(user_version(conn), 0)

    def test_unexpected_user_version_is_refused_without_changes(self):
        for version in (1, 3):
            with self.subTest(version=version):
                with contextlib.closing(sqlite3.connect(self.path)) as conn:
                    conn.execute(f"PRAGMA user_version = {version}")
                before = file_sha(self.path)
                with contextlib.closing(self.connect()) as conn, self.assertRaises(mig.MigrationError):
                    mig.migrate(conn)
                self.assertEqual(file_sha(self.path), before)


class T13Cli(FileCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = mig.main(list(args))
        return code, out.getvalue()

    def test_refuses_production_path_without_flag(self):
        before = file_sha(self.path)
        with patch.object(mig, "DB_PATH", self.path), self.assertRaises(SystemExit):
            self.run_cli("--db", str(self.path), "--backup", str(self.path) + ".bak")
        self.assertEqual(file_sha(self.path), before)
        self.assertFalse(Path(str(self.path) + ".bak").exists())

    def test_write_requires_new_backup(self):
        with self.assertRaises(SystemExit):
            self.run_cli("--db", str(self.path))
        existing = Path(self._tmp.name) / "exists.db"
        existing.write_bytes(b"keep")
        with self.assertRaises(SystemExit):
            self.run_cli("--db", str(self.path), "--backup", str(existing))
        self.assertEqual(existing.read_bytes(), b"keep")

    def test_dry_run_leaves_file_untouched(self):
        before = file_sha(self.path)
        code, out = self.run_cli("--db", str(self.path), "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn('"schema_version_after": 2', out)
        self.assertEqual(file_sha(self.path), before)

    def test_write_mode_backs_up_then_migrates(self):
        backup = Path(self._tmp.name) / "before.db"
        with contextlib.closing(self.connect()) as conn:
            original = mig.legacy_fingerprint(conn)[0]
        code, _ = self.run_cli("--db", str(self.path), "--backup", str(backup))
        self.assertEqual(code, 0)
        with contextlib.closing(sqlite3.connect(backup)) as conn:
            self.assertEqual((mig.legacy_fingerprint(conn)[0], user_version(conn)), (original, 0))
        with contextlib.closing(self.connect()) as conn:
            self.assertEqual((mig.legacy_fingerprint(conn)[0], user_version(conn)), (original, 2))


if __name__ == "__main__":
    unittest.main()
