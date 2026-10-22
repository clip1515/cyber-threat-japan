"""Regression tests for Codex's independent audit of 52645e0 (P1 x5, P2 x4).

Synthetic data, temporary SQLite/git, mock receivers only. No production code
is changed. ``Current*`` tests reproduce each finding against today's code or
the earlier reference/prototype; ``Spec*`` tests run the single Phase 2-E
protocol in tests/phase2_protocol.py (v3; v2 is kept frozen in
tests/phase2_reference.py) against hand-written expectations;
``Negative*`` tests run an unsafe variant and show the spec assertions fail.

Ground truth for delivery is the mock *receiver* (what it accepted), never the
ledger's own state, so the tests and the reference do not share an assumption.
"""
import contextlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.append(str(Path(__file__).resolve().parent.parent))

from database import db
from database import migrate_phase2 as mig
from reporting import daily_report
from reporting import notification_ledger as ledger
from tests import phase2_protocol as ref
from tests import test_phase2_p0_regressions as p0
from tests.test_phase2_migration import legacy_schema, raw
import update

NOW = "2026-10-22T00:00:00+00:00"
LATER = "2026-10-22T00:10:00+00:00"
LEASE = "2026-10-22T00:05:00+00:00"
KEV_B = "CVE-2026-97002"


def kev(cve, source="cisa_kev"):
    return raw(source, "https://nvd.nist.gov/vuln/detail/" + cve, cve, cve_ids=[cve], in_kev=True,
               kev_date_added="2026-10-01")


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def run(conn, items):
    run_id = db.start_run(conn)
    for i in items:
        update.process_item(conn, i, run_id=run_id)
    db.finish_run(conn, run_id, 1, 0, len(items), 0, 0, notes="synthetic")
    conn.commit()
    return run_id


class Receiver:
    """Mock receiving side. ``calls`` = sender invocations, ``accepted`` = what really arrived."""

    def __init__(self):
        self.calls, self.accepted = [], []

    def sender(self, channel, mode="ok", during=None):
        def send(message):
            self.calls.append((channel, message))
            if mode == "refuse":
                raise ConnectionRefusedError("refused before accept")
            if during:
                during()
            self.accepted.append((channel, message))
            if mode == "timeout_after_accept":
                raise TimeoutError("response lost after accept")
            if mode == "crash_after_accept":
                raise SystemExit("runner killed")
        return send

    def senders(self, **modes):
        return {c: self.sender(c, modes.get(c, "ok")) for c in ref.CHANNELS}

    def accepted_on(self, channel):
        return [m for c, m in self.accepted if c == channel]

    def calls_on(self, channel):
        return [m for c, m in self.calls if c == channel]


class Ledgered(unittest.TestCase):
    """A migrated DB with a baseline (existing KEV are not news) and the v2 lease columns."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "live.db"
        conn = sqlite3.connect(self.path)
        legacy_schema(conn)
        conn.close()
        with contextlib.closing(connect(self.path)) as conn:
            run(conn, [kev("CVE-2026-97001")])
            mig.migrate(conn)
            ledger.derive_events(conn, 0, NOW, baseline=True)
            ref.add_lease_columns(conn)
        self.receiver = Receiver()

    def tearDown(self):
        self._tmp.cleanup()

    def new_event(self, conn, cve=KEV_B):
        run_id = run(conn, [kev(cve)])
        return ledger.derive_events(conn, run_id, NOW)


# ---------------------------------------------------------------------------
# P1-1  ntfy sent, email failed, then DB restore: restore per channel
# ---------------------------------------------------------------------------

class P1ChannelRestore(Ledgered):
    def restore(self, rows):
        backup = self.dir / "restored.db"
        shutil.copy(self.dir / "backup.db", backup)
        with contextlib.closing(connect(backup)) as conn:
            if rows is not None:
                ref.import_channel_state(conn, rows, NOW)
        return backup

    def send_once(self, **modes):
        shutil.copy(self.path, self.dir / "backup.db")
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            ref.deliver(conn, self.receiver.senders(**modes), "runner-1", NOW, LEASE)
            return ref.export_channel_state(conn)

    def test_current_event_level_reimport_loses_failed_email(self):
        rows = self.send_once(email="refuse")
        restored = self.restore(None)
        with contextlib.closing(connect(restored)) as conn:  # the earlier reference recovery step
            conn.executemany("INSERT INTO notification_events (event_key, event_type, run_id, created_at) "
                             "VALUES (?, ?, 0, ?)", sorted({(r[0], r[1], NOW) for r in rows if r[3] == "sent"}))
            conn.commit()
            self.new_event(conn)
            ledger.deliver(conn, self.receiver.senders(), NOW)
        self.assertEqual(self.receiver.accepted_on("email"), [])  # email is lost for good

    def test_spec_channel_restore_retries_only_failed_email(self):
        rows = self.send_once(email="refuse")
        with contextlib.closing(connect(self.restore(rows))) as conn:
            self.assertEqual(self.new_event(conn), [])  # event already known after import
            ref.deliver(conn, self.receiver.senders(), "runner-2", NOW, LEASE)
        self.assertEqual(len(self.receiver.accepted_on("ntfy")), 1)
        self.assertEqual(len(self.receiver.accepted_on("email")), 1)

    def test_spec_both_channels_sent_restore_sends_nothing(self):
        rows = self.send_once()
        with contextlib.closing(connect(self.restore(rows))) as conn:
            self.new_event(conn)
            ref.deliver(conn, self.receiver.senders(), "runner-2", NOW, LEASE)
        self.assertEqual((len(self.receiver.accepted_on("ntfy")), len(self.receiver.accepted_on("email"))), (1, 1))

    def test_spec_in_flight_row_is_restored_as_unknown_and_resent_labelled(self):
        shutil.copy(self.path, self.dir / "backup.db")
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            ref.claim(conn, "runner-1", NOW, LEASE)  # runner dies before sending anything
            rows = ref.export_channel_state(conn)
        self.assertEqual({r[3] for r in rows}, {"sending"})
        with contextlib.closing(connect(self.restore(rows))) as conn:
            ref.deliver(conn, self.receiver.senders(), "runner-2", NOW, LEASE)
        self.assertTrue(all(m.startswith("[再送の可能性あり]") for _, m in self.receiver.accepted))

    def test_negative_event_level_restore_fails_spec(self):
        rows = self.send_once(email="refuse")
        restored = self.restore(None)
        with contextlib.closing(connect(restored)) as conn:
            conn.executemany("INSERT INTO notification_events (event_key, event_type, run_id, created_at) "
                             "VALUES (?, ?, 0, ?)", sorted({(r[0], r[1], NOW) for r in rows}))
            conn.commit()
            ref.deliver(conn, self.receiver.senders(), "runner-2", NOW, LEASE)
        with self.assertRaises(AssertionError):
            self.assertEqual(len(self.receiver.accepted_on("email")), 1)


# ---------------------------------------------------------------------------
# P1-2  published-history guard must fail closed
# ---------------------------------------------------------------------------

class History(unittest.TestCase):
    """Three published runs whose archives are written by the production report generator."""

    STARTS = ["2026-10-01 00:30:00", "2026-10-02 00:30:00", "2026-10-03 00:30:00"]

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.repo = self.dir / "repo"
        (self.repo / "data").mkdir(parents=True)
        self.db = self.repo / "data/threat_intel.db"
        conn = sqlite3.connect(self.db)
        legacy_schema(conn)
        conn.close()

    def tearDown(self):
        self._tmp.cleanup()

    def publish_runs(self, starts):
        for start in starts:
            with contextlib.closing(connect(self.db)) as conn:
                run_id = run(conn, [raw("jpcert_alert", f"https://rss.test/{start}", title=f"Run at {start}")])
                conn.execute("UPDATE run_log SET started_at = ?, finished_at = ? WHERE id = ?",
                             (start, start.replace("00:30:00", "00:31:00"), run_id))
                conn.commit()
                meta = dict(conn.execute("SELECT * FROM run_log WHERE id = ?", (run_id,)).fetchone())
                with patch.object(daily_report, "REPORTS_DIR", self.repo / "reports"), \
                        patch.object(daily_report, "DAILY_REPORT_PATH", self.repo / "daily_report.md"):
                    daily_report.generate_and_save(conn, run_id, meta)
            if run_id == 1:
                shutil.copy(self.db, self.dir / "after_run1.db")

    def check(self):
        with contextlib.closing(connect(self.db)) as conn:
            return ref.history_check(self.repo, conn)

    def archives(self):
        return sorted((self.repo / "reports").glob("daily_report_*.md"))


class P1HistoryGuard(History):
    def test_current_old_guard_fails_open(self):
        self.publish_runs(self.STARTS)
        shutil.copy(self.dir / "after_run1.db", self.db)
        shutil.rmtree(self.repo / "reports")
        with contextlib.closing(connect(self.db)) as conn:
            self.assertFalse(p0.old_db_is_behind(p0.old_published_history_check(self.repo, conn)))

    def test_spec_initial_empty_state_is_legitimate(self):
        result = self.check()
        self.assertEqual((result["ok"], result["state"]), (True, "initial"))

    def test_spec_consistent_history_passes(self):
        self.publish_runs(self.STARTS)
        result = self.check()
        self.assertEqual((result["ok"], result["max_published"], result["db_seq"]), (True, 3, 3))

    def test_spec_missing_or_empty_archive_with_runs_fails_closed(self):
        self.publish_runs(self.STARTS)
        for setup in ("missing", "empty"):
            with self.subTest(setup=setup):
                shutil.rmtree(self.repo / "reports", ignore_errors=True)
                if setup == "empty":
                    (self.repo / "reports").mkdir()
                result = self.check()
                self.assertFalse(result["ok"])
                self.assertIn("archive_missing_or_empty_but_db_has_runs", result["reasons"])

    def test_spec_malformed_or_corrupt_archive_fails_closed(self):
        self.publish_runs(self.STARTS)
        first, second, third = self.archives()
        cases = {
            "malformed_name": lambda: first.rename(first.with_name("daily_report_2026-10-01_RUN1.md")),
            "header_removed": lambda: second.write_text("# truncated\n", encoding="utf-8"),
            "id_mismatch": lambda: third.write_text(third.read_text(encoding="utf-8").replace(
                "(run_id=3)", "(run_id=9)"), encoding="utf-8"),
            "not_utf8": lambda: second.write_bytes(b"\xff\xfe\x00broken"),
        }
        for name, corrupt in cases.items():
            with self.subTest(case=name):
                shutil.rmtree(self.repo / "reports")
                (self.repo / "reports").mkdir()
                self.publish_archives_again()
                first, second, third = self.archives()
                corrupt()
                self.assertFalse(self.check()["ok"])

    def publish_archives_again(self):
        with contextlib.closing(connect(self.db)) as conn:
            for row in conn.execute("SELECT * FROM run_log ORDER BY id").fetchall():
                with patch.object(daily_report, "REPORTS_DIR", self.repo / "reports"), \
                        patch.object(daily_report, "DAILY_REPORT_PATH", self.repo / "daily_report.md"):
                    daily_report.generate_and_save(conn, row["id"], dict(row))

    def test_spec_restored_db_behind_and_missing_runs(self):
        self.publish_runs(self.STARTS)
        shutil.copy(self.dir / "after_run1.db", self.db)
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing_runs"], [2, 3])
        self.assertIn("db_behind_published_history", result["reasons"])

    def test_spec_run_id_reuse_is_detected_from_archive_content(self):
        self.publish_runs(self.STARTS)
        shutil.copy(self.dir / "after_run1.db", self.db)
        with contextlib.closing(connect(self.db)) as conn:  # two new runs reuse ids 2 and 3
            for _ in range(2):
                run(conn, [raw("jpcert_alert", "https://rss.test/later", title="After restore")])
        result = self.check()
        self.assertEqual((result["db_seq"], result["max_published"], result["missing_runs"]), (3, 3, []))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reused_runs"], [2, 3])

    def test_limit_filename_alone_cannot_prove_same_day_reuse(self):
        self.publish_runs(self.STARTS)
        with contextlib.closing(connect(self.db)) as conn:  # same date, different time
            conn.execute("UPDATE run_log SET started_at = '2026-10-03 18:00:00' WHERE id = 3")
            conn.commit()
            self.assertEqual(ref.filename_only_reuse_check(self.repo, conn), [])
        self.assertEqual(self.check()["reused_runs"], [3])

    def test_limit_identical_start_second_is_not_provable(self):
        """Documented limit: a reused run started in the same second cannot be told apart."""
        self.publish_runs(self.STARTS)
        result = self.check()  # nothing distinguishes it; the guard must not claim more
        self.assertTrue(result["ok"])

    def test_negative_old_guard_fails_spec_cases(self):
        self.publish_runs(self.STARTS)
        shutil.copy(self.dir / "after_run1.db", self.db)
        with contextlib.closing(connect(self.db)) as conn:
            for _ in range(2):
                run(conn, [raw("jpcert_alert", "https://rss.test/later", title="After restore")])
            old = p0.old_published_history_check(self.repo, conn)
        with self.assertRaises(AssertionError):
            self.assertTrue(p0.old_db_is_behind(old))


# ---------------------------------------------------------------------------
# P1-3  CVSS events keyed by observation, not by score
# ---------------------------------------------------------------------------

OSCILLATION = [("nvd-2026-10-01", 9.1), ("nvd-2026-10-02", 7.0), ("nvd-2026-10-03", 9.1),
               ("nvd-2026-10-04", 7.0), ("nvd-2026-10-05", 9.1)]


class P1CvssObservations(unittest.TestCase):
    def test_current_old_keys_collide(self):
        keys = [k for k, _ in p0.old_cvss_events("CVE-X", [s for _, s in OSCILLATION])]
        self.assertEqual((len(keys), len(set(keys))), (5, 3))

    def test_spec_oscillation_has_five_distinct_events(self):
        history, events = ref.cvss_events("CVE-X", OSCILLATION)
        expected = [("first_critical", "nvd-2026-10-01"), ("downgrade", "nvd-2026-10-02"),
                    ("re_critical", "nvd-2026-10-03"), ("downgrade", "nvd-2026-10-04"),
                    ("re_critical", "nvd-2026-10-05")]
        self.assertEqual([(kind, key.rsplit(":obs:", 1)[1]) for key, kind, _ in events], expected)
        self.assertEqual(len({key for key, _, _ in events}), 5)
        self.assertEqual(len(history), 5)

    def test_spec_recollecting_same_observation_is_idempotent(self):
        recollected = OSCILLATION[:3] + [OSCILLATION[2], OSCILLATION[1]] + OSCILLATION[3:]
        self.assertEqual(ref.cvss_events("CVE-X", recollected), ref.cvss_events("CVE-X", OSCILLATION))

    def test_spec_same_score_new_observation_is_history_not_alert(self):
        history, events = ref.cvss_events("CVE-X", [("o1", 9.1), ("o2", 9.1)])
        self.assertEqual(history, [("o1", 9.1), ("o2", 9.1)])
        self.assertEqual([kind for _, kind, _ in events], ["first_critical"])

    def test_spec_no_observations_means_no_invented_history(self):
        self.assertEqual(ref.cvss_events("CVE-X", []), ([], []))

    def test_spec_events_survive_ledger_insertion_without_collision(self):
        conn = sqlite3.connect(":memory:")
        legacy_schema(conn)
        mig.migrate(conn)
        _, events = ref.cvss_events("CVE-X", OSCILLATION)
        for _ in range(2):  # derived twice: second pass inserts nothing
            for key, kind, _ in events:
                conn.execute("INSERT OR IGNORE INTO notification_events (event_key, event_type, run_id, created_at) "
                             "VALUES (?, ?, 1, ?)", (key, f"cvss_{kind}", NOW))
        self.assertEqual(conn.execute("SELECT count(*) FROM notification_events").fetchone()[0], 5)

    def test_negative_score_keyed_events_fail_spec(self):
        keys = [k for k, _ in p0.old_cvss_events("CVE-X", [s for _, s in OSCILLATION])]
        with self.assertRaises(AssertionError):
            self.assertEqual(len(set(keys)), 5)


# ---------------------------------------------------------------------------
# P1-4  receiver accepted, response lost: unknown, never an unlabelled resend
# ---------------------------------------------------------------------------

class P1AmbiguousTimeout(Ledgered):
    def test_current_prototype_marks_failed_and_resends_unlabelled(self):
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            ledger.deliver(conn, self.receiver.senders(ntfy="timeout_after_accept"), NOW)
            self.assertEqual(conn.execute("SELECT state FROM notification_log WHERE channel = 'ntfy'"
                                          ).fetchone()[0], "failed")
            ledger.deliver(conn, self.receiver.senders(), NOW)
        second = self.receiver.accepted_on("ntfy")[1]
        self.assertNotIn("再送の可能性", second)

    def test_spec_timeout_is_unknown_and_resend_is_labelled(self):
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            ref.deliver(conn, self.receiver.senders(ntfy="timeout_after_accept"), "r1", NOW, LEASE)
            self.assertEqual(conn.execute("SELECT state FROM notification_log WHERE channel = 'ntfy'"
                                          ).fetchone()[0], "unknown")
            ref.deliver(conn, self.receiver.senders(), "r2", NOW, LEASE)
        ntfy = self.receiver.accepted_on("ntfy")
        self.assertEqual(len(ntfy), 2)
        self.assertIn("再送の可能性", ntfy[1])

    def test_spec_refused_before_accept_is_failed_and_retried_plainly(self):
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            ref.deliver(conn, self.receiver.senders(email="refuse"), "r1", NOW, LEASE)
            self.assertEqual(conn.execute("SELECT state FROM notification_log WHERE channel = 'email'"
                                          ).fetchone()[0], "failed")
            ref.deliver(conn, self.receiver.senders(), "r2", NOW, LEASE)
        self.assertEqual(len(self.receiver.accepted_on("email")), 1)
        self.assertNotIn("再送の可能性", self.receiver.accepted_on("email")[0])

    def test_negative_treating_every_error_as_definite_fails_spec(self):
        with patch.object(ref, "DEFINITE_FAILURES", (Exception,)), contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            ref.deliver(conn, self.receiver.senders(ntfy="timeout_after_accept"), "r1", NOW, LEASE)
            ref.deliver(conn, self.receiver.senders(), "r2", NOW, LEASE)
        with self.assertRaises(AssertionError):
            self.assertIn("再送の可能性", self.receiver.accepted_on("ntfy")[1])


# ---------------------------------------------------------------------------
# P1-5  two deliverers on one ledger: ownership, lease, attempts
# ---------------------------------------------------------------------------

class P1ConcurrentDeliverers(Ledgered):
    def setUp(self):
        super().setUp()
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
        self.a, self.b = connect(self.path), connect(self.path)

    def tearDown(self):
        self.a.close()
        self.b.close()
        super().tearDown()

    def attempts(self, channel):
        return self.a.execute("SELECT attempts FROM notification_log WHERE channel = ?", (channel,)).fetchone()[0]

    def test_current_prototype_second_deliverer_steals_live_row(self):
        senders = self.receiver.senders()
        senders["ntfy"] = self.receiver.sender(
            "ntfy", during=lambda: ledger.deliver(self.b, self.receiver.senders(), NOW))
        ledger.deliver(self.a, senders, NOW)
        self.assertEqual(len(self.receiver.accepted_on("ntfy")), 2)

    def test_spec_live_lease_is_not_touched_by_other_deliverer(self):
        seen = {}

        def b_runs_while_a_sends():
            seen["b"] = ref.deliver(self.b, self.receiver.senders(), "B", NOW, LEASE)
        senders = self.receiver.senders()
        senders["ntfy"] = self.receiver.sender("ntfy", during=b_runs_while_a_sends)
        ref.deliver(self.a, senders, "A", NOW, LEASE)
        self.assertNotIn((f"cve:{KEV_B}:kev_listed", "ntfy"), seen["b"]["sent"])
        self.assertEqual(len(self.receiver.accepted_on("ntfy")), 1)
        self.assertEqual(len(self.receiver.accepted_on("email")), 1)
        for channel in ref.CHANNELS:  # attempts == real sender invocations
            self.assertEqual(self.attempts(channel), len(self.receiver.calls_on(channel)))

    def test_spec_other_deliverer_cannot_finalize_live_row(self):
        ref.claim(self.a, "A", NOW, LEASE)
        row = self.a.execute("SELECT id FROM notification_log WHERE channel = 'ntfy'").fetchone()[0]
        self.assertFalse(ref.finalize(self.b, row, "B", "sent"))
        self.assertEqual(self.b.execute("SELECT state, owner FROM notification_log WHERE id = ?",
                                        (row,)).fetchone()[:], ("sending", "A"))

    def test_spec_expired_lease_is_reclaimed_as_unknown_and_late_owner_is_ignored(self):
        senders = self.receiver.senders()
        senders["ntfy"] = self.receiver.sender("ntfy", mode="crash_after_accept")
        with self.assertRaises(SystemExit):
            ref.deliver(self.a, senders, "A", NOW, LEASE)
        row = self.a.execute("SELECT id FROM notification_log WHERE channel = 'ntfy'").fetchone()[0]
        early = ref.deliver(self.b, self.receiver.senders(), "B", NOW, LEASE)  # lease still valid
        self.assertNotIn((f"cve:{KEV_B}:kev_listed", "ntfy"), early["sent"])
        ref.deliver(self.b, self.receiver.senders(), "B", LATER, "2026-10-22T00:15:00+00:00")
        ntfy = self.receiver.accepted_on("ntfy")
        self.assertEqual(len(ntfy), 2)
        self.assertIn("再送の可能性", ntfy[1])
        self.assertFalse(ref.finalize(self.a, row, "A", "failed", "late"))  # A comes back too late
        self.assertEqual(self.a.execute("SELECT state FROM notification_log WHERE id = ?", (row,)).fetchone()[0],
                         "sent")
        self.assertEqual(self.attempts("ntfy"), len(self.receiver.calls_on("ntfy")))

    def test_negative_claim_without_ownership_check_duplicates(self):
        def unsafe_claim(conn, owner, now, lease_until, max_attempts=ref.MAX_ATTEMPTS, *_):
            # Like the prototype: every 'sending' row is assumed stale, whoever owns it.
            conn.execute("UPDATE notification_log SET state = 'unknown', owner = NULL, token = NULL "
                         "WHERE state = 'sending'")
            conn.commit()
            rows = conn.execute("SELECT id FROM notification_log WHERE state IN ('planned','failed','unknown')"
                                ).fetchall()
            claimed = []
            for (row_id,) in rows:
                token = f"unsafe:{row_id}:{owner}"
                conn.execute("UPDATE notification_log SET state = 'sending', owner = ?, token = ?, "
                             "lease_until_us = ?, send_started = 0, attempts = attempts + 1 WHERE id = ?",
                             (owner, token, ref.utc_us(lease_until), row_id))
                claimed.append((row_id, token, False))
            conn.commit()
            return claimed
        with patch.object(ref, "claim", unsafe_claim):
            senders = self.receiver.senders()
            senders["ntfy"] = self.receiver.sender(
                "ntfy", during=lambda: ref.deliver(self.b, self.receiver.senders(), "B", NOW, LEASE))
            ref.deliver(self.a, senders, "A", NOW, LEASE)
        with self.assertRaises(AssertionError):
            self.assertEqual(len(self.receiver.accepted_on("ntfy")), 1)


# ---------------------------------------------------------------------------
# P2-1  unknown has a retry limit
# ---------------------------------------------------------------------------

class P2UnknownRetryLimit(Ledgered):
    def test_current_prototype_sends_unknown_past_limit(self):
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            conn.execute("UPDATE notification_log SET state = 'unknown', attempts = 5 WHERE channel = 'ntfy'")
            conn.commit()
            ledger.deliver(conn, self.receiver.senders(), NOW)
        self.assertEqual(len(self.receiver.calls_on("ntfy")), 1)

    def test_spec_repeated_ambiguity_stops_at_limit_and_is_abandoned(self):
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            for n in range(5):
                ref.deliver(conn, self.receiver.senders(ntfy="timeout_after_accept"), f"r{n}", NOW, LEASE)
            state, attempts = conn.execute("SELECT state, attempts FROM notification_log WHERE channel = 'ntfy'"
                                           ).fetchone()
        self.assertEqual((state, attempts), ("abandoned", ref.MAX_ATTEMPTS))
        self.assertEqual(len(self.receiver.calls_on("ntfy")), ref.MAX_ATTEMPTS)

    def test_negative_without_limit_keeps_sending(self):
        with contextlib.closing(connect(self.path)) as conn:
            self.new_event(conn)
            for n in range(5):
                ref.deliver(conn, self.receiver.senders(ntfy="timeout_after_accept"), f"r{n}", NOW, LEASE,
                            max_attempts=99)
        with self.assertRaises(AssertionError):
            self.assertEqual(len(self.receiver.calls_on("ntfy")), ref.MAX_ATTEMPTS)


# ---------------------------------------------------------------------------
# P2-2  publish failure -> no notification: the real control path
# ---------------------------------------------------------------------------

NOTIFY_STEPS = ("Notify via ntfy.sh (push notification)", "Notify via email")


def notification_gated_on_publish(workflow):
    """Static check of daily.yml. GitHub's implicit success() itself is not executed here."""
    steps = workflow["jobs"]["update"]["steps"]
    names = [s["name"] for s in steps]
    publish = steps[names.index("Commit and push updated data")]
    problems = []
    if publish.get("continue-on-error"):
        problems.append("publish step continues on error")
    for name in NOTIFY_STEPS:
        step = steps[names.index(name)]
        if names.index(name) < names.index("Commit and push updated data"):
            problems.append(f"{name} runs before publication")
        if any(f in str(step.get("if", "")) for f in ("always()", "failure()", "cancelled()")):
            problems.append(f"{name} runs regardless of publication")
        if step.get("continue-on-error"):
            problems.append(f"{name} hides its own failure")
    return problems


class P2PublishFailureControlPath(unittest.TestCase):
    WORKFLOW = Path(__file__).parents[1] / ".github/workflows/daily.yml"

    def test_workflow_gates_notification_on_publication(self):
        self.assertEqual(notification_gated_on_publish(yaml.safe_load(self.WORKFLOW.read_text())), [])

    def test_publisher_process_exits_nonzero_on_refused_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            remote, a, b = tmp / "remote.git", tmp / "a", tmp / "b"
            subprocess.run(["git", "init", "-q", "--bare", "--initial-branch=main", str(remote)], check=True)
            for repo in (a, b):
                subprocess.run(["git", "clone", "-q", str(remote), str(repo)], check=True, capture_output=True)
                for k, v in (("user.name", "F"), ("user.email", "f@example.test")):
                    subprocess.run(["git", "-C", str(repo), "config", k, v], check=True)
            (a / "data").mkdir()
            sqlite3.connect(a / "data/threat_intel.db").close()
            subprocess.run(["git", "-C", str(a), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(a), "commit", "-q", "-m", "seed"], check=True)
            subprocess.run(["git", "-C", str(a), "push", "-q", "origin", "HEAD:main"], check=True)
            subprocess.run(["git", "-C", str(b), "pull", "-q", "origin", "main"], check=True, capture_output=True)
            for repo, table in ((a, "newer"), (b, "stale")):
                with contextlib.closing(sqlite3.connect(repo / "data/threat_intel.db")) as conn:
                    conn.execute(f"CREATE TABLE {table} (x)")
            script = Path(__file__).parents[1] / "scripts/publish_daily_update.py"
            first = subprocess.run([sys.executable, str(script), "--backup-dir", str(tmp / "rec-a")],
                                   cwd=a, capture_output=True, text=True)
            second = subprocess.run([sys.executable, str(script), "--backup-dir", str(tmp / "rec-b")],
                                    cwd=b, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 1)  # the step fails -> later steps see failure
            self.assertIn("newer generated data", second.stderr)

    def test_negative_mutated_workflow_is_flagged(self):
        workflow = yaml.safe_load(self.WORKFLOW.read_text())
        steps = workflow["jobs"]["update"]["steps"]
        for step in steps:
            if step["name"] == "Commit and push updated data":
                step["continue-on-error"] = True
            if step["name"] == "Notify via email":
                step["if"] = "${{ always() }}"
        self.assertEqual(len(notification_gated_on_publish(workflow)), 2)


# ---------------------------------------------------------------------------
# P2-3  unassigned article -> CVE -> report -> notification (integration)
# ---------------------------------------------------------------------------

class P2UnassignedArticleIntegration(Ledgered):
    URL = "https://nvd.nist.gov/vuln/detail/" + KEV_B

    def hold_article(self, conn):
        """A KEV article for a CVE that is held, not linked to any incident."""
        run(conn, [raw("jpcert_alert", "https://rss.test/a", KEV_B, title="Article mentioning the CVE")])
        run_id = db.start_run(conn)
        article = conn.execute("INSERT INTO articles (original_url, normalized_url, date_basis, recorded_at, "
                               "provenance) VALUES (?, ?, 'collected', ?, 'collected')",
                               (self.URL + "#held", self.URL + "#held", NOW)).lastrowid
        conn.execute("INSERT INTO article_cves VALUES (?, ?, 'subject')", (article, KEV_B))
        db.upsert_cve(conn, KEV_B, in_kev=1, kev_date_added="2026-10-02", run_id=run_id)
        conn.commit()
        return run_id, article

    def test_spec_held_kev_reaches_report_and_one_notification(self):
        with contextlib.closing(connect(self.path)) as conn:
            run_id, article = self.hold_article(conn)
            self.assertEqual(conn.execute("SELECT count(*) FROM incident_articles WHERE article_id = ?",
                                          (article,)).fetchone()[0], 0)
            self.assertEqual(p0.ref_report_with_unassigned_kev(conn, run_id)["unassigned_kev_cve_ids"], [KEV_B])
            self.assertEqual(ledger.derive_events(conn, run_id, NOW), [f"cve:{KEV_B}:kev_listed"])
            ref.deliver(conn, self.receiver.senders(), "r1", NOW, LEASE)
            # Later a human attaches the article to the existing incident.
            incident = conn.execute("SELECT id FROM incidents WHERE cve_ids LIKE ?", (f"%{KEV_B}%",)).fetchone()[0]
            cand = conn.execute("INSERT INTO incident_candidates (incident_id, article_id, reason, state, created_at, "
                                "decided_at, decided_by) VALUES (?, ?, 'subject_cve_partial', 'accepted', ?, ?, "
                                "'analyst')", (incident, article, NOW, NOW)).lastrowid
            conn.execute("INSERT INTO incident_articles (incident_id, article_id, link_reason, decided_by, "
                         "candidate_id, linked_at) VALUES (?, ?, 'human_approved', 'human', ?, ?)",
                         (incident, article, cand, NOW))
            conn.commit()
            self.assertEqual(ledger.derive_events(conn, run_id + 1, NOW), [])
            ref.deliver(conn, self.receiver.senders(), "r2", NOW, LEASE)
        self.assertEqual((len(self.receiver.accepted_on("ntfy")), len(self.receiver.accepted_on("email"))), (1, 1))

    def test_negative_touched_only_and_incident_keyed_path_sends_nothing_while_held(self):
        with contextlib.closing(connect(self.path)) as conn:
            run_id, _ = self.hold_article(conn)
            report = p0.touched_only_report(conn, run_id)
            keys = [k for k in p0.incident_keyed_events(conn, run_id) if KEV_B in k]
        with self.assertRaises(AssertionError):
            self.assertTrue(report["unassigned_kev_cve_ids"] or keys)


# ---------------------------------------------------------------------------
# P2-4  observation history vs today's max-only storage
# ---------------------------------------------------------------------------

class P2CvssStorageDivergence(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        legacy_schema(self.conn)

    def test_current_storage_keeps_max_while_latest_observation_is_lower(self):
        for score in (9.8, 7.0):
            db.upsert_cve(self.conn, "CVE-X", cvss=score)
        stored = self.conn.execute("SELECT cvss FROM cves").fetchone()[0]
        history, events = ref.cvss_events("CVE-X", [("o1", 9.8), ("o2", 7.0)])
        self.assertEqual((stored, history[-1][1]), (9.8, 7.0))
        self.assertEqual([kind for _, kind, _ in events], ["first_critical", "downgrade"])

    def test_negative_deriving_from_stored_max_cannot_see_downgrade(self):
        for score in (9.8, 7.0):
            db.upsert_cve(self.conn, "CVE-X", cvss=score)
        stored = self.conn.execute("SELECT cvss FROM cves").fetchone()[0]
        _, events = ref.cvss_events("CVE-X", [("stored", stored)])
        with self.assertRaises(AssertionError):
            self.assertIn("downgrade", [kind for _, kind, _ in events])


if __name__ == "__main__":
    unittest.main()
