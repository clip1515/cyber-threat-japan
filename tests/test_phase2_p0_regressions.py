"""Phase 2-E P0 regression tests (synthetic data, temporary SQLite/git, mock senders).

No production code is changed by these tests. Each P0 item has three parts:

* ``Current*`` tests pin today's behaviour and prove the gap exists.
* ``Spec*`` tests run a small reference implementation of the Phase 2-E design
  (kept in this file, prefixed ``ref_``) and state the required behaviour.
* ``Negative*`` tests run an unsafe variant and show the spec assertions fail.

When the real implementation lands, the ``ref_`` helpers are replaced by the
production functions and the ``Current*`` tests are updated in the same commit.

After Codex's audits of 52645e0 and fba787b every ``ref_`` helper here goes through the
single Phase 2-E protocol in tests/phase2_protocol.py (v3), the same one the P1 and v3
tests use. The original helpers are kept as ``old_*`` so their defects stay reproducible.
"""
import contextlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from database import db
from database import migrate_phase2 as mig
from reporting import notification_ledger as ledger
from reporting.daily_report import build_report_data
from tests import phase2_protocol as reference
from tests.test_phase2_migration import legacy_schema, raw
import update

NOW = "2026-10-22T00:00:00+00:00"
LEASE_END = "2026-10-22T00:05:00+00:00"
AFTER_LEASE = "2026-10-22T00:10:00+00:00"  # beyond lease + protocol MAX_SKEW_US
KEV_A, KEV_B, CVE_C = "CVE-2026-95001", "CVE-2026-95002", "CVE-2026-95003"
SPEC = importlib.util.spec_from_file_location(
    "p0_publisher", Path(__file__).parents[1] / "scripts/publish_daily_update.py")
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)


def kev(cve, url=None):
    return raw("cisa_kev", url or "https://nvd.nist.gov/vuln/detail/" + cve, cve, cve_ids=[cve],
               in_kev=True, kev_date_added="2026-10-01")


def run(conn, items):
    run_id = db.start_run(conn)
    for i in items:
        update.process_item(conn, i, run_id=run_id)
    db.finish_run(conn, run_id, 1, 0, len(items), 0, 0, notes="synthetic")
    conn.commit()
    return run_id


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def git(repo, *args, check=True):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=check)


class Senders:
    """Mock channels; records every message, can fail per channel."""

    def __init__(self, failing=()):
        self.sent, self.failing = [], set(failing)

    def __call__(self):
        def make(channel):
            def send(message):
                if channel in self.failing:
                    raise ConnectionRefusedError(f"{channel} down")  # definite: nothing accepted
                self.sent.append((channel, message))
            return send
        return {c: make(c) for c in ledger.CHANNELS}


class TempDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def new_db(self, name="live.db"):
        path = self.dir / name
        conn = sqlite3.connect(path)
        legacy_schema(conn)
        conn.close()
        return path


# ---------------------------------------------------------------------------
# 1. Resend after the delivery result could not be recorded (across runners)
# ---------------------------------------------------------------------------

def ref_mark_sending_for_publish(conn, now):
    """Design I1 via the v3 protocol: claims (token, lease) are made inside the data commit."""
    return reference.prepare(conn, "publisher", now, LEASE_END)


def ref_send_premarked(conn, prepared, senders, published_generation):
    """First send of this run's claims, allowed only once main carries the same generation."""
    return reference.send_prepared(conn, prepared, senders, NOW, published_generation)


class RunnerRepos(TempDir):
    """A bare 'main' plus fresh clones that stand in for separate runners."""

    def setUp(self):
        super().setUp()
        self.remote = self.dir / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "--initial-branch=main", str(self.remote)], check=True)
        seed = self.clone("seed")
        (seed / "data").mkdir()
        db_path = seed / "data/threat_intel.db"
        conn = sqlite3.connect(db_path)
        legacy_schema(conn)
        conn.close()
        with contextlib.closing(connect(db_path)) as conn:
            run(conn, [kev(KEV_A)])
            mig.migrate(conn)
            ledger.derive_events(conn, 0, NOW, baseline=True)
            reference.install(conn)
        self.push(seed, "seed")
        self.prepared = {}

    def clone(self, name):
        path = self.dir / name
        git(self.dir, "clone", "-q", str(self.remote), str(path))
        git(path, "config", "user.name", "Fixture")
        git(path, "config", "user.email", "fixture@example.test")
        return path

    def push(self, repo, message):
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", message)
        git(repo, "push", "-q", "origin", "HEAD:main")  # normal push; fails if not fast-forward

    def remote_generation(self):
        """Generation of the DB currently published on main (read from the bare remote)."""
        target = self.dir / f"published-{uuid.uuid4().hex}.db"
        target.write_bytes(subprocess.run(["git", "--git-dir", str(self.remote), "show", "main:data/threat_intel.db"],
                                          capture_output=True, check=True).stdout)
        with contextlib.closing(sqlite3.connect(target)) as conn:
            return reference.generation(conn)

    def runner_collects_new_kev(self, name, mark_sending):
        repo = self.clone(name)
        conn = connect(repo / "data/threat_intel.db")
        run_id = run(conn, [kev(KEV_B)])
        ledger.derive_events(conn, run_id, NOW)
        if mark_sending:
            self.prepared[name] = ref_mark_sending_for_publish(conn, NOW)
        conn.close()
        self.push(repo, "data commit (first publication)")
        return repo


class CurrentPrototypeResend(RunnerRepos):
    def test_prototype_resends_without_duplicate_marker_after_lost_second_commit(self):
        """Gap I1 in reporting/notification_ledger.py as it stands: 'sending' is never published."""
        senders = Senders()
        repo = self.runner_collects_new_kev("run1", mark_sending=False)
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            ledger.deliver(conn, senders(), NOW)  # both channels succeed; result commit never pushed
        nxt = self.clone("run2")
        with contextlib.closing(connect(nxt / "data/threat_intel.db")) as conn:
            self.assertEqual({r[0] for r in conn.execute("SELECT state FROM notification_log")}, {"planned"})
            ledger.deliver(conn, senders(), NOW)
        ntfy = [m for c, m in senders.sent if c == "ntfy"]
        self.assertEqual(len(ntfy), 2)
        self.assertFalse(any("再送の可能性" in m for m in ntfy))  # duplicate goes out unlabelled


class SpecResend(RunnerRepos):
    def test_lost_result_commit_causes_one_labelled_resend(self):
        senders = Senders()
        repo = self.runner_collects_new_kev("run1", mark_sending=True)
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            ref_send_premarked(conn, self.prepared["run1"], senders(), self.remote_generation())
            # sent; the second (result) commit is lost
        nxt = self.clone("run2")
        with contextlib.closing(connect(nxt / "data/threat_intel.db")) as conn:
            reference.deliver(conn, senders(), "runner-2", AFTER_LEASE)
            self.assertEqual(dict(conn.execute("SELECT channel, state FROM notification_log")),
                             {"ntfy": "sent", "email": "sent"})
        for channel in ledger.CHANNELS:
            messages = [m for c, m in senders.sent if c == channel]
            self.assertEqual(len(messages), 2)
            self.assertNotIn("再送の可能性", messages[0])
            self.assertIn("再送の可能性", messages[1])

    def test_failed_first_publication_sends_once_unlabelled_later(self):
        senders = Senders()
        repo = self.clone("run1")
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            run_id = run(conn, [kev(KEV_B)])
            ledger.derive_events(conn, run_id, NOW)
            prepared = ref_mark_sending_for_publish(conn, NOW)
            # Publication fails (nothing pushed): this runner may not send.
            with self.assertRaises(reference.StalePublication):
                ref_send_premarked(conn, prepared, senders(), self.remote_generation())
        nxt = self.clone("run2")
        with contextlib.closing(connect(nxt / "data/threat_intel.db")) as conn:
            run_id = run(conn, [kev(KEV_B)])
            self.assertEqual(ledger.derive_events(conn, run_id, NOW), [f"cve:{KEV_B}:kev_listed"])
            prepared = ref_mark_sending_for_publish(conn, NOW)
        self.push(nxt, "data commit (first publication)")
        with contextlib.closing(connect(nxt / "data/threat_intel.db")) as conn:
            ref_send_premarked(conn, prepared, senders(), self.remote_generation())
        self.assertEqual([c for c, _ in senders.sent], ["ntfy", "email"])
        self.assertFalse(any("再送の可能性" in m for _, m in senders.sent))

    def test_one_channel_failing_is_retried_alone_on_next_runner(self):
        senders = Senders(failing={"email"})
        repo = self.runner_collects_new_kev("run1", mark_sending=True)
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            ref_send_premarked(conn, self.prepared["run1"], senders(), self.remote_generation())
        self.push(repo, "result commit")
        senders.failing.clear()
        nxt = self.clone("run2")
        with contextlib.closing(connect(nxt / "data/threat_intel.db")) as conn:
            reference.deliver(conn, senders(), "runner-2", AFTER_LEASE)
        self.assertEqual([c for c, _ in senders.sent], ["ntfy", "email"])
        self.assertFalse(any("再送の可能性" in m for _, m in senders.sent))


class NegativeResend(RunnerRepos):
    def test_spec_assertion_fails_without_publishing_sending_state(self):
        senders = Senders()
        repo = self.runner_collects_new_kev("run1", mark_sending=False)  # unsafe: planned rows published
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            ledger.deliver(conn, senders(), NOW)
        with contextlib.closing(connect(self.clone("run2") / "data/threat_intel.db")) as conn:
            ledger.deliver(conn, senders(), NOW)
        second = [m for c, m in senders.sent if c == "ntfy"][1]
        with self.assertRaises(AssertionError):
            self.assertIn("再送の可能性", second)


# ---------------------------------------------------------------------------
# 2. run ID reuse and missing collection history after a DB rollback
# ---------------------------------------------------------------------------

ARCHIVE = re.compile(r"_run(\d+)\.md$")


def old_published_history_check(repo, conn):
    """Original reference (fails open on missing/empty/malformed archives and reused ids)."""
    archived = sorted(int(m.group(1)) for p in (repo / "reports").glob("*.md") if (m := ARCHIVE.search(p.name)))
    seq = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'run_log'").fetchone()
    db_runs = {r[0] for r in conn.execute("SELECT id FROM run_log")}
    return {"max_published": max(archived, default=0), "db_seq": seq[0] if seq else 0,
            "missing_runs": [r for r in archived if r not in db_runs]}


def old_db_is_behind(check):
    return check["db_seq"] < check["max_published"] or bool(check["missing_runs"])


def ref_published_history_check(repo, conn):
    return reference.history_check(repo, conn)


def ref_db_is_behind(check):
    return not check["ok"]


def naive_db_is_behind(repo, conn):
    """Unsafe: trusts the dashboard JSON, which is restored together with the DB."""
    last = json.loads((repo / "docs/data/dashboard_data.json").read_text())["last_run"]["id"]
    return conn.execute("SELECT max(id) FROM run_log").fetchone()[0] < last


class RollbackHistory(TempDir):
    """A checkout with three published runs (DB, dashboard JSON, archived reports)."""

    def setUp(self):
        super().setUp()
        self.repo = self.dir / "repo"
        (self.repo / "data").mkdir(parents=True)
        (self.repo / "reports").mkdir()
        (self.repo / "docs/data").mkdir(parents=True)
        self.db = self.repo / "data/threat_intel.db"
        conn = sqlite3.connect(self.db)
        legacy_schema(conn)
        conn.close()
        self.json_after = {}
        for n, item in enumerate([kev(KEV_A), raw("jpcert_alert", "https://rss.test/2", title="Run 2"),
                                  kev(KEV_B)], start=1):
            with contextlib.closing(connect(self.db)) as conn:
                run_id = run(conn, [item])
                started, finished = conn.execute("SELECT started_at, finished_at FROM run_log WHERE id = ?",
                                                 (run_id,)).fetchone()
            # Named like reporting/daily_report.py:289-290 (date taken from started_at).
            (self.repo / f"reports/daily_report_{started[:10]}_run{run_id}.md").write_text(
                f"- 実行日時: {started} 〜 {finished} (run_id={run_id})\n", encoding="utf-8")
            payload = json.dumps({"last_run": {"id": run_id}})
            (self.repo / "docs/data/dashboard_data.json").write_text(payload)
            self.json_after[run_id] = payload
            if run_id == 1:
                shutil.copy(self.db, self.dir / "after_run1.db")

    def restore_run1(self, also_json=False):
        shutil.copy(self.dir / "after_run1.db", self.db)
        if also_json:
            (self.repo / "docs/data/dashboard_data.json").write_text(self.json_after[1])


class CurrentRunIdReuse(RollbackHistory):
    def test_restored_db_reuses_lost_run_id_and_loses_kev_first_seen(self):
        self.restore_run1()
        with contextlib.closing(connect(self.db)) as conn:
            new_run = run(conn, [kev(KEV_B)])
            self.assertEqual(new_run, 2)  # id 2 already published for a different run
            self.assertEqual(conn.execute("SELECT kev_first_seen_run_id FROM cves WHERE cve_id = ?",
                                          (KEV_B,)).fetchone()[0], 2)  # originally run 3
        self.assertEqual(len(list((self.repo / "reports").glob("daily_report_*_run2.md"))), 1)


class SpecPublishedHistoryGuard(RollbackHistory):
    def test_consistent_checkout_passes(self):
        with contextlib.closing(connect(self.db)) as conn:
            check = ref_published_history_check(self.repo, conn)
        self.assertEqual((check["ok"], check["max_published"], check["db_seq"], check["missing_runs"]),
                         (True, 3, 3, []))
        self.assertFalse(ref_db_is_behind(check))

    def test_restored_db_is_detected_with_missing_runs(self):
        self.restore_run1()
        with contextlib.closing(connect(self.db)) as conn:
            check = ref_published_history_check(self.repo, conn)
        self.assertEqual((check["max_published"], check["db_seq"], check["missing_runs"]), (3, 1, [2, 3]))
        self.assertTrue(ref_db_is_behind(check))

    def test_restoring_json_too_is_still_detected(self):
        self.restore_run1(also_json=True)
        with contextlib.closing(connect(self.db)) as conn:
            self.assertTrue(ref_db_is_behind(ref_published_history_check(self.repo, conn)))

    def test_gap_inside_history_is_detected(self):
        with contextlib.closing(connect(self.db)) as conn:
            conn.execute("DELETE FROM run_log WHERE id = 2")
            conn.commit()
            check = ref_published_history_check(self.repo, conn)
        self.assertEqual(check["missing_runs"], [2])
        self.assertTrue(ref_db_is_behind(check))

    def test_archived_reports_cannot_be_deleted_by_publication(self):
        """The anchor is durable: scripts/publish_daily_update.py:66-67 refuses deletions."""
        remote = self.dir / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "--initial-branch=main", str(remote)], check=True)
        for args in (("init", "-q", "--initial-branch=main"), ("config", "user.name", "F"),
                     ("config", "user.email", "f@example.test"), ("add", "-A"), ("commit", "-q", "-m", "seed"),
                     ("remote", "add", "origin", str(remote)), ("push", "-q", "origin", "HEAD:main")):
            git(self.repo, *args)
        next((self.repo / "reports").glob("daily_report_*_run3.md")).unlink()
        cwd = Path.cwd()
        try:
            os.chdir(self.repo)
            with self.assertRaises(RuntimeError) as ctx:
                PUBLISHER.publish(self.dir / "recovery")
        finally:
            os.chdir(cwd)
        self.assertIn("Refusing to delete", str(ctx.exception))


class NegativeRunIdGuard(RollbackHistory):
    def test_json_based_guard_misses_rollback_of_db_and_json(self):
        self.restore_run1(also_json=True)
        with contextlib.closing(connect(self.db)) as conn:
            self.assertFalse(naive_db_is_behind(self.repo, conn))  # unsafe guard says "fine"
            self.assertTrue(ref_db_is_behind(ref_published_history_check(self.repo, conn)))


# ---------------------------------------------------------------------------
# 3. New KEV for an unassigned article must stay in the daily report
# ---------------------------------------------------------------------------

def ref_report_with_unassigned_kev(conn, run_id):
    data = build_report_data(conn, run_id)
    covered = {c for r in data["kev_items"] for c in filter(None, (r["cve_ids"] or "").split(","))}
    unassigned = sorted(db.get_new_kev_cve_ids_by_run(conn, run_id) - covered)
    return {**data, "unassigned_kev_cve_ids": unassigned,
            "significant_change": data["significant_change"] or bool(unassigned)}


def touched_only_report(conn, run_id):
    """Unsafe: today's behaviour (only incidents touched by the run)."""
    data = build_report_data(conn, run_id)
    return {**data, "unassigned_kev_cve_ids": []}


class UnassignedKev(TempDir):
    def setUp(self):
        super().setUp()
        self.conn = connect(self.new_db())
        run(self.conn, [raw("jpcert_alert", "https://rss.test/a", KEV_B, title="Article mentioning the CVE")])
        # A KEV article for the same CVE is held as unassigned: CVE facts stored, no incident touched.
        self.run_id = db.start_run(self.conn)
        db.upsert_cve(self.conn, KEV_B, in_kev=1, kev_date_added="2026-10-02", run_id=self.run_id)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        super().tearDown()

    def test_current_report_drops_the_kev(self):
        data = build_report_data(self.conn, self.run_id)
        self.assertEqual((data["kev_items"], data["significant_change"]), ([], False))

    def test_spec_report_keeps_the_kev_and_marks_significant(self):
        data = ref_report_with_unassigned_kev(self.conn, self.run_id)
        self.assertEqual(data["unassigned_kev_cve_ids"], [KEV_B])
        self.assertTrue(data["significant_change"])

    def test_spec_does_not_list_an_assigned_kev_twice(self):
        run_id = run(self.conn, [kev(KEV_A)])
        data = ref_report_with_unassigned_kev(self.conn, run_id)
        self.assertEqual(len(data["kev_items"]), 1)
        self.assertEqual(data["unassigned_kev_cve_ids"], [])

    def test_negative_touched_only_report_fails_spec(self):
        data = touched_only_report(self.conn, self.run_id)
        with self.assertRaises(AssertionError):
            self.assertEqual(data["unassigned_kev_cve_ids"], [KEV_B])


# ---------------------------------------------------------------------------
# 4. CVSS: first critical, further increase, downgrade (and re-critical)
# ---------------------------------------------------------------------------

CRITICAL = 9.0


def ref_cvss_events(cve_id, scores):
    """v2 reference with one synthetic observation id per score; returns (key, kind)."""
    _, events = reference.cvss_events(cve_id, [(f"obs{i}", s) for i, s in enumerate(scores)])
    return [(key, kind) for key, kind, _ in events]


def old_cvss_events(cve_id, observations):
    """Original reference: keys use the score, so recurring transitions collide."""
    events, previous, ever_critical = [], None, False
    for score in observations:
        if score >= CRITICAL and (previous is None or previous < CRITICAL):
            kind = "re_critical" if ever_critical else "first_critical"
            ever_critical = True
        elif score >= CRITICAL and score > previous:
            kind = "increase"
        elif previous is not None and previous >= CRITICAL > score:
            kind = "downgrade"
        else:
            kind = None
        if kind:
            events.append((f"cve:{cve_id}:cvss:{kind}:{score}", kind))
        previous = score
    return events


def max_based_cvss_events(conn, cve_id, observations):
    """Unsafe: reads cves.cvss after each upsert, i.e. today's max-only storage."""
    for score in observations:
        db.upsert_cve(conn, cve_id, cvss=score)
    return ref_cvss_events(cve_id, [conn.execute("SELECT cvss FROM cves WHERE cve_id = ?",
                                                 (cve_id,)).fetchone()[0]])


class CvssTransitions(TempDir):
    SEQUENCE = [5.0, 9.1, 9.8, 7.0, 9.3]

    def test_current_storage_hides_downgrade(self):
        with contextlib.closing(connect(self.new_db())) as conn:
            for score in (9.8, 7.0):
                db.upsert_cve(conn, CVE_C, cvss=score)
            self.assertEqual(conn.execute("SELECT cvss FROM cves WHERE cve_id = ?", (CVE_C,)).fetchone()[0], 9.8)

    def test_current_prototype_reports_critical_only_once(self):
        with contextlib.closing(connect(self.new_db())) as conn:
            mig.migrate(conn)
            keys = []
            for n, score in enumerate(self.SEQUENCE, start=1):
                db.upsert_cve(conn, CVE_C, cvss=score)
                keys += ledger.derive_events(conn, n, NOW)
        self.assertEqual(keys, [f"cve:{CVE_C}:cvss_critical"])  # increase/downgrade/re-critical invisible

    def test_spec_distinguishes_first_increase_downgrade_and_recritical(self):
        self.assertEqual([k for _, k in ref_cvss_events(CVE_C, self.SEQUENCE)],
                         ["first_critical", "increase", "downgrade", "re_critical"])

    def test_spec_is_idempotent_for_repeated_observations(self):
        self.assertEqual(ref_cvss_events(CVE_C, [9.1, 9.1, 9.1]), ref_cvss_events(CVE_C, [9.1]))
        self.assertEqual(ref_cvss_events(CVE_C, [4.0, 6.5, 8.9]), [])

    def test_negative_max_based_detection_fails_spec(self):
        with contextlib.closing(connect(self.new_db())) as conn:
            kinds = [k for _, k in max_based_cvss_events(conn, CVE_C, self.SEQUENCE)]
        with self.assertRaises(AssertionError):
            self.assertEqual(kinds, ["first_critical", "increase", "downgrade", "re_critical"])


# ---------------------------------------------------------------------------
# 5. A critical event is notified once per channel
# ---------------------------------------------------------------------------

def incident_keyed_events(conn, run_id):
    """Unsafe: one event per (incident, KEV CVE) instead of per CVE."""
    keys = []
    for incident_id, cve_ids in conn.execute("SELECT id, cve_ids FROM incidents WHERE in_kev = 1"):
        for cve in filter(None, (cve_ids or "").split(",")):
            keys.append(f"incident:{incident_id}:{cve}:kev_listed")
    return keys


class NoDuplicateNotification(TempDir):
    def setUp(self):
        super().setUp()
        self.path = self.new_db()
        with contextlib.closing(connect(self.path)) as conn:
            run(conn, [kev(KEV_A)])
            mig.migrate(conn)
            ledger.derive_events(conn, 0, NOW, baseline=True)
        self.senders = Senders()

    def cycle(self, conn, items):
        run_id = run(conn, items)
        ledger.derive_events(conn, run_id, NOW)
        ledger.deliver(conn, self.senders(), NOW)

    def per_channel(self, key):
        return {c: sum(1 for ch, m in self.senders.sent if ch == c and key in m) for c in ledger.CHANNELS}

    def test_same_kev_from_kev_nvd_rerun_and_second_incident_is_sent_once(self):
        key = f"cve:{KEV_B}:kev_listed"
        with contextlib.closing(connect(self.path)) as conn:
            self.cycle(conn, [kev(KEV_B)])
            self.cycle(conn, [raw("nvd_cve", "https://nvd.nist.gov/vuln/detail/" + KEV_B, KEV_B,
                                  cve_ids=[KEV_B], cvss=9.8)])
            self.cycle(conn, [kev(KEV_B)])  # re-run
            self.cycle(conn, [raw("jpcert_alert", "https://rss.test/other", f"{KEV_B} {CVE_C}",
                                  title="Partial overlap, separate incident")])
        self.assertEqual(self.per_channel(key), {"ntfy": 1, "email": 1})

    def test_restore_without_ledger_reimport_would_renotify(self):
        """P0-2 dependency: restoring the DB alone re-sends; re-importing sent keys prevents it."""
        key = f"cve:{KEV_B}:kev_listed"
        pristine = self.dir / "backup_before_kev.db"
        shutil.copy(self.path, pristine)
        with contextlib.closing(connect(self.path)) as conn:
            self.cycle(conn, [kev(KEV_B)])
            sent_keys = [r[0] for r in conn.execute(
                "SELECT DISTINCT event_key FROM notification_log WHERE state = 'sent'")]
        self.assertEqual(sent_keys, [key])

        unsafe = self.dir / "restored_unsafe.db"  # DB restored, ledger not re-imported
        shutil.copy(pristine, unsafe)
        with contextlib.closing(connect(unsafe)) as conn:
            self.cycle(conn, [kev(KEV_B)])
        self.assertEqual(self.per_channel(key), {"ntfy": 2, "email": 2})

        self.senders.sent.clear()
        safe = self.dir / "restored_safe.db"  # reference recovery step: re-import sent events
        shutil.copy(pristine, safe)
        with contextlib.closing(connect(safe)) as conn:
            conn.executemany("INSERT INTO notification_events (event_key, event_type, run_id, created_at) "
                             "VALUES (?, 'kev_listed', 0, ?)", [(k, NOW) for k in sent_keys])
            conn.commit()
            self.cycle(conn, [kev(KEV_B)])
        self.assertEqual(self.per_channel(key), {"ntfy": 0, "email": 0})

    def test_negative_incident_keyed_events_duplicate_across_incidents(self):
        with contextlib.closing(connect(self.path)) as conn:
            run(conn, [kev(KEV_B)])
            run(conn, [raw("cisa_kev", "https://rss.test/kev-mirror", f"{KEV_B} {CVE_C}", cve_ids=[KEV_B],
                           in_kev=True, title="Same KEV in a second incident")])
            keys = [k for k in incident_keyed_events(conn, 0) if KEV_B in k]
        self.assertEqual(len(keys), 2)
        with self.assertRaises(AssertionError):
            self.assertEqual(len(set(keys)), 1)


if __name__ == "__main__":
    unittest.main()
