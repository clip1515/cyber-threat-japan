"""Phase 2-D: recovery options and notification failures, on synthetic data only.

Temporary SQLite files and mock senders only: no production database, no
network, no real notification. The ledger and drop tool are not wired into
any workflow.
"""
import contextlib
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.append(str(Path(__file__).resolve().parent.parent))

from database import db
from database import migrate_phase2 as mig
from database import rollback_phase2 as rb
from reporting import dashboard_export, notify_summary
from reporting import notification_ledger as ledger
from reporting.daily_report import build_report_data
from tests.test_phase2_migration import legacy_schema, raw
import update

NOW = "2026-10-22T00:00:00+00:00"
KEV_A, KEV_B = "CVE-2026-94001", "CVE-2026-94002"


def kev(cve, url):
    return raw("cisa_kev", url, cve, cve_ids=[cve], in_kev=True, kev_date_added="2026-10-01")


def run(conn, items):
    run_id = db.start_run(conn)
    for i in items:
        update.process_item(conn, i, run_id=run_id)
    db.finish_run(conn, run_id, 1, 0, len(items), 0, 0, notes="synthetic")
    conn.commit()
    return run_id


class FileDB(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "live.db"
        conn = sqlite3.connect(self.path)
        legacy_schema(conn)
        conn.close()

    def tearDown(self):
        self._tmp.cleanup()

    def connect(self, path=None):
        conn = sqlite3.connect(path or self.path)
        conn.row_factory = sqlite3.Row
        return conn


class RecoveryOptions(FileDB):
    """Timeline: run1 -> backup -> migration -> run2 (new RSS article, new KEV)."""

    def setUp(self):
        super().setUp()
        with contextlib.closing(self.connect()) as conn:
            self.run1 = run(conn, [kev(KEV_A, "https://nvd.nist.gov/vuln/detail/" + KEV_A)])
        self.backup = self.dir / "pre-migration.db"
        shutil.copy(self.path, self.backup)
        with contextlib.closing(self.connect()) as conn:
            mig.migrate(conn)
            self.run2 = run(conn, [raw("jpcert_alert", "https://rss.test/short-lived", title="Only in feed briefly"),
                                   kev(KEV_B, "https://nvd.nist.gov/vuln/detail/" + KEV_B)])
            self.after_run2 = mig.legacy_fingerprint(conn)[0]

    def test_code_only_rollback_keeps_everything(self):
        with contextlib.closing(self.connect()) as conn:
            run(conn, [raw("jpcert_alert", "https://rss.test/later", title="Legacy code keeps working")])
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(conn.execute("SELECT count(*) FROM incidents").fetchone()[0], 4)
            # Inert Phase 2 tables simply lag behind until the next migration run.
            self.assertEqual(conn.execute("SELECT count(*) FROM incident_observations").fetchone()[0], 1)

    def test_safe_drop_keeps_post_migration_legacy_rows(self):
        with contextlib.closing(self.connect()) as conn:
            rb.drop_phase2(conn)
            self.assertEqual(mig.legacy_fingerprint(conn)[0], self.after_run2)
            self.assertFalse({r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                             & set(mig.PHASE2_TABLES))
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT kev_first_seen_run_id FROM cves WHERE cve_id = ?",
                                          (KEV_B,)).fetchone()[0], self.run2)
            mig.migrate(conn)  # re-migration after a drop works
            self.assertEqual(conn.execute("SELECT count(*) FROM incident_observations").fetchone()[0], 3)

    def test_safe_drop_refuses_phase2_only_data(self):
        with contextlib.closing(self.connect()) as conn:
            conn.execute("INSERT INTO notification_events VALUES ('e', NULL, 'kev_listed', 1, 't')")
            conn.commit()
            with self.assertRaises(mig.MigrationError):
                rb.drop_phase2(conn)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
            rb.drop_phase2(conn, allow_data_loss=True)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)

    def test_safe_drop_failure_rolls_back(self):
        with contextlib.closing(self.connect()) as conn:
            with patch.object(rb, "legacy_fingerprint", side_effect=[("a", {}), ("b", {})]):
                with self.assertRaises(mig.MigrationError):
                    rb.drop_phase2(conn)
            self.assertIn("articles", {r[0] for r in conn.execute("SELECT name FROM sqlite_master")})
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)

    def test_backup_restore_loses_data_and_recollection_cannot_restore_it(self):
        shutil.copy(self.backup, self.path)
        with contextlib.closing(self.connect()) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM incidents").fetchone()[0], 1)  # 2 lost
            self.assertIsNone(conn.execute("SELECT 1 FROM cves WHERE cve_id = ?", (KEV_B,)).fetchone())
            # Re-collect: the RSS window has moved on, the KEV catalog still lists KEV_B.
            rerun = run(conn, [kev(KEV_B, "https://nvd.nist.gov/vuln/detail/" + KEV_B)])
            self.assertIsNone(conn.execute("SELECT 1 FROM incidents WHERE source_url = "
                                           "'https://rss.test/short-lived'").fetchone())
            first_seen = conn.execute("SELECT kev_first_seen_run_id FROM cves WHERE cve_id = ?",
                                      (KEV_B,)).fetchone()[0]
            # run_log ids restart from the backup, so the lost run's id is reused: the
            # KEV first-seen reference now silently points at a different run.
            self.assertEqual(rerun, self.run2)
            self.assertEqual(first_seen, rerun)
            report = build_report_data(conn, rerun)
            self.assertEqual(len(report["kev_items"]), 1)  # already-notified KEV reported as new again
            self.assertTrue(report["significant_change"])


class CurrentNotificationBehaviour(FileDB):
    def summary(self, conn, run_id):
        data = dashboard_export.build_dashboard_data(conn, run_id=run_id)
        target = self.dir / f"dashboard_{run_id}.json"
        target.write_text(json.dumps(data, ensure_ascii=False))
        with patch.object(notify_summary, "DATA_PATH", target):
            return notify_summary.build_summary_text()

    def test_publish_ok_notify_failed_event_is_never_sent_again(self):
        """Significance is per run (daily_report.py:99-103, 132-137): a missed day is gone."""
        with contextlib.closing(self.connect()) as conn:
            run1 = run(conn, [kev(KEV_A, "https://nvd.nist.gov/vuln/detail/" + KEV_A)])
            self.assertIn("重要な変化を検出", self.summary(conn, run1))
            # The notification for run1 fails; the next run re-collects the same item.
            run2 = run(conn, [kev(KEV_A, "https://nvd.nist.gov/vuln/detail/" + KEV_A)])
            self.assertIn("重要な新規変化はありません", self.summary(conn, run2))

    def test_workflow_notification_ordering_and_conditions(self):
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/daily.yml").read_text())
        steps = workflow["jobs"]["update"]["steps"]
        names = [s["name"] for s in steps]
        order = {n: names.index(n) for n in names}
        # Summary is built before publishing; both notifications follow publishing.
        self.assertLess(order["Build notification summary"], order["Commit and push updated data"])
        self.assertLess(order["Commit and push updated data"], order["Notify via ntfy.sh (push notification)"])
        self.assertLess(order["Notify via ntfy.sh (push notification)"], order["Notify via email"])
        by_name = {s["name"]: s for s in steps}
        for name in ("Notify via ntfy.sh (push notification)", "Notify via email"):
            condition = by_name[name]["if"]
            # No status function: GitHub applies success(), so a failed publish or a
            # failed ntfy step skips every later notification step.
            self.assertFalse(any(f in condition for f in ("always()", "failure()", "cancelled()")))
        self.assertIn("failure()", by_name["Alert on workflow failure"]["if"])
        self.assertEqual(workflow["jobs"]["update"]["if"], "github.ref == 'refs/heads/main'")


class Crash(BaseException):
    """Stands in for the runner being terminated mid-step."""


class Ledger(FileDB):
    def setUp(self):
        super().setUp()
        with contextlib.closing(self.connect()) as conn:
            run(conn, [kev(KEV_A, "https://nvd.nist.gov/vuln/detail/" + KEV_A)])
            mig.migrate(conn)
            ledger.derive_events(conn, 0, NOW, baseline=True)  # existing KEV are not news
        self.sent = []

    def sender(self, channel, fail=False):
        def send(message):
            if fail:
                raise ConnectionError(f"{channel} down")
            self.sent.append((channel, message))
        return send

    def new_kev(self, conn, cve=KEV_B):
        run_id = run(conn, [kev(cve, "https://nvd.nist.gov/vuln/detail/" + cve)])
        return ledger.derive_events(conn, run_id, NOW)

    def states(self, conn):
        return dict(conn.execute("SELECT channel, state FROM notification_log").fetchall())

    def test_baseline_does_not_notify_existing_kev(self):
        with contextlib.closing(self.connect()) as conn:
            self.assertEqual(ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW),
                             {"sent": [], "failed": [], "abandoned": []})

    def test_ntfy_ok_email_failed_retries_only_email(self):
        with contextlib.closing(self.connect()) as conn:
            self.assertEqual(self.new_kev(conn), [f"cve:{KEV_B}:kev_listed"])
            ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email", fail=True)}, NOW)
            self.assertEqual(self.states(conn), {"ntfy": "sent", "email": "failed"})
            ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW)
            self.assertEqual([c for c, _ in self.sent], ["ntfy", "email"])
            self.assertEqual(self.states(conn), {"ntfy": "sent", "email": "sent"})

    def test_sent_but_result_not_saved_is_resent_with_marker(self):
        with contextlib.closing(self.connect()) as conn:
            self.new_kev(conn)
            calls = {"n": 0}

            def failing_commit():
                calls["n"] += 1
                if calls["n"] == 3:  # 1: stale reset, 2: 'sending', 3: 'sent' for ntfy
                    raise sqlite3.OperationalError("disk I/O error")
                conn.commit()
            with self.assertRaises(sqlite3.OperationalError):
                ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW,
                               commit=failing_commit)
        with contextlib.closing(self.connect()) as conn:  # the uncommitted 'sent' is gone
            self.assertEqual(self.states(conn)["ntfy"], "sending")
            ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW)
            self.assertEqual(self.states(conn), {"ntfy": "sent", "email": "sent"})
        ntfy = [m for c, m in self.sent if c == "ntfy"]
        self.assertEqual(len(ntfy), 2)
        self.assertNotIn("再送の可能性", ntfy[0])
        self.assertIn("再送の可能性", ntfy[1])

    def test_runner_killed_mid_delivery_loses_nothing(self):
        with contextlib.closing(self.connect()) as conn:
            self.new_kev(conn)

            def killed(message):
                raise Crash()
            with self.assertRaises(Crash):
                ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": killed}, NOW)
        with contextlib.closing(self.connect()) as conn:
            ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW)
            self.assertEqual(self.states(conn), {"ntfy": "sent", "email": "sent"})
        self.assertEqual([c for c, _ in self.sent], ["ntfy", "email"])
        self.assertIn("再送の可能性", self.sent[1][1])

    def test_rerun_does_not_renotify(self):
        with contextlib.closing(self.connect()) as conn:
            self.new_kev(conn)
            senders = {"ntfy": self.sender("ntfy"), "email": self.sender("email")}
            ledger.deliver(conn, senders, NOW)
            self.assertEqual(self.new_kev(conn), [])  # same KEV re-collected
            ledger.deliver(conn, senders, NOW)
        self.assertEqual(len(self.sent), 2)

    def test_publish_failure_discards_plan_but_next_run_derives_it_again(self):
        published = self.dir / "published.db"
        shutil.copy(self.path, published)
        with contextlib.closing(self.connect()) as conn:  # this run's DB is never published
            self.new_kev(conn)
        with contextlib.closing(self.connect(published)) as conn:
            self.assertEqual(self.new_kev(conn), [f"cve:{KEV_B}:kev_listed"])
            ledger.deliver(conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW)
        self.assertEqual(len(self.sent), 2)

    def test_repeated_failure_is_abandoned_not_retried_forever(self):
        with contextlib.closing(self.connect()) as conn:
            self.new_kev(conn)
            down = {"ntfy": self.sender("ntfy"), "email": self.sender("email", fail=True)}
            outcomes = [ledger.deliver(conn, down, NOW) for _ in range(4)]
            self.assertEqual(self.states(conn)["email"], "abandoned")
            self.assertEqual(outcomes[2]["abandoned"], [(f"cve:{KEV_B}:kev_listed", "email")])
            self.assertEqual(outcomes[3], {"sent": [], "failed": [], "abandoned": []})

    def test_negative_control_without_presend_commit_resend_is_unlabelled(self):
        source = Path(ledger.__file__).read_text(encoding="utf-8")
        presend = "                     \"delivery_id = ? WHERE id = ?\", (attempts + 1, now, delivery_id, row_id))\n        commit()\n"
        self.assertIn(presend, source)
        namespace = {"__name__": "mutated_ledger"}
        exec(compile(source.replace(presend, presend.replace("        commit()\n", "")), "mutated", "exec"),
             namespace)
        with contextlib.closing(self.connect()) as conn:
            self.new_kev(conn)
            calls = {"n": 0}

            def failing_commit():
                calls["n"] += 1
                if calls["n"] == 2:  # now the first commit after the send
                    raise sqlite3.OperationalError("disk I/O error")
                conn.commit()
            with self.assertRaises(sqlite3.OperationalError):
                namespace["deliver"](conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW,
                                     commit=failing_commit)
        with contextlib.closing(self.connect()) as conn:
            namespace["deliver"](conn, {"ntfy": self.sender("ntfy"), "email": self.sender("email")}, NOW)
        ntfy = [m for c, m in self.sent if c == "ntfy"]
        self.assertEqual(len(ntfy), 2)
        self.assertNotIn("再送の可能性", ntfy[1])  # the duplicate goes out unlabelled


class UnassignedArticles(FileDB):
    def test_held_kev_is_missed_by_report_but_derived_by_ledger(self):
        with contextlib.closing(self.connect()) as conn:
            run(conn, [raw("jpcert_alert", "https://rss.test/a", KEV_B, title="Article A")])
            mig.migrate(conn)
            ledger.derive_events(conn, 0, NOW, baseline=True)
            # A KEV article for the same CVE is held as unassigned: CVE facts are stored,
            # no incident is touched in this run.
            run_id = db.start_run(conn)
            db.upsert_cve(conn, KEV_B, in_kev=1, kev_date_added="2026-10-02", run_id=run_id)
            conn.commit()
            self.assertEqual(build_report_data(conn, run_id)["kev_items"], [])  # today's report misses it
            self.assertEqual(ledger.derive_events(conn, run_id, NOW), [f"cve:{KEV_B}:kev_listed"])

    def test_cvss_rise_to_critical_is_an_event_once(self):
        with contextlib.closing(self.connect()) as conn:
            run(conn, [raw("jpcert_alert", "https://rss.test/a", KEV_B, title="Article A", cvss=5.0)])
            mig.migrate(conn)
            ledger.derive_events(conn, 0, NOW, baseline=True)
            db.upsert_cve(conn, KEV_B, cvss=9.8)
            conn.commit()
            self.assertEqual(ledger.derive_events(conn, 2, NOW), [f"cve:{KEV_B}:cvss_critical"])
            db.upsert_cve(conn, KEV_B, cvss=9.9)
            self.assertEqual(ledger.derive_events(conn, 3, NOW), [])


if __name__ == "__main__":
    unittest.main()
