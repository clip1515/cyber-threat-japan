"""Phase 2-E v3: Codex's counterexamples against v2 (fba787b) and the single protocol.

Synthetic data, temporary SQLite files, temporary git repositories and mock
receivers only; no production code. ``Current*`` reproduce each counterexample
against the frozen v2 reference (tests/phase2_reference.py); ``Spec*`` run the
v3 protocol (tests/phase2_protocol.py) that the P0 and P1 tests also use;
``Negative*`` run an unsafe variant. What the receiver accepted and what the
DB says are asserted separately.
"""
import contextlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parent.parent))

from database import db
from database import migrate_phase2 as mig
from reporting import daily_report
from reporting import notification_ledger as ledger
from tests import phase2_protocol as proto
from tests import phase2_reference as v2
from tests.test_phase2_migration import legacy_schema, raw
from tests.test_phase2_p0_regressions import RunnerRepos
from tests.test_phase2_p1_regressions import History
import update

T0 = "2026-10-22T00:00:00+00:00"
T_LEASE = "2026-10-22T00:05:00+00:00"
T_PAST_LEASE_IN_SKEW = "2026-10-22T00:05:30+00:00"
T_PAST_SKEW = "2026-10-22T00:06:01+00:00"
T10 = "2026-10-22T00:10:00+00:00"
T15 = "2026-10-22T00:15:00+00:00"
KEV_B = "CVE-2026-99002"
LABEL = "[再送の可能性あり]"


def kev(cve):
    return raw("cisa_kev", "https://nvd.nist.gov/vuln/detail/" + cve, cve, cve_ids=[cve], in_kev=True)


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def run(conn, items):
    run_id = db.start_run(conn)
    for i in items:
        update.process_item(conn, i, run_id=run_id)
    conn.commit()
    return run_id


class Receiver:
    """Ground truth: what the receiving side was called with and accepted."""

    def __init__(self):
        self.calls, self.accepted = [], []

    def sender(self, channel, mode="ok", during=None):
        def send(message):
            self.calls.append((channel, message))
            if mode == "refuse":
                raise ConnectionRefusedError("refused")
            if during:
                during()
            self.accepted.append((channel, message))
            if mode == "timeout":
                raise TimeoutError("response lost after accept")
        return send

    def senders(self, **modes):
        return {c: self.sender(c, modes.get(c, "ok")) for c in proto.CHANNELS}

    def on(self, channel):
        return [m for c, m in self.accepted if c == channel]


class Proxy:
    """Runs ``hook`` once, just before the first claim UPDATE of the wrapped connection."""

    def __init__(self, conn, hook):
        self.conn, self.hook, self.fired = conn, hook, False

    def execute(self, sql, *args):
        if not self.fired and sql.startswith("UPDATE notification_log SET state = 'sending'"):
            self.fired = True
            self.hook()
        return self.conn.execute(sql, *args)

    def commit(self):
        self.conn.commit()


class LedgerDB(unittest.TestCase):
    """A migrated DB with a baseline and one new KEV event (two planned rows)."""

    V2 = False

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "ledger.db"
        conn = sqlite3.connect(self.path)
        legacy_schema(conn)
        conn.close()
        with contextlib.closing(connect(self.path)) as conn:
            run(conn, [kev("CVE-2026-99001")])
            mig.migrate(conn)
            ledger.derive_events(conn, 0, T0, baseline=True)
            (v2.add_lease_columns if self.V2 else proto.install)(conn)
            ledger.derive_events(conn, run(conn, [kev(KEV_B)]), T0)
        self.a, self.b = connect(self.path), connect(self.path)
        self.receiver = Receiver()

    def tearDown(self):
        self.a.close()
        self.b.close()
        self._tmp.cleanup()

    def row(self, channel):
        return self.a.execute("SELECT * FROM notification_log WHERE channel = ?", (channel,)).fetchone()


# ---------------------------------------------------------------------------
# 1. ABA: owner names are reused; every claim needs its own token
# ---------------------------------------------------------------------------

class CurrentV2Aba(LedgerDB):
    V2 = True

    def test_stale_finalize_with_reused_owner_name_is_accepted(self):
        v2.claim(self.a, "runner", T0, T_LEASE)
        row = self.row("ntfy")["id"]
        v2.claim(self.a, "other", T10, T15)
        self.a.execute("UPDATE notification_log SET state = 'unknown', owner = NULL WHERE id = ?", (row,))
        self.a.commit()
        v2.claim(self.a, "runner", "2026-10-22T00:20:00+00:00", "2026-10-22T00:25:00+00:00")
        self.assertTrue(v2.finalize(self.a, row, "runner", "sent"))


class SpecTokenFencing(LedgerDB):
    def aba(self):
        first = dict((r, t) for r, t, _ in proto.claim(self.a, "runner", T0, T_LEASE))
        second = dict((r, t) for r, t, _ in proto.claim(self.a, "runner", T10, T15))  # same owner name
        return first, second

    def test_every_claim_gets_a_new_token_and_fence(self):
        first, second = self.aba()
        row = self.row("ntfy")
        self.assertNotEqual(first[row["id"]], second[row["id"]])
        self.assertEqual(row["fence"], 2)

    def test_stale_token_updates_zero_rows(self):
        first, second = self.aba()
        row = self.row("ntfy")["id"]
        self.assertFalse(proto.finalize(self.a, row, "runner", "sent", token=first[row]))
        self.assertEqual((self.row("ntfy")["state"], self.row("ntfy")["token"]), ("sending", second[row]))
        self.assertTrue(proto.finalize(self.a, row, "runner", "sent", token=second[row]))

    def test_owner_and_token_must_both_match(self):
        claims = proto.claim(self.a, "A", T0, T_LEASE)
        row, token, _ = claims[0]
        self.assertFalse(proto.finalize(self.a, row, "B", "sent", token=token))
        self.assertFalse(proto.finalize(self.a, row, "A", "sent", token=None))
        self.assertFalse(proto.finalize(self.a, row, "A", "sent", token=token + "x"))
        self.assertTrue(proto.finalize(self.a, row, "A", "sent", token=token))

    def test_negative_owner_only_finalize_accepts_stale_claim(self):
        first, _ = self.aba()
        row = self.row("ntfy")["id"]

        def owner_only(conn, row_id, owner, state, error=None, token=None):
            return conn.execute("UPDATE notification_log SET state = ? WHERE id = ? AND owner = ? AND "
                                "state = 'sending'", (state, row_id, owner)).rowcount == 1
        with self.assertRaises(AssertionError):
            self.assertFalse(owner_only(self.a, row, "runner", "sent", token=first[row]))


# ---------------------------------------------------------------------------
# 2. Lease: UTC integers, skew margin, re-check before send, unavoidable duplicates
# ---------------------------------------------------------------------------

class CurrentV2Lease(LedgerDB):
    V2 = True

    def test_offset_text_comparison_steals_live_lease(self):
        v2.claim(self.a, "A", T0, T_LEASE)
        stolen = v2.claim(self.b, "B", "2026-10-22T09:01:00+09:00", "2026-10-22T09:06:00+09:00")  # 00:01Z
        self.assertEqual(len(stolen), 2)

    def test_no_recheck_sends_a_row_already_taken_over(self):
        b = lambda: v2.deliver(self.b, self.receiver.senders(), "B", T10, T15)
        senders = self.receiver.senders()
        senders["ntfy"] = self.receiver.sender("ntfy", during=b)
        v2.deliver(self.a, senders, "A", T0, T_LEASE)
        self.assertEqual(len(self.receiver.on("email")), 2)
        self.assertEqual(sum(LABEL not in m for m in self.receiver.on("email")), 1)


class SpecLease(LedgerDB):
    def test_utc_offsets_do_not_cause_early_reclaim(self):
        proto.claim(self.a, "A", T0, T_LEASE)
        self.assertEqual(proto.claim(self.b, "B", "2026-10-22T09:01:00+09:00", "2026-10-22T09:06:00+09:00"), [])
        self.assertEqual(len(proto.claim(self.b, "B", "2026-10-22T09:07:00+09:00", "2026-10-22T09:12:00+09:00")), 2)

    def test_timestamps_without_offset_are_rejected(self):
        with self.assertRaises(ValueError):
            proto.claim(self.a, "A", "2026-10-22T00:00:00", T_LEASE)

    def test_skew_margin_delays_reclaim(self):
        proto.claim(self.a, "A", T0, T_LEASE)
        self.assertEqual(proto.claim(self.b, "B", T_PAST_LEASE_IN_SKEW, T10), [])
        self.assertEqual(len(proto.claim(self.b, "B", T_PAST_SKEW, T10)), 2)

    def test_recheck_before_send_blocks_a_row_taken_over(self):
        outcome = {}
        b = lambda: outcome.setdefault("b", proto.deliver(self.b, self.receiver.senders(), "B", T10, T15))
        senders = self.receiver.senders()
        senders["ntfy"] = self.receiver.sender("ntfy", during=b)
        # A's clock reads T0 for its first send; by the time it reaches email, B has run and it is T10.
        a = proto.deliver(self.a, senders, "A", T0, T_LEASE, clock=lambda: T10 if "b" in outcome else T0)
        # Receiver: email exactly once (A never started it; B sent it plainly).
        self.assertEqual(len(self.receiver.on("email")), 1)
        self.assertNotIn(LABEL, self.receiver.on("email")[0])
        # DB: A's email claim lost on re-check; B owns the outcome.
        self.assertIn((f"cve:{KEV_B}:kev_listed", "email"), a["not_owner"])
        self.assertEqual((self.row("email")["state"], self.row("email")["sends"]), ("sent", 1))

    def test_owner_past_its_own_lease_does_not_start_a_send(self):
        a = proto.deliver(self.a, self.receiver.senders(), "A", T0, T_LEASE, clock=lambda: T10)  # nobody took over
        self.assertEqual(self.receiver.calls, [])  # receiver: nothing
        self.assertEqual(len(a["not_owner"]), 2)
        self.assertEqual((self.row("ntfy")["send_started"], self.row("ntfy")["sends"]), (0, 0))  # DB
        proto.deliver(self.b, self.receiver.senders(), "B", T10, T15)
        self.assertEqual([LABEL in m for m in self.receiver.on("ntfy")], [False])  # provably unsent: plain

    def test_skew_margin_also_applies_to_started_sends(self):
        proto.prepare(self.a, "A", T0, T_LEASE)  # published-mode claims: send_started = 1
        self.assertEqual(proto.claim(self.b, "B", T_PAST_LEASE_IN_SKEW, T10), [])
        self.assertEqual([p for _, _, p in proto.claim(self.b, "B", T_PAST_SKEW, T10)], [True, True])

    def test_published_claim_taken_over_in_same_db_is_not_sent_again(self):
        prepared = proto.prepare(self.a, "A", T0, T_LEASE)
        proto.deliver(self.b, self.receiver.senders(), "B", T10, T15)  # B reclaims and sends labelled
        result = proto.send_prepared(self.a, prepared, self.receiver.senders(), T0, prepared["generation"])
        self.assertEqual(result, ["not_owner", "not_owner"])
        for channel in proto.CHANNELS:
            self.assertEqual([LABEL in m for m in self.receiver.on(channel)], [True])  # receiver: once
            self.assertEqual((self.row(channel)["state"], self.row(channel)["sends"]), ("sent", 2))  # DB

    def test_limit_send_in_flight_when_lease_expires_is_duplicated_but_labelled(self):
        """Cannot be prevented: A passed the re-check and is inside the external call."""
        b = lambda: proto.deliver(self.b, self.receiver.senders(), "B", T10, T15)
        senders = self.receiver.senders()
        senders["ntfy"] = self.receiver.sender("ntfy", during=b)
        a = proto.deliver(self.a, senders, "A", T0, T_LEASE, clock=lambda: T0)
        ntfy = self.receiver.on("ntfy")
        self.assertEqual(len(ntfy), 2)  # receiver: duplicate
        self.assertEqual([LABEL in m for m in ntfy], [True, False])  # B's labelled resend lands first
        self.assertIn((f"cve:{KEV_B}:kev_listed", "ntfy"), a["unrecorded"])  # DB: A could not record
        self.assertEqual((self.row("ntfy")["state"], self.row("ntfy")["sends"]), ("sent", 2))

    def test_negative_without_skew_margin_reclaims_early(self):
        proto.claim(self.a, "A", T0, T_LEASE)
        with patch.object(proto, "MAX_SKEW_US", 0):
            taken = proto.claim(self.b, "B", T_PAST_LEASE_IN_SKEW, T10, max_skew_us=proto.MAX_SKEW_US)
        with self.assertRaises(AssertionError):
            self.assertEqual(taken, [])

    def test_negative_without_recheck_duplicates_email(self):
        """Unsafe variant: A skips the owner/token re-check and the guarded send_started update."""
        outcome = {}
        b = lambda: outcome.setdefault("b", proto.deliver(self.b, self.receiver.senders(), "B", T10, T15))
        senders = self.receiver.senders()
        senders["ntfy"] = self.receiver.sender("ntfy", during=b)
        original = proto.send_claimed

        def no_recheck(conn, row_id, owner, token, possibly, s, now, max_attempts=3, published=False):
            if owner != "A":
                return original(conn, row_id, owner, token, possibly, s, now, max_attempts, published)
            conn.execute("UPDATE notification_log SET send_started = 1, sends = sends + 1 WHERE id = ?", (row_id,))
            conn.commit()
            with patch.object(proto, "owns", lambda *a, **k: True):
                return original(conn, row_id, owner, token, possibly, s, now, max_attempts, published=True)
        with patch.object(proto, "send_claimed", no_recheck):
            proto.deliver(self.a, senders, "A", T0, T_LEASE, clock=lambda: T10 if "b" in outcome else T0)
        self.assertIn("b", outcome)
        with self.assertRaises(AssertionError):
            self.assertEqual(len(self.receiver.on("email")), 1)


# ---------------------------------------------------------------------------
# 3. Publication: claims travel with the data commit; send only after it is on main
# ---------------------------------------------------------------------------

class Publication(RunnerRepos):
    def collect(self, name):
        repo = self.clone(name)
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            ledger.derive_events(conn, run(conn, [kev(KEV_B)]), T0)
            prepared = proto.prepare(conn, name, T0, T_LEASE)
        return repo, prepared

    def try_push(self, repo, message):
        git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
        git("add", "-A")
        git("commit", "-q", "-m", message)
        return git("push", "-q", "origin", "HEAD:main").returncode == 0

    def send(self, repo, prepared, receiver, modes=None):
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            return proto.send_prepared(conn, prepared, receiver.senders(**(modes or {})), T0,
                                       self.remote_generation())

    def main_states(self):
        repo = self.clone(f"inspect-{uuid.uuid4().hex[:6]}")
        with contextlib.closing(connect(repo / "data/threat_intel.db")) as conn:
            return {r["channel"]: (r["state"], r["sends"]) for r in conn.execute(
                "SELECT channel, state, sends FROM notification_log WHERE event_key = ?", (f"cve:{KEV_B}:kev_listed",))}


class CurrentV2Publication(unittest.TestCase):
    def test_two_runners_on_separate_copies_both_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.db"
            conn = sqlite3.connect(base)
            legacy_schema(conn)
            conn.close()
            with contextlib.closing(connect(base)) as c:
                run(c, [kev("CVE-2026-99001")])
                mig.migrate(c)
                ledger.derive_events(c, 0, T0, baseline=True)
                v2.add_lease_columns(c)
                ledger.derive_events(c, run(c, [kev(KEV_B)]), T0)
            receiver = Receiver()
            for name in ("x.db", "y.db"):
                shutil.copy(base, Path(tmp) / name)
                with contextlib.closing(connect(Path(tmp) / name)) as c:
                    v2.deliver(c, receiver.senders(), name, T0, T_LEASE)
            self.assertEqual(len(receiver.on("ntfy")), 2)


class SpecPublication(Publication):
    def test_rejected_first_publication_never_sends(self):
        receiver = Receiver()
        a, a_prep = self.collect("A")
        b, b_prep = self.collect("B")  # same base, independent SQLite file
        self.assertTrue(self.try_push(b, "B data"))
        self.assertFalse(self.try_push(a, "A data"))  # not fast-forward
        with self.assertRaises(proto.StalePublication):
            self.send(a, a_prep, receiver)
        self.send(b, b_prep, receiver)
        self.assertEqual((len(receiver.on("ntfy")), len(receiver.on("email"))), (1, 1))
        self.assertEqual(self.main_states(), {"ntfy": ("sending", 1), "email": ("sending", 1)})

    def test_old_generation_deliverer_cannot_send_after_newer_publication(self):
        receiver = Receiver()
        a, a_prep = self.collect("A")
        self.assertTrue(self.try_push(a, "A data"))
        b = self.clone("B")
        with contextlib.closing(connect(b / "data/threat_intel.db")) as conn:
            proto.prepare(conn, "B", T0, T_LEASE)
        self.assertTrue(self.try_push(b, "B data"))
        with self.assertRaises(proto.StalePublication):  # A wakes up late
            self.send(a, a_prep, receiver)
        self.assertEqual(receiver.accepted, [])

    def test_lost_or_rejected_result_commit_keeps_possible_duplicate(self):
        for lose in ("skipped", "rejected"):
            with self.subTest(result_commit=lose):
                receiver = Receiver()
                a, a_prep = self.collect(f"A-{lose}")
                self.assertTrue(self.try_push(a, "A data"))
                self.send(a, a_prep, receiver)
                if lose == "rejected":
                    other = self.clone(f"other-{lose}")
                    (other / "README.md").write_text("concurrent change\n")
                    self.assertTrue(self.try_push(other, "concurrent"))
                    self.assertFalse(self.try_push(a, "A results"))
                nxt = self.clone(f"next-{lose}")
                with contextlib.closing(connect(nxt / "data/threat_intel.db")) as conn:
                    proto.deliver(conn, receiver.senders(), "next", T10, T15)
                    states = {r["channel"]: (r["state"], r["sends"]) for r in conn.execute(
                        "SELECT channel, state, sends FROM notification_log WHERE event_key = ?",
                        (f"cve:{KEV_B}:kev_listed",))}
                self.assertEqual(states, {"ntfy": ("sent", 2), "email": ("sent", 2)})
                for channel in proto.CHANNELS:
                    self.assertEqual([LABEL in m for m in receiver.on(channel)], [False, True])
                # repeat on a fresh remote state for the second subtest
                self.tearDown()
                self.setUp()

    def test_negative_without_publication_gate_rejected_runner_sends(self):
        receiver = Receiver()
        a, a_prep = self.collect("A")
        b, b_prep = self.collect("B")
        self.try_push(b, "B data")
        self.try_push(a, "A data")
        self.send(b, b_prep, receiver)
        with contextlib.closing(connect(a / "data/threat_intel.db")) as conn:  # gate skipped
            for row_id, token, possibly in a_prep["claims"]:
                proto.send_claimed(conn, row_id, "A", token, possibly, receiver.senders(), T0, published=True)
        with self.assertRaises(AssertionError):
            self.assertEqual(len(receiver.on("ntfy")), 1)


# ---------------------------------------------------------------------------
# 4. Restore into an existing DB
# ---------------------------------------------------------------------------

def rows_in_all_states():
    return [(f"cve:CVE-2026-9910{i}:kev_listed", "kev_listed", "ntfy", state, attempts, sends, error)
            for i, (state, attempts, sends, error) in enumerate([
                ("sent", 1, 1, None), ("failed", 1, 1, "ConnectionRefusedError"), ("sending", 1, 1, None),
                ("unknown", 2, 2, "TimeoutError"), ("abandoned", 3, 3, "retry limit reached")])]


class CurrentV2Restore(LedgerDB):
    V2 = True

    def test_import_into_existing_rows_fails_midway(self):
        v2.deliver(self.a, self.receiver.senders(email="refuse"), "A", T0, T_LEASE)
        rows = v2.export_channel_state(self.a)
        with self.assertRaises(sqlite3.IntegrityError):
            v2.import_channel_state(self.b, rows, T0)
        self.assertTrue(self.b.in_transaction)  # partial work left open for the caller to commit


class SpecRestore(LedgerDB):
    def count(self):
        return self.a.execute("SELECT count(*) FROM notification_log").fetchone()[0]

    def test_all_states_round_trip_and_sending_becomes_unknown(self):
        report = proto.import_channel_state(self.b, rows_in_all_states(), T0)
        self.assertEqual(report, {"inserted": 5, "unchanged": 0, "held": []})
        states = [r[0] for r in self.a.execute(
            "SELECT state FROM notification_log WHERE event_key LIKE 'cve:CVE-2026-9910%' ORDER BY event_key")]
        self.assertEqual(states, ["sent", "failed", "unknown", "unknown", "abandoned"])

    def test_reimport_is_idempotent(self):
        proto.import_channel_state(self.b, rows_in_all_states(), T0)
        before = self.count()
        report = proto.import_channel_state(self.b, rows_in_all_states(), T0)
        self.assertEqual((report["inserted"], report["held"], self.count()), (0, [], before))

    def test_import_into_db_with_identical_rows_is_noop(self):
        rows = proto.export_channel_state(self.a)
        report = proto.import_channel_state(self.b, rows, T0)
        self.assertEqual((report["inserted"], report["unchanged"], report["held"]), (0, 2, []))

    def test_partial_failure_rolls_back_everything(self):
        before = self.count()

        def fault(index):
            if index == 3:
                raise RuntimeError("disk full")
        with self.assertRaises(RuntimeError):
            proto.import_channel_state(self.b, rows_in_all_states(), T0, _fault=fault)
        self.assertEqual(self.count(), before)
        self.assertFalse(self.b.in_transaction)

    def test_conflicting_result_is_held_not_overwritten_and_not_sent(self):
        proto.deliver(self.a, self.receiver.senders(email="refuse"), "A", T0, T_LEASE)  # email failed here
        imported = [r if r[2] != "email" else (r[0], r[1], "email", "sent", 1, 1, None)
                    for r in proto.export_channel_state(self.a)]
        report = proto.import_channel_state(self.b, imported, T0)
        self.assertEqual(report["held"], [(f"cve:{KEV_B}:kev_listed", "email")])
        self.assertEqual(self.row("email")["state"], "failed")  # DB: not guessed
        proto.deliver(self.a, self.receiver.senders(), "C", T10, T15)
        self.assertEqual(self.receiver.on("email"), [])  # receiver: never accepted an email
        self.assertEqual([c for c, _ in self.receiver.calls].count("email"), 1)  # only the original refused call
        self.assertEqual(self.row("email")["state"], "failed")  # DB: still held, not claimed by C

    def test_strict_mode_refuses_whole_import(self):
        before = self.count()
        conflicting = [(f"cve:{KEV_B}:kev_listed", "kev_listed", "ntfy", "sent", 1, 1, None)] + rows_in_all_states()
        with self.assertRaises(proto.RestoreConflict):
            proto.import_channel_state(self.b, rows_in_all_states() + conflicting[:1], T0, strict=True)
        self.assertEqual(self.count(), before)

    def test_negative_overwriting_import_changes_conflicting_state(self):
        proto.deliver(self.a, self.receiver.senders(email="refuse"), "A", T0, T_LEASE)
        self.a.execute("UPDATE notification_log SET state = 'sent', last_error = NULL WHERE channel = 'email'")
        with self.assertRaises(AssertionError):
            self.assertEqual(self.row("email")["state"], "failed")


# ---------------------------------------------------------------------------
# 5. CVSS observations
# ---------------------------------------------------------------------------

class CurrentV2Cvss(unittest.TestCase):
    def test_conflicting_duplicate_id_is_silently_dropped(self):
        history, _ = v2.cvss_events("CVE-X", [("lm-1", 9.8), ("lm-1", 4.0)])
        self.assertEqual(history, [("lm-1", 9.8)])

    def test_arrival_order_is_used_as_time_order(self):
        _, events = v2.cvss_events("CVE-X", [("t3", 9.1), ("t1", 5.0), ("t2", 9.8)])
        self.assertEqual([k for _, k, _ in events], ["first_critical", "downgrade", "re_critical"])


class SpecCvss(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        legacy_schema(self.conn)
        mig.migrate(self.conn)
        proto.install(self.conn)

    def ingest(self, lm, score, source="nvd", vector=None):
        return proto.cvss_ingest(self.conn, "CVE-X", source, lm, score, vector)

    def test_same_id_different_content_is_reported_as_conflict(self):
        history, _, conflicts = proto.cvss_events_checked("CVE-X", [("lm-1", 9.8), ("lm-1", 4.0)])
        self.assertEqual((history, conflicts), ([("lm-1", 9.8)], [("lm-1", 9.8, 4.0)]))

    def test_ingest_conflict_is_quarantined_and_original_kept(self):
        self.assertEqual(self.ingest("2026-10-01T00:00:00Z", 9.8), "inserted")
        self.assertEqual(self.ingest("2026-10-01T00:00:00+00:00", 4.0), "conflict")  # same instant
        self.assertEqual([r[0] for r in self.conn.execute("SELECT score FROM cvss_observations")], [9.8])
        self.assertEqual([r[0] for r in self.conn.execute("SELECT rejected_score FROM cvss_conflicts")], [4.0])

    def test_reingest_identical_content_is_noop(self):
        self.ingest("2026-10-01T00:00:00Z", 9.8)
        first = proto.cvss_new_events(self.conn, "CVE-X")
        self.assertEqual(self.ingest("2026-10-01T09:00:00+09:00", 9.8), "duplicate")
        self.assertEqual(proto.cvss_new_events(self.conn, "CVE-X")["events"], [])
        self.assertEqual(len(first["events"]), 1)

    def test_out_of_order_arrival_is_sorted_by_time(self):
        for lm, score in (("2026-10-03T00:00:00Z", 9.1), ("2026-10-01T00:00:00Z", 5.0),
                          ("2026-10-02T00:00:00Z", 9.8)):
            self.ingest(lm, score)
        result = proto.cvss_new_events(self.conn, "CVE-X")
        self.assertEqual([(k, s) for _, k, s in result["events"]], [("first_critical", 9.8)])

    def test_late_observation_goes_to_history_without_alert(self):
        self.ingest("2026-10-01T00:00:00Z", 5.0)
        self.ingest("2026-10-03T00:00:00Z", 9.8)
        proto.cvss_new_events(self.conn, "CVE-X")
        self.ingest("2026-10-02T00:00:00Z", 9.9)  # arrives after the watermark, but is older
        result = proto.cvss_new_events(self.conn, "CVE-X")
        self.assertEqual(result["events"], [])
        self.assertEqual([score for _, score in result["late"]], [9.9])
        self.assertEqual(len(result["history"]), 3)

    def test_last_modified_is_not_assumed_unique(self):
        self.assertEqual(self.ingest("2026-10-01T00:00:00Z", 9.8, vector="AV:N"), "inserted")
        self.assertEqual(self.ingest("2026-10-01T00:00:00Z", 9.8, vector="AV:L"), "conflict")
        self.assertEqual(self.ingest("2026-10-01T00:00:00Z", 7.0, source="ghsa"), "inserted")

    def test_naive_last_modified_is_rejected(self):
        with self.assertRaises(ValueError):
            self.ingest("2026-10-01T00:00:00", 9.8)

    def test_negative_replace_on_conflict_silently_changes_history(self):
        self.ingest("2026-10-01T00:00:00Z", 9.8)
        self.conn.execute("INSERT OR REPLACE INTO cvss_observations (cve_id, source, last_modified_us, content_hash, "
                          "score) VALUES ('CVE-X', 'nvd', ?, 'other', 4.0)", (proto.utc_us("2026-10-01T00:00:00Z"),))
        with self.assertRaises(AssertionError):
            self.assertEqual(self.conn.execute("SELECT score FROM cvss_observations").fetchall(), [(9.8,)])


# ---------------------------------------------------------------------------
# 6. Published history
# ---------------------------------------------------------------------------

class HistoryV3(History):
    def check(self):
        with contextlib.closing(connect(self.db)) as conn:
            return proto.history_check(self.repo, conn)

    def archive(self, run_id):
        return next((self.repo / "reports").glob(f"daily_report_*_run{run_id}.md"))


class CurrentV2History(HistoryV3):
    def v2check(self):
        with contextlib.closing(connect(self.db)) as conn:
            return v2.history_check(self.repo, conn)

    def test_earlier_dated_duplicate_archive_passes(self):
        self.publish_runs(self.STARTS)
        text = self.archive(2).read_text(encoding="utf-8").replace("2026-10-02 00:30:00", "2026-09-30 00:30:00")
        (self.repo / "reports/daily_report_2026-09-30_run2.md").write_text(text, encoding="utf-8")
        self.assertTrue(self.v2check()["ok"])

    def test_name_content_mismatch_and_invalid_date_pass(self):
        self.publish_runs(self.STARTS)
        self.archive(3).rename(self.repo / "reports/daily_report_2026-10-07_run3.md")
        self.archive(1).rename(self.repo / "reports/daily_report_2026-13-45_run1.md")
        self.assertTrue(self.v2check()["ok"])


class SpecHistoryV3(HistoryV3):
    def test_duplicate_archive_for_one_run_is_rejected(self):
        self.publish_runs(self.STARTS)
        text = self.archive(2).read_text(encoding="utf-8").replace("2026-10-02 00:30:00", "2026-09-30 00:30:00")
        (self.repo / "reports/daily_report_2026-09-30_run2.md").write_text(text, encoding="utf-8")
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertEqual(result["duplicate_runs"], [2])

    def test_name_content_mismatch_is_rejected(self):
        self.publish_runs(self.STARTS)
        self.archive(3).rename(self.repo / "reports/daily_report_2026-10-07_run3.md")
        self.assertIn("name_content_mismatch:daily_report_2026-10-07_run3.md", self.check()["reasons"])

    def test_invalid_dates_are_rejected(self):
        self.publish_runs(self.STARTS)
        for bad in ("2026-13-45", "2026-02-30"):
            with self.subTest(date=bad):
                path = self.repo / f"reports/daily_report_{bad}_run9.md"
                path.write_text("- 実行日時: 2026-10-01 00:30:00 〜 x (run_id=9)\n", encoding="utf-8")
                self.assertIn(f"invalid_date:{path.name}", self.check()["reasons"])
                path.unlink()
        self.archive(1).write_text("- 実行日時: 2026-10-01 25:61:00 〜 x (run_id=1)\n", encoding="utf-8")
        self.assertTrue(any(r.startswith("invalid_header_date") for r in self.check()["reasons"]))

    def test_unpublished_tail_is_allowed_but_gap_and_loss_are_not(self):
        self.publish_runs(self.STARTS)
        with contextlib.closing(connect(self.db)) as conn:
            run(conn, [raw("jpcert_alert", "https://rss.test/local", title="Not yet published")])
        result = self.check()
        self.assertEqual((result["ok"], result["unpublished_runs"]), (True, [4]))
        self.archive(2).unlink()
        result = self.check()
        self.assertFalse(result["ok"])
        self.assertEqual(result["unarchived_gaps"], [2])

    def test_manifest_distinguishes_initial_state_from_lost_archives(self):
        with contextlib.closing(connect(self.db)) as conn:
            run(conn, [raw("jpcert_alert", "https://rss.test/first", title="First run")])
        self.assertFalse(self.check()["ok"])  # no evidence: fail closed
        manifest = self.repo / proto.MANIFEST
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"published_runs": []}))
        result = self.check()
        self.assertEqual((result["ok"], result["state"]), (True, "initial"))
        manifest.write_text(json.dumps({"published_runs": [1]}))
        result = self.check()  # manifest says run 1 was published but no archive exists: loss
        self.assertFalse(result["ok"])
        self.assertIn("manifest_archive_mismatch", result["reasons"])

    def test_run_uuid_detects_same_second_reuse_that_start_time_cannot(self):
        self.publish_runs(self.STARTS)
        with contextlib.closing(connect(self.db)) as conn:
            conn.execute("ALTER TABLE run_log ADD COLUMN run_uuid TEXT")
            for run_id in (1, 2, 3):
                conn.execute("UPDATE run_log SET run_uuid = ? WHERE id = ?", (str(uuid.uuid4()), run_id))
            conn.commit()
            uuids = dict(conn.execute("SELECT id, run_uuid FROM run_log"))
        for run_id in (1, 2, 3):
            path = self.archive(run_id)
            path.write_text(path.read_text(encoding="utf-8") + f"\nrun_uuid={uuids[run_id]}\n", encoding="utf-8")
        self.assertTrue(self.check()["ok"])
        with contextlib.closing(connect(self.db)) as conn:  # same id, same start second, different run
            conn.execute("UPDATE run_log SET run_uuid = ? WHERE id = 3", (str(uuid.uuid4()),))
            conn.commit()
        self.assertEqual(self.check()["reused_runs"], [3])

    def test_limit_same_second_reuse_without_run_uuid(self):
        self.publish_runs(self.STARTS)
        self.assertTrue(self.check()["ok"])  # a same-second reuse would look exactly like this


# ---------------------------------------------------------------------------
# 7. Retry limit under concurrency
# ---------------------------------------------------------------------------

class CurrentV2RetryCap(LedgerDB):
    V2 = True

    def test_select_then_update_race_exceeds_cap(self):
        self.a.execute("UPDATE notification_log SET state = 'unknown', attempts = 2 WHERE channel = 'ntfy'")
        self.a.execute("UPDATE notification_log SET state = 'sent', attempts = 1 WHERE channel = 'email'")
        self.a.commit()
        hook = lambda: v2.deliver(self.a, self.receiver.senders(ntfy="timeout"), "A", T0, T_LEASE)
        v2.deliver(Proxy(self.b, hook), self.receiver.senders(ntfy="timeout"), "B", T0, T_LEASE)
        self.assertEqual(self.row("ntfy")["attempts"], 4)


class SpecRetryCap(LedgerDB):
    def setup_two_sends_used(self):
        self.a.execute("UPDATE notification_log SET state = 'unknown', attempts = 2, sends = 2 WHERE channel = 'ntfy'")
        self.a.execute("UPDATE notification_log SET state = 'sent', attempts = 1, sends = 1 WHERE channel = 'email'")
        self.a.commit()

    def test_race_between_select_and_update_does_not_exceed_cap(self):
        self.setup_two_sends_used()
        hook = lambda: proto.deliver(self.a, self.receiver.senders(ntfy="timeout"), "A", T0, T_LEASE)
        proto.deliver(Proxy(self.b, hook), self.receiver.senders(ntfy="timeout"), "B", T0, T_LEASE)
        ntfy_calls = [m for c, m in self.receiver.calls if c == "ntfy"]
        self.assertEqual(len(ntfy_calls), 1)  # receiver: one more call only
        self.assertEqual(self.row("ntfy")["sends"], 3)  # DB: at the cap, never above

    def test_two_deliverers_claiming_same_row_one_wins(self):
        hook = lambda: proto.claim(self.a, "A", T0, T_LEASE)
        taken = proto.claim(Proxy(self.b, hook), "B", T0, T_LEASE)
        self.assertEqual(taken, [])
        self.assertEqual({self.row(c)["owner"] for c in proto.CHANNELS}, {"A"})

    def test_cap_is_enforced_in_update_where(self):
        def exhaust():
            self.a.execute("UPDATE notification_log SET sends = 3 WHERE channel = 'ntfy'")
            self.a.commit()
        self.a.execute("UPDATE notification_log SET state = 'unknown', attempts = 2, sends = 2 WHERE channel = 'ntfy'")
        self.a.commit()
        proto.claim(Proxy(self.b, exhaust), "B", T0, T_LEASE)
        self.assertNotEqual(self.row("ntfy")["state"], "sending")

    def test_claimed_but_not_sent_is_distinguished(self):
        proto.claim(self.a, "A", T0, T_LEASE)  # A stops before sending anything
        self.assertEqual(self.row("ntfy")["sends"], 0)
        proto.deliver(self.b, self.receiver.senders(), "B", T10, T15)
        self.assertEqual([LABEL in m for m in self.receiver.on("ntfy")], [False])  # receiver: plain, once
        self.assertEqual((self.row("ntfy")["state"], self.row("ntfy")["sends"]), ("sent", 1))  # DB

    def test_negative_cap_not_in_update_where_exceeds(self):
        """Unsafe variant: the cap is not part of any UPDATE ... WHERE (max_attempts=99 at every write)."""
        self.setup_two_sends_used()
        hook = lambda: proto.deliver(self.a, self.receiver.senders(ntfy="timeout"), "A", T0, T_LEASE, 99)
        proto.deliver(Proxy(self.b, hook), self.receiver.senders(ntfy="timeout"), "B", T0, T_LEASE, 99)
        proto.deliver(self.b, self.receiver.senders(ntfy="timeout"), "C", T10, T15, 99)
        with self.assertRaises(AssertionError):
            self.assertLessEqual(self.row("ntfy")["sends"], proto.MAX_ATTEMPTS)

if __name__ == "__main__":
    unittest.main()
