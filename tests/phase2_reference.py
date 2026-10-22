"""Reference implementations (v2) of the Phase 2-E design, used only by tests.

Not collected by pytest (no ``test_`` prefix) and not imported by production
code. Each function states what it can and cannot prove; tests check those
limits explicitly. Written after Codex's independent audit of 52645e0 (P1 x5,
P2 x4); see tests/test_phase2_p1_regressions.py.
"""
import re
import uuid

CHANNELS = ("ntfy", "email")
MAX_ATTEMPTS = 3
CRITICAL = 9.0

# ---------------------------------------------------------------------------
# Published-history guard (P1-2): fail closed
# ---------------------------------------------------------------------------

ARCHIVE_NAME = re.compile(r"^daily_report_(\d{4}-\d{2}-\d{2})_run(\d+)\.md$")
ARCHIVE_HEADER = re.compile(r"^- 実行日時: (.+?) 〜 .*\(run_id=(\d+)\)\s*$", re.M)


def history_check(repo, conn):
    """Compare the DB with the archives main has published.

    Proves: every archived run id exists in run_log with the same start time
    (content header, not only the file name); the AUTOINCREMENT counter is not
    behind the newest archive; no archive is malformed.
    Cannot prove: runs that never produced an archive (failed or unpublished
    runs) and an archive rewritten consistently with a tampered DB. A missing
    or empty archive while the DB already has runs is treated as loss, because
    from the files alone it is indistinguishable from deleted history.
    """
    reasons, archived = [], {}
    reports = repo / "reports"
    db_runs = {r[0]: r[1] for r in conn.execute("SELECT id, started_at FROM run_log")}
    seq_row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'run_log'").fetchone()
    db_seq = seq_row[0] if seq_row else 0
    if reports.is_dir():
        for path in sorted(reports.iterdir()):
            if not path.name.startswith("daily_report_"):
                continue
            name = ARCHIVE_NAME.match(path.name)
            if not name:
                reasons.append(f"malformed_name:{path.name}")
                continue
            try:
                header = ARCHIVE_HEADER.search(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                header = None
            run_id = int(name.group(2))
            if not header or int(header.group(2)) != run_id:
                reasons.append(f"corrupt_archive:{path.name}")
                continue
            archived[run_id] = header.group(1)
    if not archived and not reasons:
        if db_runs or db_seq:
            reasons.append("archive_missing_or_empty_but_db_has_runs")
        return {"ok": not reasons, "state": "initial" if not reasons else "loss",
                "reasons": reasons, "max_published": 0, "db_seq": db_seq, "missing_runs": [], "reused_runs": []}
    max_published = max(archived, default=0)
    missing = sorted(r for r in archived if r not in db_runs)
    reused = sorted(r for r, started in archived.items() if r in db_runs and db_runs[r] != started)
    if db_seq < max_published:
        reasons.append("db_behind_published_history")
    if missing:
        reasons.append("archived_runs_missing_from_db")
    if reused:
        reasons.append("run_id_reused")
    return {"ok": not reasons, "state": "consistent" if not reasons else "loss", "reasons": reasons,
            "max_published": max_published, "db_seq": db_seq, "missing_runs": missing, "reused_runs": reused}


def filename_only_reuse_check(repo, conn):
    """Weaker variant using only the date in the file name (documented limit)."""
    reused = []
    for path in (repo / "reports").glob("daily_report_*_run*.md"):
        m = ARCHIVE_NAME.match(path.name)
        row = conn.execute("SELECT started_at FROM run_log WHERE id = ?", (int(m.group(2)),)).fetchone() if m else None
        if row and row[0][:10] != m.group(1):
            reused.append(int(m.group(2)))
    return sorted(reused)


# ---------------------------------------------------------------------------
# CVSS observation events (P1-3)
# ---------------------------------------------------------------------------

def cvss_events(cve_id, observations):
    """observations: ordered (observation_id, score) pairs, e.g. NVD lastModified.

    Returns (history, events). Re-collecting the same observation id is a no-op;
    a new observation with an unchanged score is kept in history without an
    alert. Event keys carry the observation id, so recurring transitions with
    equal scores never collide. No observations -> no history, no events.
    """
    history, events, seen = [], [], set()
    previous, ever_critical = None, False
    for observation_id, score in observations:
        if observation_id in seen:
            continue
        seen.add(observation_id)
        history.append((observation_id, score))
        kind = None
        if score >= CRITICAL and (previous is None or previous < CRITICAL):
            kind = "re_critical" if ever_critical else "first_critical"
            ever_critical = True
        elif previous is not None and score >= CRITICAL and score > previous:
            kind = "increase"
        elif previous is not None and previous >= CRITICAL > score:
            kind = "downgrade"
        if kind:
            events.append((f"cve:{cve_id}:cvss:{kind}:obs:{observation_id}", kind, score))
        previous = score
    return history, events


# ---------------------------------------------------------------------------
# Ledger v2 (P1-1, P1-4, P1-5, P2-1)
# ---------------------------------------------------------------------------

class NotDelivered(Exception):
    """Raised by a sender only when the receiver provably did not accept."""


DEFINITE_FAILURES = (NotDelivered, ConnectionRefusedError)


def add_lease_columns(conn):
    """Columns the v2 ledger needs on top of schema_phase2.sql (design change)."""
    for column in ("owner TEXT", "lease_until TEXT"):
        conn.execute(f"ALTER TABLE notification_log ADD COLUMN {column}")
    conn.commit()


def claim(conn, owner, now, lease_until, max_attempts=MAX_ATTEMPTS):
    """Atomically take sendable rows. A live 'sending' row of another owner is never touched;
    an expired one is reclaimed as 'unknown' (delivery cannot be proven)."""
    conn.execute("UPDATE notification_log SET state = 'unknown', owner = NULL, lease_until = NULL "
                 "WHERE state = 'sending' AND lease_until < ?", (now,))
    conn.execute("UPDATE notification_log SET state = 'abandoned', last_error = COALESCE(last_error, "
                 "'retry limit reached with unproven delivery') "
                 "WHERE state IN ('failed', 'unknown') AND attempts >= ?", (max_attempts,))
    conn.commit()
    claimed = []
    for row_id, state in conn.execute(
            "SELECT id, state FROM notification_log WHERE state IN ('planned', 'failed', 'unknown') "
            "AND attempts < ? ORDER BY id", (max_attempts,)).fetchall():
        # attempts is counted at claim time: schema_phase2.sql requires attempts >= 1 for every
        # non-planned row. Invariant: invocations <= attempts <= invocations + crashes between
        # claim and send (each such crash leaves an 'unknown' row that is resent labelled).
        cur = conn.execute(
            "UPDATE notification_log SET state = 'sending', owner = ?, lease_until = ?, delivery_id = ?, "
            "attempts = attempts + 1, last_attempt_at = ? WHERE id = ? AND state = ?",
            (owner, lease_until, uuid.uuid4().hex, now, row_id, state))
        conn.commit()
        if cur.rowcount == 1:
            claimed.append((row_id, state == "unknown"))
    return claimed


def finalize(conn, row_id, owner, state, error=None):
    cur = conn.execute("UPDATE notification_log SET state = ?, last_error = ?, owner = NULL, lease_until = NULL "
                       "WHERE id = ? AND owner = ? AND state = 'sending'", (state, error, row_id, owner))
    conn.commit()
    return cur.rowcount == 1


def deliver(conn, senders, owner, now, lease_until, max_attempts=MAX_ATTEMPTS):
    outcome = {"sent": [], "failed": [], "unknown": [], "lost_lease": []}
    for row_id, possibly_sent in claim(conn, owner, now, lease_until, max_attempts):
        key, channel, delivery_id = conn.execute(
            "SELECT event_key, channel, delivery_id FROM notification_log WHERE id = ?", (row_id,)).fetchone()
        message = f"{key} (delivery {delivery_id})"
        if possibly_sent:
            message = "[再送の可能性あり] " + message
        try:
            senders[channel](message)
        except DEFINITE_FAILURES as exc:
            state, error = "failed", f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # noqa: BLE001 - outcome unknown: may have been accepted
            state, error = "unknown", f"{type(exc).__name__}: {exc}"
        else:
            state, error = "sent", None
        if finalize(conn, row_id, owner, state, error):
            outcome[state].append((key, channel))
        else:
            outcome["lost_lease"].append((key, channel))
    return outcome


def export_channel_state(conn):
    return [tuple(r) for r in conn.execute(
        "SELECT e.event_key, e.event_type, l.channel, l.state, l.attempts, l.last_error "
        "FROM notification_events e JOIN notification_log l ON l.event_key = e.event_key ORDER BY l.id")]


def import_channel_state(conn, rows, now):
    """Restore per-channel state after a DB restore. In-flight rows come back as 'unknown'."""
    for key, event_type, channel, state, attempts, error in rows:
        conn.execute("INSERT OR IGNORE INTO notification_events (event_key, event_type, run_id, created_at) "
                     "VALUES (?, ?, 0, ?)", (key, event_type, now))
        restored = "unknown" if state == "sending" else state
        conn.execute("INSERT INTO notification_log (event_key, channel, state, attempts, last_error) "
                     "VALUES (?, ?, ?, ?, ?)",
                     (key, channel, restored, max(attempts, 1) if restored != "planned" else 0,
                      error if restored != "failed" else (error or "restored failed state")))
    conn.commit()
