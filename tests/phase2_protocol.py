"""Phase 2-E v3: one test-only protocol for publication (P0) and delivery (P1).

Not collected by pytest and not imported by production code. Every Phase 2-E
spec test (P0, P1 and v3) goes through this module; tests/phase2_reference.py
is kept frozen as v2 only to reproduce its defects.

Row states (notification_log.state) and transitions:

  planned --claim--> sending(owner, token, lease) --send--> sent | failed | unknown
  sending, lease + max skew passed, send_started=1 --> unknown  (delivery unproven)
  sending, lease + max skew passed, send_started=0 --> failed   (provably never sent)
  failed | unknown --claim (sends < max)--> sending
  failed | unknown, sends >= max --> abandoned
  any row with an unresolved restore conflict --> not claimable (held)

Two claim modes:
  local:     one shared SQLite file; send_started/sends are recorded (committed)
             immediately before the external call, after re-checking owner+token.
  published: claims are made before the data commit and published with it
             (send_started=1, sends+1 at claim). Sending is allowed only after
             that commit is on main and main's generation equals the claimer's.
             Across runners only the published copy is visible, so a lost
             result commit is always treated as "possibly sent".

What this cannot guarantee (tested explicitly):
  * an external send already in flight when its lease expires cannot be
    recalled; the reclaimer's resend is labelled, the original is not;
  * clock skew larger than MAX_SKEW_US can still cause an early reclaim;
  * 'sends' is an upper bound across runners: a published claim whose send
    never happened is still counted.
"""
import hashlib
import json
import re
import uuid
from datetime import date, datetime, timedelta, timezone

CHANNELS = ("ntfy", "email")
MAX_ATTEMPTS = 3
CRITICAL = 9.0
LEASE_US = 5 * 60 * 1_000_000
MAX_SKEW_US = 60 * 1_000_000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class NotDelivered(Exception):
    """Raised by a sender only when the receiver provably did not accept."""


DEFINITE_FAILURES = (NotDelivered, ConnectionRefusedError)


class StalePublication(Exception):
    """The claimer's generation is not the one published on main."""


class RestoreConflict(Exception):
    pass


def utc_us(value):
    """ISO-8601 with an explicit offset (or 'Z') -> integer microseconds since epoch, UTC."""
    if isinstance(value, int):
        return value
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp without UTC offset: {value!r}")
    return (parsed - EPOCH) // timedelta(microseconds=1)


# ---------------------------------------------------------------------------
# Schema additions (test-only; schema_phase2.sql is not changed)
# ---------------------------------------------------------------------------

LOG_COLUMNS = ("owner TEXT", "token TEXT", "fence INTEGER NOT NULL DEFAULT 0", "lease_until_us INTEGER",
               "sends INTEGER NOT NULL DEFAULT 0", "send_started INTEGER NOT NULL DEFAULT 0")


def install(conn):
    present = {r[1] for r in conn.execute("PRAGMA table_info(notification_log)")}
    for column in LOG_COLUMNS:
        if column.split()[0] not in present:
            conn.execute(f"ALTER TABLE notification_log ADD COLUMN {column}")
    conn.execute("CREATE TABLE IF NOT EXISTS protocol_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT OR IGNORE INTO protocol_meta VALUES ('generation', 'initial')")
    conn.execute("""CREATE TABLE IF NOT EXISTS restore_conflicts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT NOT NULL, channel TEXT NOT NULL,
        existing TEXT NOT NULL, imported TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0,
        UNIQUE (event_key, channel, imported))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cvss_observations (
        cve_id TEXT NOT NULL, source TEXT NOT NULL, last_modified_us INTEGER NOT NULL,
        content_hash TEXT NOT NULL, score REAL NOT NULL, vector TEXT, alerted INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (cve_id, source, last_modified_us))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cvss_conflicts (
        cve_id TEXT NOT NULL, source TEXT NOT NULL, last_modified_us INTEGER NOT NULL,
        kept_hash TEXT NOT NULL, rejected_hash TEXT NOT NULL, rejected_score REAL,
        PRIMARY KEY (cve_id, source, last_modified_us, rejected_hash))""")
    conn.execute("CREATE TABLE IF NOT EXISTS cvss_watermarks (cve_id TEXT PRIMARY KEY, last_modified_us INTEGER)")
    conn.commit()


add_lease_columns = install  # name used by earlier tests


def generation(conn):
    """Opaque publication id. A counter is not enough: two runners starting from the same
    base would both produce N+1, and a runner whose publication was rejected would pass."""
    return conn.execute("SELECT value FROM protocol_meta WHERE key = 'generation'").fetchone()[0]


# ---------------------------------------------------------------------------
# Claim / send / finalize
# ---------------------------------------------------------------------------

HELD = ("NOT EXISTS (SELECT 1 FROM restore_conflicts c WHERE c.event_key = notification_log.event_key "
        "AND c.channel = notification_log.channel AND c.resolved = 0)")


def _expire(conn, now_us, max_skew_us):
    conn.execute("UPDATE notification_log SET state = 'unknown', owner = NULL, token = NULL, lease_until_us = NULL "
                 "WHERE state = 'sending' AND send_started = 1 AND lease_until_us + ? < ?", (max_skew_us, now_us))
    conn.execute("UPDATE notification_log SET state = 'failed', last_error = 'claimed but provably not sent', "
                 "owner = NULL, token = NULL, lease_until_us = NULL "
                 "WHERE state = 'sending' AND send_started = 0 AND lease_until_us + ? < ?", (max_skew_us, now_us))


def claim(conn, owner, now, lease_until=None, max_attempts=MAX_ATTEMPTS, max_skew_us=MAX_SKEW_US, published=False):
    """Returns [(row_id, token, possibly_sent)]. Each claim gets a fresh token (fence)."""
    now_us = utc_us(now)
    lease_us = utc_us(lease_until) if lease_until is not None else now_us + LEASE_US
    if lease_us <= now_us:
        raise ValueError("lease must end after now")
    _expire(conn, now_us, max_skew_us)
    conn.execute("UPDATE notification_log SET state = 'abandoned', "
                 "last_error = COALESCE(last_error, 'retry limit reached') "
                 "WHERE state IN ('failed', 'unknown') AND sends >= ?", (max_attempts,))
    conn.commit()
    claimed = []
    candidates = conn.execute(
        f"SELECT id, state, fence FROM notification_log WHERE state IN ('planned', 'failed', 'unknown') "
        f"AND sends < ? AND {HELD} ORDER BY id", (max_attempts,)).fetchall()
    for row_id, state, fence in candidates:
        token = f"{fence + 1}:{uuid.uuid4().hex}"
        started = 1 if published else 0
        cur = conn.execute(
            f"UPDATE notification_log SET state = 'sending', owner = ?, token = ?, fence = fence + 1, "
            f"lease_until_us = ?, attempts = attempts + 1, last_attempt_at = ?, delivery_id = ?, "
            f"send_started = ?, sends = sends + ? "
            f"WHERE id = ? AND state = ? AND fence = ? AND sends < ? AND {HELD}",
            (owner, token, lease_us, now, uuid.uuid4().hex, started, started, row_id, state, fence, max_attempts))
        conn.commit()
        if cur.rowcount == 1:
            claimed.append((row_id, token, state == "unknown"))
    return claimed


def owns(conn, row_id, owner, token, now):
    row = conn.execute("SELECT owner, token, state, lease_until_us FROM notification_log WHERE id = ?",
                       (row_id,)).fetchone()
    return (row is not None and row[0] == owner and row[1] == token and row[2] == "sending"
            and token is not None and utc_us(now) <= row[3])


def finalize(conn, row_id, owner, state, error=None, token=None):
    """Only the current owner holding the current token can finish a row."""
    if token is None:
        return False
    cur = conn.execute("UPDATE notification_log SET state = ?, last_error = ?, owner = NULL, token = NULL, "
                       "lease_until_us = NULL WHERE id = ? AND owner = ? AND token = ? AND state = 'sending'",
                       (state, error, row_id, owner, token))
    conn.commit()
    return cur.rowcount == 1


def send_claimed(conn, row_id, owner, token, possibly_sent, senders, now, max_attempts=MAX_ATTEMPTS,
                 published=False):
    """Returns sent/failed/unknown, '<state>_unrecorded' if the send happened but the
    token was lost meanwhile, or 'not_owner' if the re-check before sending failed."""
    if not owns(conn, row_id, owner, token, now):
        return "not_owner"
    if not published:
        cur = conn.execute("UPDATE notification_log SET send_started = 1, sends = sends + 1 "
                           "WHERE id = ? AND owner = ? AND token = ? AND state = 'sending' AND send_started = 0 "
                           "AND sends < ?", (row_id, owner, token, max_attempts))
        conn.commit()
        if cur.rowcount != 1:
            return "not_owner"
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
    return state if finalize(conn, row_id, owner, state, error, token) else f"{state}_unrecorded"


def deliver(conn, senders, owner, now, lease_until=None, max_attempts=MAX_ATTEMPTS, max_skew_us=MAX_SKEW_US,
            clock=None):
    """Local mode on one shared SQLite file. ``clock`` (if given) supplies the time used
    for the re-check right before each send."""
    outcome = {"sent": [], "failed": [], "unknown": [], "not_owner": [], "unrecorded": []}
    for row_id, token, possibly in claim(conn, owner, now, lease_until, max_attempts, max_skew_us):
        result = send_claimed(conn, row_id, owner, token, possibly, senders, clock() if clock else now,
                              max_attempts)
        key, channel = conn.execute("SELECT event_key, channel FROM notification_log WHERE id = ?",
                                    (row_id,)).fetchone()
        outcome["unrecorded" if result.endswith("_unrecorded") else result].append((key, channel))
    return outcome


# Published mode (P0): claim before the data commit, send only after it is on main.

def prepare(conn, owner, now, lease_until=None, max_attempts=MAX_ATTEMPTS):
    gen = uuid.uuid4().hex
    conn.execute("UPDATE protocol_meta SET value = ? WHERE key = 'generation'", (gen,))
    conn.commit()
    return {"generation": gen, "owner": owner,
            "claims": claim(conn, owner, now, lease_until, max_attempts, published=True)}


def send_prepared(conn, prepared, senders, now, published_generation):
    if published_generation != prepared["generation"] or generation(conn) != published_generation:
        raise StalePublication(f"published generation {published_generation} != {prepared['generation']}")
    return [send_claimed(conn, row_id, prepared["owner"], token, possibly, senders, now, published=True)
            for row_id, token, possibly in prepared["claims"]]


# ---------------------------------------------------------------------------
# Restore of per-channel state (all-or-nothing, conflicts held, never guessed)
# ---------------------------------------------------------------------------

def export_channel_state(conn):
    return [tuple(r) for r in conn.execute(
        "SELECT e.event_key, e.event_type, l.channel, l.state, l.attempts, l.sends, l.last_error "
        "FROM notification_events e JOIN notification_log l ON l.event_key = e.event_key ORDER BY l.id")]


def _normalize(state, attempts, sends, error):
    if state == "sending":
        return "unknown", max(attempts, 1), max(sends, 1), "restored in-flight row (delivery unproven)"
    if state == "planned":
        return "planned", 0, 0, error
    if state == "failed":
        return "failed", max(attempts, 1), sends, error or "restored failed row"
    return state, max(attempts, 1), sends, error


def import_channel_state(conn, rows, now, strict=False, _fault=None):
    """Insert missing rows; identical rows are no-ops; differing rows are held (or, with
    strict=True, the whole import is refused). Any exception rolls everything back."""
    report = {"inserted": 0, "unchanged": 0, "held": []}
    conn.commit()
    conn.execute("SAVEPOINT import_channels")
    try:
        for index, (key, event_type, channel, state, attempts, sends, error) in enumerate(rows):
            if _fault:
                _fault(index)
            st, at, se, er = _normalize(state, attempts, sends, error)
            existing = conn.execute("SELECT state, attempts, sends FROM notification_log "
                                    "WHERE event_key = ? AND channel = ?", (key, channel)).fetchone()
            if existing is None:
                conn.execute("INSERT OR IGNORE INTO notification_events (event_key, event_type, run_id, created_at) "
                             "VALUES (?, ?, 0, ?)", (key, event_type, now))
                conn.execute("INSERT INTO notification_log (event_key, channel, state, attempts, sends, "
                             "send_started, last_error) VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (key, channel, st, at, se, 1 if se else 0, er))
                report["inserted"] += 1
            elif tuple(existing) == (st, at, se):
                report["unchanged"] += 1
            else:
                if strict:
                    raise RestoreConflict(f"{key}/{channel}: existing {tuple(existing)} vs imported {(st, at, se)}")
                conn.execute("INSERT OR IGNORE INTO restore_conflicts (event_key, channel, existing, imported) "
                             "VALUES (?, ?, ?, ?)", (key, channel, json.dumps(list(existing)),
                                                     json.dumps([st, at, se])))
                report["held"].append((key, channel))
        conn.execute("RELEASE import_channels")
        conn.commit()
    except BaseException:
        conn.execute("ROLLBACK TO import_channels")
        conn.execute("RELEASE import_channels")
        conn.commit()
        raise
    return report


# ---------------------------------------------------------------------------
# CVSS observations
# ---------------------------------------------------------------------------

def _transitions(cve_id, observations):
    """observations: [(obs_key, score)] already in time order -> [(event_key, kind, score)]."""
    events, previous, ever_critical = [], None, False
    for obs_key, score in observations:
        kind = None
        if score >= CRITICAL and (previous is None or previous < CRITICAL):
            kind = "re_critical" if ever_critical else "first_critical"
            ever_critical = True
        elif previous is not None and score >= CRITICAL and score > previous:
            kind = "increase"
        elif previous is not None and previous >= CRITICAL > score:
            kind = "downgrade"
        if kind:
            events.append((f"cve:{cve_id}:cvss:{kind}:obs:{obs_key}", kind, score))
        previous = score
    return events


def cvss_events_checked(cve_id, observations):
    """Caller-ordered (obs_id, score) pairs. Same id + same score: no-op. Same id + different
    score: conflict, kept out of history. Returns (history, events, conflicts)."""
    seen, history, conflicts = {}, [], []
    for obs_id, score in observations:
        if obs_id in seen:
            if seen[obs_id] != score:
                conflicts.append((obs_id, seen[obs_id], score))
            continue
        seen[obs_id] = score
        history.append((obs_id, score))
    return history, _transitions(cve_id, history), conflicts


def cvss_events(cve_id, observations):
    history, events, _ = cvss_events_checked(cve_id, observations)
    return history, events


def _content_hash(score, vector):
    return hashlib.sha256(json.dumps([score, vector]).encode()).hexdigest()


def cvss_ingest(conn, cve_id, source, last_modified, score, vector=None):
    """lastModified is part of the identity, not trusted to be unique on its own: the same
    (source, lastModified) with different content is a conflict and is quarantined."""
    lm = utc_us(last_modified)
    digest = _content_hash(score, vector)
    row = conn.execute("SELECT content_hash FROM cvss_observations WHERE cve_id = ? AND source = ? "
                       "AND last_modified_us = ?", (cve_id, source, lm)).fetchone()
    if row is None:
        conn.execute("INSERT INTO cvss_observations (cve_id, source, last_modified_us, content_hash, score, vector) "
                     "VALUES (?, ?, ?, ?, ?, ?)", (cve_id, source, lm, digest, score, vector))
        result = "inserted"
    elif row[0] == digest:
        result = "duplicate"
    else:
        conn.execute("INSERT OR IGNORE INTO cvss_conflicts VALUES (?, ?, ?, ?, ?, ?)",
                     (cve_id, source, lm, row[0], digest, score))
        result = "conflict"
    conn.commit()
    return result


def cvss_new_events(conn, cve_id):
    """Transitions are computed over the time-sorted history. Only observations newer than
    the CVE's watermark may raise alerts; older late arrivals go to history only."""
    rows = conn.execute("SELECT source, last_modified_us, content_hash, score, alerted FROM cvss_observations "
                        "WHERE cve_id = ? ORDER BY last_modified_us, source, content_hash", (cve_id,)).fetchall()
    keyed = [(f"{s}:{lm}:{h[:12]}", score) for s, lm, h, score, _ in rows]
    lm_of = {f"{s}:{lm}:{h[:12]}": lm for s, lm, h, _, _ in rows}
    wm_row = conn.execute("SELECT last_modified_us FROM cvss_watermarks WHERE cve_id = ?", (cve_id,)).fetchone()
    watermark = wm_row[0] if wm_row else None
    events = _transitions(cve_id, keyed)
    fresh = [e for e in events if watermark is None or lm_of[e[0].rsplit(":obs:", 1)[1]] > watermark]
    late = [(f"{s}:{lm}:{h[:12]}", score) for s, lm, h, score, alerted in rows
            if not alerted and watermark is not None and lm <= watermark]
    if rows:
        conn.execute("UPDATE cvss_observations SET alerted = 1 WHERE cve_id = ?", (cve_id,))
        conn.execute("INSERT INTO cvss_watermarks VALUES (?, ?) ON CONFLICT(cve_id) DO UPDATE SET "
                     "last_modified_us = max(last_modified_us, excluded.last_modified_us)",
                     (cve_id, max(r[1] for r in rows)))
        conn.commit()
    return {"history": keyed, "events": fresh, "late": late}


# ---------------------------------------------------------------------------
# Published history
# ---------------------------------------------------------------------------

ARCHIVE_NAME = re.compile(r"^daily_report_(\d{4}-\d{2}-\d{2})_run(\d+)\.md$")
ARCHIVE_HEADER = re.compile(r"^- 実行日時: (.+?) 〜 .*\(run_id=(\d+)\)\s*$", re.M)
ARCHIVE_UUID = re.compile(r"run_uuid=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
MANIFEST = "docs/data/publication_manifest.json"


def history_check(repo, conn):
    """Fail-closed comparison of the DB with what main has published.

    Rejects: malformed names, invalid dates, unreadable/corrupt headers, name/header date
    mismatch, two archives for one run id, DB behind, archived runs missing from the DB,
    archived runs whose start time (or run_uuid, when both sides carry one) differs.
    Distinguishes: runs newer than the last archive (unpublished, allowed) from runs below
    it without an archive (unarchived gap, rejected).
    Cannot prove without run_uuid: a reused id whose run started in the same second.
    Without a publication manifest, "no archives but runs in the DB" is ambiguous and is
    rejected; with a manifest listing no published runs it is the legitimate initial state.
    """
    reasons, archived, names = [], {}, {}
    reports = repo / "reports"
    db_runs = {r[0]: r[1] for r in conn.execute("SELECT id, started_at FROM run_log")}
    has_uuid = "run_uuid" in {r[1] for r in conn.execute("PRAGMA table_info(run_log)")}
    db_uuid = dict(conn.execute("SELECT id, run_uuid FROM run_log")) if has_uuid else {}
    seq_row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'run_log'").fetchone()
    db_seq = seq_row[0] if seq_row else 0
    manifest_path = repo / MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    if reports.is_dir():
        for path in sorted(reports.iterdir()):
            if not path.name.startswith("daily_report_"):
                continue
            name = ARCHIVE_NAME.match(path.name)
            if not name:
                reasons.append(f"malformed_name:{path.name}")
                continue
            try:
                date.fromisoformat(name.group(1))
            except ValueError:
                reasons.append(f"invalid_date:{path.name}")
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                reasons.append(f"corrupt_archive:{path.name}")
                continue
            header = ARCHIVE_HEADER.search(text)
            run_id = int(name.group(2))
            if not header or int(header.group(2)) != run_id:
                reasons.append(f"corrupt_archive:{path.name}")
                continue
            try:
                started_day = datetime.fromisoformat(header.group(1)).date().isoformat()
            except ValueError:
                reasons.append(f"invalid_header_date:{path.name}")
                continue
            if started_day != name.group(1):
                reasons.append(f"name_content_mismatch:{path.name}")
                continue
            names.setdefault(run_id, []).append(path.name)
            uuid_match = ARCHIVE_UUID.search(text)
            archived[run_id] = (header.group(1), uuid_match.group(1) if uuid_match else None)
    duplicates = sorted(r for r, n in names.items() if len(n) > 1)
    if duplicates:
        reasons.append("duplicate_archive")
    published = set(archived)
    if manifest is not None:
        listed = set(manifest.get("published_runs", []))
        if listed != published:
            reasons.append("manifest_archive_mismatch")
        published |= listed
    if not published and not reasons:
        if db_runs and manifest is None:
            reasons.append("archive_missing_or_empty_but_db_has_runs")
        state = "initial" if not reasons else "loss"
        return {"ok": not reasons, "state": state, "reasons": reasons, "max_published": 0, "db_seq": db_seq,
                "missing_runs": [], "reused_runs": [], "unpublished_runs": sorted(db_runs),
                "unarchived_gaps": [], "duplicate_runs": duplicates}
    max_published = max(published, default=0)
    missing = sorted(r for r in published if r not in db_runs)
    reused = sorted(r for r, (started, run_uuid) in archived.items() if r in db_runs and (
        db_runs[r] != started or (run_uuid and has_uuid and db_uuid.get(r) and db_uuid[r] != run_uuid)))
    unpublished = sorted(r for r in db_runs if r not in published and r > max_published)
    gaps = sorted(r for r in db_runs if r not in published and r < max_published)
    if db_seq < max_published:
        reasons.append("db_behind_published_history")
    if missing:
        reasons.append("archived_runs_missing_from_db")
    if reused:
        reasons.append("run_id_reused")
    if gaps:
        reasons.append("unarchived_runs_below_published_max")
    return {"ok": not reasons, "state": "consistent" if not reasons else "loss", "reasons": reasons,
            "max_published": max_published, "db_seq": db_seq, "missing_runs": missing, "reused_runs": reused,
            "unpublished_runs": unpublished, "unarchived_gaps": gaps, "duplicate_runs": duplicates}


def filename_only_reuse_check(repo, conn):
    reused = []
    for path in (repo / "reports").glob("daily_report_*_run*.md"):
        m = ARCHIVE_NAME.match(path.name)
        row = conn.execute("SELECT started_at FROM run_log WHERE id = ?", (int(m.group(2)),)).fetchone() if m else None
        if row and row[0][:10] != m.group(1):
            reused.append(int(m.group(2)))
    return sorted(reused)
