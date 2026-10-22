"""Prototype notification ledger on the Phase 2 tables. Not wired into any workflow.

Design points it demonstrates (docs/phase2-resilience-design.md §4-5):

* Events are derived from durable CVE state (cves.in_kev, cves.cvss), not from
  "what this run touched". An event missed because a publish failed, or because
  its article is held as unassigned, is derived again by the next run.
* Each channel has its own row, so one channel failing never blocks another.
* A row is committed as 'sending' BEFORE the send. If the run dies after sending
  but before recording the result, the next run finds 'sending', marks it
  'unknown' and resends with an explicit possible-duplicate marker: at least
  once, never silently lost, and a duplicate is always labelled.
"""
import uuid

CHANNELS = ("ntfy", "email")
CVSS_CRITICAL = 9.0
MAX_ATTEMPTS = 3


def _cve_signals(conn):
    for (cve_id,) in conn.execute("SELECT cve_id FROM cves WHERE in_kev = 1 ORDER BY cve_id"):
        yield f"cve:{cve_id}:kev_listed", "kev_listed"
    for (cve_id,) in conn.execute("SELECT cve_id FROM cves WHERE cvss >= ? ORDER BY cve_id", (CVSS_CRITICAL,)):
        yield f"cve:{cve_id}:cvss_critical", "cvss_critical"


def derive_events(conn, run_id, now, baseline=False):
    """Record not-yet-known events. A baseline run records them without delivery rows."""
    created = []
    for key, event_type in _cve_signals(conn):
        if conn.execute("SELECT 1 FROM notification_events WHERE event_key = ?", (key,)).fetchone():
            continue
        conn.execute("INSERT INTO notification_events (event_key, event_type, run_id, created_at) "
                     "VALUES (?, ?, ?, ?)", (key, event_type, run_id, now))
        if not baseline:
            conn.executemany("INSERT INTO notification_log (event_key, channel, state) VALUES (?, ?, 'planned')",
                             [(key, channel) for channel in CHANNELS])
        created.append(key)
    conn.commit()
    return created


def deliver(conn, senders, now, commit=None, max_attempts=MAX_ATTEMPTS):
    """Send pending rows. ``senders`` maps channel -> callable(message); ``commit`` is injectable for tests."""
    commit = commit or conn.commit
    conn.execute("UPDATE notification_log SET state = 'unknown' WHERE state = 'sending'")
    commit()
    rows = conn.execute(
        "SELECT id, event_key, channel, state, attempts FROM notification_log "
        "WHERE state IN ('planned', 'unknown') OR (state = 'failed' AND attempts < ?) ORDER BY id",
        (max_attempts,)).fetchall()
    outcome = {"sent": [], "failed": [], "abandoned": []}
    for row_id, key, channel, state, attempts in rows:
        delivery_id = uuid.uuid4().hex
        message = f"{key} (delivery {delivery_id})"
        if state == "unknown":
            message = "[再送の可能性あり] " + message
        conn.execute("UPDATE notification_log SET state = 'sending', attempts = ?, last_attempt_at = ?, "
                     "delivery_id = ? WHERE id = ?", (attempts + 1, now, delivery_id, row_id))
        commit()
        try:
            senders[channel](message)
        except Exception as exc:  # noqa: BLE001 - a channel failure must not stop the others
            final = "abandoned" if attempts + 1 >= max_attempts else "failed"
            conn.execute("UPDATE notification_log SET state = ?, last_error = ? WHERE id = ?",
                         (final, f"{type(exc).__name__}: {exc}", row_id))
            commit()
            outcome[final].append((key, channel))
            continue
        conn.execute("UPDATE notification_log SET state = 'sent', last_error = NULL WHERE id = ?", (row_id,))
        commit()
        outcome["sent"].append((key, channel))
    return outcome
