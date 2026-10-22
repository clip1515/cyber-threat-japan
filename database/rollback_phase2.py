"""Remove the Phase 2 tables in one transaction. Runs ONLY when called explicitly.

This is the preferred recovery from a bad Phase 2 rollout: unlike restoring a
pre-migration backup it keeps every legacy row collected after the migration
(incidents, status history, KEV first-seen runs). Legacy tables are verified
byte-for-byte (rowid order) before COMMIT.

It refuses to drop data that exists only in Phase 2 tables (collected articles,
analyst evidence, candidate decisions, notification state) unless the caller
confirms that loss explicitly.
"""
import sqlite3

from database.migrate_phase2 import (
    PHASE2_TABLES, SCHEMA_VERSION, MigrationError, legacy_fingerprint,
)

# Children before parents so that foreign keys are never violated mid-drop.
DROP_ORDER = (
    "notification_log", "notification_events", "assessment_history", "evidence",
    "incident_merges", "incident_articles", "incident_candidates", "incident_observations",
    "article_cves", "article_revisions", "article_sightings", "articles", "phase2_migrations",
)
PHASE2_ONLY_DATA = {
    "collected articles": "SELECT count(*) FROM articles WHERE provenance = 'collected'",
    "collected sightings": "SELECT count(*) FROM article_sightings WHERE provenance = 'collected'",
    "non-migrated revisions": "SELECT count(*) FROM article_revisions WHERE change_kind <> 'migrated'",
    "non-migrated links": "SELECT count(*) FROM incident_articles WHERE decided_by <> 'migration'",
    "observed first-observation times": "SELECT count(*) FROM incident_observations WHERE basis = 'observed'",
    "non-migrated evidence": "SELECT count(*) FROM evidence WHERE provenance <> 'migrated_cves'",
    "candidates": "SELECT count(*) FROM incident_candidates",
    "merges": "SELECT count(*) FROM incident_merges",
    "assessment history": "SELECT count(*) FROM assessment_history",
    "notification events": "SELECT count(*) FROM notification_events",
}


def phase2_only_data(conn):
    return {label: n for label, sql in PHASE2_ONLY_DATA.items()
            if (n := conn.execute(sql).fetchone()[0])}


def drop_phase2(conn, allow_data_loss=False):
    """Drop every Phase 2 table and reset user_version to 0. Returns a report dict."""
    if conn.in_transaction:
        raise MigrationError("Caller has an open transaction; refusing to drop")
    if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        raise MigrationError("Database is not at Phase 2 schema version; nothing to drop")
    unique = phase2_only_data(conn)
    if unique and not allow_data_loss:
        raise MigrationError(f"Phase 2 tables hold data found nowhere else: {unique}")

    saved_isolation = conn.isolation_level
    conn.isolation_level = None
    try:
        # Must be set outside a transaction; tables are dropped children-first anyway.
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            before, _ = legacy_fingerprint(conn)
            for table in DROP_ORDER:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
            placeholders = ",".join("?" * len(PHASE2_TABLES))
            conn.execute(f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})", PHASE2_TABLES)
            if legacy_fingerprint(conn)[0] != before:
                raise MigrationError("Legacy tables changed while dropping Phase 2 tables")
            if conn.execute("PRAGMA foreign_key_check").fetchall():
                raise MigrationError("Foreign key violations after drop")
            conn.execute("PRAGMA user_version = 0")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.isolation_level = saved_isolation
    return {"dropped_phase2_only_data": unique, "legacy_fingerprint": before}
