"""Phase 2 additive migration. Runs ONLY when called explicitly.

Nothing in update.py or db.init_db() calls this module. It creates the tables in
schema_phase2.sql and backfills them from the legacy tables with INSERTs only.
Legacy rows are never updated or deleted; a fingerprint of every legacy table is
compared before COMMIT. Everything happens in one transaction that is rolled
back on any error, including a failed post-migration check.

The backfill is incremental: running it again inserts only rows that are still
missing (e.g. incidents added by the legacy pipeline since the last run), and a
run that has nothing to insert writes nothing at all.

    python -m database.migrate_phase2 --db copy.db --backup before.db
    python -m database.migrate_phase2 --db data/threat_intel.db --dry-run
"""
import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import DB_PATH
from parsers.url_normalizer import normalize_url

SCHEMA_VERSION = 2
PHASE2_SCHEMA_PATH = Path(__file__).resolve().parent / "schema_phase2.sql"
LEGACY_TABLES = ("sources", "incidents", "incident_urls", "iocs", "cves", "status_history", "run_log")
PHASE2_TABLES = (
    "phase2_migrations", "articles", "article_sightings", "article_revisions", "article_cves",
    "incident_candidates", "incident_articles", "incident_observations", "incident_merges",
    "evidence", "assessment_history", "notification_events", "notification_log",
)
NVD_DETAIL_URL = re.compile(r"^https://nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d{4,7})$")


class MigrationError(RuntimeError):
    pass


def schema_statements(sql: str = None):
    """Split the schema into single statements (executescript would COMMIT)."""
    sql = PHASE2_SCHEMA_PATH.read_text(encoding="utf-8") if sql is None else sql
    statements, buffer = [], ""
    for line in sql.splitlines(keepends=True):
        if not buffer and (not line.strip() or line.lstrip().startswith("--")):
            continue
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer.strip())
            buffer = ""
    if buffer.strip():
        raise MigrationError("Incomplete statement at end of schema_phase2.sql")
    return statements


def _existing_tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def legacy_fingerprint(conn):
    """sha256 over every legacy row (ordered by rowid) plus their AUTOINCREMENT counters."""
    digest = hashlib.sha256()
    counts = {}
    tables = _existing_tables(conn)
    for table in LEGACY_TABLES:
        if table not in tables:
            continue
        rows = conn.execute(f"SELECT rowid, * FROM {table} ORDER BY rowid").fetchall()
        counts[table] = len(rows)
        digest.update(f"{table}:{len(rows)}\n".encode())
        for row in rows:
            digest.update(repr(tuple(row)).encode("utf-8"))
    if "sqlite_sequence" in tables:
        placeholders = ",".join("?" * len(LEGACY_TABLES))
        for row in conn.execute(f"SELECT name, seq FROM sqlite_sequence WHERE name IN ({placeholders}) "
                                "ORDER BY name", LEGACY_TABLES):
            digest.update(repr(tuple(row)).encode("utf-8"))
    return digest.hexdigest(), counts


def _url(value):
    return value.strip() if value and value.strip() else None


def create_schema(conn, report, now):
    for statement in schema_statements():
        conn.execute(statement)


def backfill_articles(conn, report, now):
    known = {r[0] for r in conn.execute("SELECT original_url FROM articles")}
    inserted = 0
    # Primary URLs first (lowest incident id wins for URLs shared by several incidents).
    for row in conn.execute("SELECT id, source_url, title, published_at, source_updated_at "
                            "FROM incidents ORDER BY id").fetchall():
        url = _url(row[1])
        if url is None or url in known:
            continue
        has_dates = row[3] is not None or row[4] is not None
        conn.execute(
            "INSERT INTO articles (original_url, normalized_url, title, published_at, source_updated_at, "
            "date_basis, recorded_at, provenance) VALUES (?, ?, ?, ?, ?, ?, ?, 'migrated_primary')",
            (url, normalize_url(url), row[2], row[3], row[4],
             "legacy_representative" if has_dates else "unknown", now),
        )
        known.add(url)
        inserted += 1
    for (raw,) in conn.execute("SELECT source_url FROM incident_urls ORDER BY rowid").fetchall():
        url = _url(raw)
        if url is None or url in known:
            continue
        conn.execute(
            "INSERT INTO articles (original_url, normalized_url, date_basis, recorded_at, provenance) "
            "VALUES (?, ?, 'unknown', ?, 'migrated_alias')",
            (url, normalize_url(url), now),
        )
        known.add(url)
        inserted += 1
    report["inserted"]["articles"] = inserted


def backfill_revisions(conn, report, now):
    cur = conn.execute(
        """INSERT INTO article_revisions (article_id, revision_no, observed_at, source_id, title,
                                          published_at, source_updated_at, legacy_raw_hash, change_kind)
           SELECT a.id, 1, ?, s.id, a.title, a.published_at, a.source_updated_at, i.raw_hash, 'migrated'
           FROM articles a
           LEFT JOIN incidents i ON i.id = (SELECT MIN(id) FROM incidents WHERE source_url = a.original_url)
           LEFT JOIN sources s ON s.name = i.source_name
           WHERE a.provenance <> 'collected'
             AND NOT EXISTS (SELECT 1 FROM article_revisions r WHERE r.article_id = a.id)""",
        (now,),
    )
    report["inserted"]["article_revisions"] = cur.rowcount


def backfill_sightings(conn, report, now):
    cur = conn.execute(
        """INSERT OR IGNORE INTO article_sightings (article_id, source_id, trust_level, provenance)
           SELECT a.id, s.id, i.source_trust_level, 'migrated'
           FROM incidents i
           JOIN articles a ON a.original_url = trim(i.source_url)
           JOIN sources s ON s.name = i.source_name"""
    )
    report["inserted"]["article_sightings"] = cur.rowcount
    report["unmapped_source_names"] = [r[0] for r in conn.execute(
        "SELECT DISTINCT source_name FROM incidents WHERE source_name IS NOT NULL "
        "AND source_name NOT IN (SELECT name FROM sources) ORDER BY 1")]


def backfill_links(conn, report, now):
    total = 0
    for sql in (
        """INSERT OR IGNORE INTO incident_articles (incident_id, article_id, link_reason, decided_by, linked_at)
           SELECT u.incident_id, a.id, 'migrated', 'migration', ? FROM incident_urls u
           JOIN articles a ON a.original_url = trim(u.source_url)""",
        # Incidents whose source_url is owned by another incident in incident_urls.
        """INSERT OR IGNORE INTO incident_articles (incident_id, article_id, link_reason, decided_by, linked_at)
           SELECT i.id, a.id, 'migrated', 'migration', ? FROM incidents i
           JOIN articles a ON a.original_url = trim(i.source_url)""",
    ):
        total += conn.execute(sql, (now,)).rowcount
    report["inserted"]["incident_articles"] = total


def backfill_article_cves(conn, report, now):
    # Only the subject CVE that the URL itself proves (NVD/KEV collectors build
    # https://nvd.nist.gov/vuln/detail/<CVE>). Other legacy CVEs stay incident-level:
    # which article mentioned them is unknown.
    inserted = 0
    for article_id, url in conn.execute("SELECT id, original_url FROM articles "
                                        "WHERE provenance <> 'collected'").fetchall():
        match = NVD_DETAIL_URL.match(url)
        if match:
            inserted += conn.execute(
                "INSERT OR IGNORE INTO article_cves (article_id, cve_id, role) VALUES (?, ?, 'subject')",
                (article_id, match.group(1)),
            ).rowcount
    report["inserted"]["article_cves"] = inserted


def backfill_observations(conn, report, now):
    cur = conn.execute(
        """INSERT INTO incident_observations (incident_id, first_observed_at, basis)
           SELECT id, created_at, CASE WHEN created_at IS NULL THEN 'unknown' ELSE 'legacy_created_at' END
           FROM incidents WHERE id NOT IN (SELECT incident_id FROM incident_observations)"""
    )
    report["inserted"]["incident_observations"] = cur.rowcount


def backfill_kev_evidence(conn, report, now):
    # NOT EXISTS instead of INSERT OR IGNORE: an ignored insert still advances the
    # AUTOINCREMENT counter, which would make every re-run write to the file.
    cur = conn.execute(
        """INSERT INTO evidence (cve_id, claim, polarity, statement_type, source_role,
                                           source_id, published_at, observed_at, observed_basis, provenance)
           SELECT c.cve_id, 'kev_listed', 'asserted', 'catalog_listing', 'catalog',
                  (SELECT id FROM sources WHERE id = 'cisa_kev'), c.kev_date_added,
                  COALESCE(r.started_at, c.last_checked_at),
                  CASE WHEN r.started_at IS NOT NULL THEN 'run_log_kev_first_seen'
                       ELSE 'cves_last_checked_at' END,
                  'migrated_cves'
           FROM cves c LEFT JOIN run_log r ON r.id = c.kev_first_seen_run_id
           WHERE c.in_kev = 1 AND COALESCE(r.started_at, c.last_checked_at) IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM evidence e WHERE e.provenance = 'migrated_cves'
                             AND e.cve_id = c.cve_id AND e.claim = 'kev_listed')"""
    )
    report["inserted"]["evidence"] = cur.rowcount
    report["kev_without_observation_time"] = conn.execute(
        "SELECT count(*) FROM cves c LEFT JOIN run_log r ON r.id = c.kev_first_seen_run_id "
        "WHERE c.in_kev = 1 AND COALESCE(r.started_at, c.last_checked_at) IS NULL").fetchone()[0]


def verify(conn, report, before_fingerprint):
    after, _ = legacy_fingerprint(conn)
    if after != before_fingerprint:
        raise MigrationError("Legacy tables changed during migration")
    checks = {
        "incident_urls rows without article link": """
            SELECT count(*) FROM incident_urls u WHERE NOT EXISTS (
              SELECT 1 FROM incident_articles ia JOIN articles a ON a.id = ia.article_id
              WHERE ia.incident_id = u.incident_id AND a.original_url = trim(u.source_url))
              AND trim(COALESCE(u.source_url, '')) <> ''""",
        "incidents with a URL but no article link": """
            SELECT count(*) FROM incidents i WHERE trim(COALESCE(i.source_url, '')) <> ''
              AND NOT EXISTS (SELECT 1 FROM incident_articles ia WHERE ia.incident_id = i.id)""",
        "incidents without observation row": """
            SELECT count(*) FROM incidents i WHERE NOT EXISTS (
              SELECT 1 FROM incident_observations o WHERE o.incident_id = i.id)""",
        "articles without revision": """
            SELECT count(*) FROM articles a WHERE NOT EXISTS (
              SELECT 1 FROM article_revisions r WHERE r.article_id = a.id)""",
    }
    for label, sql in checks.items():
        if conn.execute(sql).fetchone()[0]:
            raise MigrationError(f"Post-migration check failed: {label}")
    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise MigrationError(f"Foreign key violations after migration: {violations[:5]}")
    if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise MigrationError("PRAGMA quick_check failed")
    report["url_less_incidents"] = [r[0] for r in conn.execute(
        "SELECT id FROM incidents WHERE trim(COALESCE(source_url, '')) = '' ORDER BY id")]
    report["shared_articles"] = conn.execute(
        "SELECT count(*) FROM (SELECT article_id FROM incident_articles GROUP BY 1 HAVING count(*) > 1)"
    ).fetchone()[0]
    report["normalized_url_collisions"] = [
        json.loads(r[0]) for r in conn.execute(
            "SELECT json_group_array(original_url) FROM articles GROUP BY normalized_url "
            "HAVING count(*) > 1 ORDER BY normalized_url")]


STEPS = (create_schema, backfill_articles, backfill_revisions, backfill_sightings, backfill_links,
         backfill_article_cves, backfill_observations, backfill_kev_evidence)


def migrate(conn, now=None):
    """Apply schema version 2 and the backfill in one transaction. Returns a report dict."""
    if conn.in_transaction:
        raise MigrationError("Caller has an open transaction; refusing to migrate")
    missing = [t for t in LEGACY_TABLES if t not in _existing_tables(conn)]
    if missing:
        raise MigrationError(f"Legacy schema missing {missing}; run db.init_db() first")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, SCHEMA_VERSION):
        raise MigrationError(f"Unexpected user_version {version}; expected 0 or {SCHEMA_VERSION}")
    if conn.execute("PRAGMA foreign_key_check").fetchall():
        raise MigrationError("Existing foreign key violations; refusing to migrate inconsistent data")

    now = now or datetime.now(timezone.utc).isoformat()
    report = {"schema_version_before": version, "inserted": {}}
    saved_isolation = conn.isolation_level
    conn.isolation_level = None
    try:
        conn.execute("PRAGMA foreign_keys = ON")  # must be set outside a transaction
        conn.execute("BEGIN IMMEDIATE")
        try:
            before, counts = legacy_fingerprint(conn)
            report["legacy_counts"] = counts
            for step in STEPS:
                step(conn, report, now)
            verify(conn, report, before)
            report["noop"] = version == SCHEMA_VERSION and not any(report["inserted"].values())
            if not report["noop"]:
                if version != SCHEMA_VERSION:
                    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                conn.execute(
                    "INSERT INTO phase2_migrations (schema_version, started_at, finished_at, "
                    "legacy_fingerprint, report_json) VALUES (?, ?, ?, ?, ?)",
                    (SCHEMA_VERSION, now, datetime.now(timezone.utc).isoformat(), before,
                     json.dumps(report, ensure_ascii=False, sort_keys=True)),
                )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.isolation_level = saved_isolation
    report["schema_version_after"] = conn.execute("PRAGMA user_version").fetchone()[0]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicit Phase 2 schema migration (never automatic)")
    parser.add_argument("--db", required=True, help="SQLite file to migrate")
    parser.add_argument("--backup", help="New file to receive a backup before migrating")
    parser.add_argument("--dry-run", action="store_true",
                        help="Open the file read-only, migrate an in-memory copy and print the report")
    parser.add_argument("--allow-production-db", action="store_true",
                        help="Required to write to config.settings.DB_PATH")
    args = parser.parse_args(argv)

    path = Path(args.db).resolve()
    if not path.is_file():
        parser.error(f"{path} does not exist")
    if args.dry_run:
        source = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        target = sqlite3.connect(":memory:")
        source.backup(target)
        source.close()
        print(json.dumps(migrate(target), ensure_ascii=False, indent=2))
        return 0
    if path == Path(DB_PATH).resolve() and not args.allow_production_db:
        parser.error("Refusing to migrate the production database without --allow-production-db")
    if not args.backup:
        parser.error("--backup is required when writing")
    backup = Path(args.backup)
    if backup.exists():
        parser.error(f"Backup {backup} already exists; refusing to overwrite")
    conn = sqlite3.connect(path)
    try:
        with sqlite3.connect(backup) as dest:
            conn.backup(dest)
        print(json.dumps(migrate(conn), ensure_ascii=False, indent=2))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
