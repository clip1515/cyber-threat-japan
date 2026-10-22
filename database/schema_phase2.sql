-- Phase 2 additive schema (schema version 2).
-- Applied ONLY by database/migrate_phase2.py when called explicitly.
-- db.init_db() never loads this file and no existing table is altered.
-- History tables are append-only (enforced by the triggers at the end).
-- Foreign keys use the default NO ACTION: deleting a legacy incident that has
-- Phase 2 history fails instead of silently cascading the history away.

CREATE TABLE IF NOT EXISTS phase2_migrations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version     INTEGER NOT NULL,
    started_at         TEXT NOT NULL,
    finished_at        TEXT NOT NULL,
    legacy_fingerprint TEXT NOT NULL,
    report_json        TEXT NOT NULL CHECK (json_valid(report_json))
);

-- One row per document, identified by its original URL (kept byte-for-byte).
CREATE TABLE IF NOT EXISTS articles (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url      TEXT NOT NULL UNIQUE CHECK (length(trim(original_url)) > 0),
    normalized_url    TEXT NOT NULL,             -- candidates/collision checks only; not unique
    title             TEXT,
    published_at      TEXT,
    source_updated_at TEXT,
    -- legacy_representative: copied from the incident's representative columns at
    -- migration time; the value may originate from another URL of that incident.
    date_basis        TEXT NOT NULL CHECK (date_basis IN ('collected','legacy_representative','unknown')),
    recorded_at       TEXT NOT NULL,             -- when this row was written, not when the article appeared
    provenance        TEXT NOT NULL CHECK (provenance IN ('collected','migrated_primary','migrated_alias'))
);
CREATE INDEX IF NOT EXISTS idx_articles_normalized_url ON articles(normalized_url);

-- Which sources delivered an article (JPCERT feeds share URLs; KEV and NVD
-- both use https://nvd.nist.gov/vuln/detail/<CVE>).
CREATE TABLE IF NOT EXISTS article_sightings (
    article_id     INTEGER NOT NULL REFERENCES articles(id),
    source_id      TEXT NOT NULL REFERENCES sources(id),
    trust_level    INTEGER,
    first_seen_at  TEXT,
    last_seen_at   TEXT,
    first_run_id   INTEGER,
    last_run_id    INTEGER,
    provenance     TEXT NOT NULL CHECK (provenance IN ('collected','migrated')),
    PRIMARY KEY (article_id, source_id),
    CHECK (provenance = 'migrated' OR (first_seen_at IS NOT NULL AND last_seen_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_article_sightings_source ON article_sightings(source_id);

-- Article version history. Uniqueness is per sequence number, not per content,
-- so a legitimate return to an earlier version is recorded as a new revision.
CREATE TABLE IF NOT EXISTS article_revisions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id        INTEGER NOT NULL REFERENCES articles(id),
    revision_no       INTEGER NOT NULL CHECK (revision_no >= 1),
    observed_at       TEXT NOT NULL,
    run_id            INTEGER,
    source_id         TEXT REFERENCES sources(id),
    title             TEXT,
    published_at      TEXT,
    source_updated_at TEXT,
    content_hash      TEXT,
    legacy_raw_hash   TEXT,                      -- RawItem.raw_hash(); not comparable with content_hash
    change_kind       TEXT NOT NULL CHECK (change_kind IN ('initial','content','dates','reverted','migrated')),
    UNIQUE (article_id, revision_no)
);

CREATE TABLE IF NOT EXISTS article_cves (
    article_id INTEGER NOT NULL REFERENCES articles(id),
    cve_id     TEXT NOT NULL CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'),
    role       TEXT NOT NULL CHECK (role IN ('subject','mentioned','unknown')),
    PRIMARY KEY (article_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_article_cves_cve ON article_cves(cve_id);

CREATE TABLE IF NOT EXISTS incident_candidates (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id       INTEGER NOT NULL REFERENCES incidents(id),
    article_id        INTEGER REFERENCES articles(id),
    other_incident_id INTEGER REFERENCES incidents(id),
    reason            TEXT NOT NULL CHECK (reason IN (
                        'subject_cve_exact','subject_cve_partial','mentioned_cve',
                        'normalized_url','title_similar')),
    score             REAL,
    details_json      TEXT CHECK (details_json IS NULL OR json_valid(details_json)),
    state             TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','accepted','rejected','superseded')),
    created_run_id    INTEGER,
    created_at        TEXT NOT NULL,
    decided_at        TEXT,
    decided_by        TEXT,
    decision_note     TEXT,
    CHECK ((article_id IS NULL) <> (other_incident_id IS NULL)),
    CHECK (other_incident_id IS NULL OR other_incident_id > incident_id),  -- canonical pair order
    CHECK ((state = 'open') = (decided_at IS NULL)),
    CHECK (state IN ('open','superseded') OR decided_by IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_incident_candidates ON incident_candidates(
    incident_id, COALESCE(article_id, -1), COALESCE(other_incident_id, -1), reason);
CREATE INDEX IF NOT EXISTS idx_incident_candidates_article ON incident_candidates(article_id);
CREATE INDEX IF NOT EXISTS idx_incident_candidates_other ON incident_candidates(other_incident_id);

-- An article may belong to several incidents (legacy shared URLs, human
-- approvals) but to at most one by automatic decision.
CREATE TABLE IF NOT EXISTS incident_articles (
    incident_id  INTEGER NOT NULL REFERENCES incidents(id),
    article_id   INTEGER NOT NULL REFERENCES articles(id),
    link_reason  TEXT NOT NULL CHECK (link_reason IN (
                   'same_original_url','created_incident','human_approved','migrated')),
    decided_by   TEXT NOT NULL CHECK (decided_by IN ('auto','human','migration')),
    candidate_id INTEGER REFERENCES incident_candidates(id),
    linked_at    TEXT NOT NULL,
    run_id       INTEGER,
    PRIMARY KEY (incident_id, article_id),
    CHECK ((link_reason = 'human_approved') = (decided_by = 'human')),
    CHECK ((link_reason = 'migrated') = (decided_by = 'migration')),
    CHECK (link_reason <> 'human_approved' OR candidate_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_incident_articles_article ON incident_articles(article_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_incident_articles_one_auto
    ON incident_articles(article_id) WHERE decided_by = 'auto';

-- System first-observation time, kept apart from incidents.first_seen_at.
CREATE TABLE IF NOT EXISTS incident_observations (
    incident_id       INTEGER PRIMARY KEY REFERENCES incidents(id),
    first_observed_at TEXT,
    basis             TEXT NOT NULL CHECK (basis IN ('legacy_created_at','observed','unknown')),
    CHECK ((basis = 'unknown') = (first_observed_at IS NULL))
);

CREATE TABLE IF NOT EXISTS incident_merges (
    merged_id    INTEGER NOT NULL REFERENCES incidents(id),
    into_id      INTEGER NOT NULL REFERENCES incidents(id),
    candidate_id INTEGER NOT NULL REFERENCES incident_candidates(id),
    decided_by   TEXT NOT NULL,
    decided_at   TEXT NOT NULL,
    revoked_at   TEXT,
    PRIMARY KEY (merged_id, candidate_id),
    CHECK (merged_id <> into_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_merges_into ON incident_merges(into_id);

-- Evidence is append-only. A correction or retraction is a new row with the
-- opposite polarity that supersedes the earlier one; uniqueness is per
-- (subject, claim, polarity, article revision, superseded row, provenance), so
-- assert -> deny -> re-assert chains from successive revisions are all kept.
CREATE TABLE IF NOT EXISTS evidence (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id         INTEGER REFERENCES incidents(id),
    cve_id              TEXT,
    claim               TEXT NOT NULL CHECK (claim IN (
                          'kev_listed','exploited_in_wild','exploitation_attempted',
                          'compromise','ransomware_associated','patch_available')),
    polarity            TEXT NOT NULL CHECK (polarity IN ('asserted','denied')),
    statement_type      TEXT NOT NULL CHECK (statement_type IN (
                          'first_party_statement','third_party_report','catalog_listing','keyword_signal')),
    source_role         TEXT NOT NULL CHECK (source_role IN (
                          'victim_org','vendor','gov_cert','researcher','media','social','catalog','unknown')),
    verification        TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN (
                          'unverified','corroborated','analyst_verified')),
    article_revision_id INTEGER REFERENCES article_revisions(id),
    source_id           TEXT REFERENCES sources(id),
    source_url          TEXT,
    published_at        TEXT,
    observed_at         TEXT NOT NULL,
    observed_basis      TEXT NOT NULL CHECK (observed_basis IN (
                          'collected','analyst','run_log_kev_first_seen','cves_last_checked_at')),
    run_id              INTEGER,
    supersedes_id       INTEGER REFERENCES evidence(id),
    provenance          TEXT NOT NULL CHECK (provenance IN ('collected','analyst','migrated_cves')),
    note                TEXT,
    CHECK (incident_id IS NOT NULL OR cve_id IS NOT NULL),
    CHECK (provenance <> 'collected' OR (article_revision_id IS NOT NULL AND source_url IS NOT NULL)),
    CHECK (verification = 'unverified' OR provenance = 'analyst')
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence ON evidence(
    COALESCE(incident_id, -1), COALESCE(cve_id, ''), claim, polarity,
    COALESCE(article_revision_id, -1), COALESCE(supersedes_id, -1), provenance);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_cve ON evidence(cve_id);
CREATE INDEX IF NOT EXISTS idx_evidence_supersedes ON evidence(supersedes_id);

CREATE TABLE IF NOT EXISTS assessment_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id),
    field        TEXT NOT NULL CHECK (field IN ('severity','compromise_level')),
    old_value    TEXT,
    new_value    TEXT,
    evidence_ids TEXT NOT NULL CHECK (json_valid(evidence_ids) AND json_array_length(evidence_ids) > 0),
    decided_by   TEXT NOT NULL,
    run_id       INTEGER,
    changed_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assessment_history_incident ON assessment_history(incident_id);

CREATE TABLE IF NOT EXISTS notification_events (
    event_key   TEXT PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id),
    event_type  TEXT NOT NULL,
    run_id      INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key       TEXT NOT NULL REFERENCES notification_events(event_key),
    channel         TEXT NOT NULL CHECK (channel IN ('ntfy','email')),
    state           TEXT NOT NULL CHECK (state IN ('planned','sending','sent','failed','unknown','abandoned')),
    attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_attempt_at TEXT,
    last_error      TEXT,
    delivery_id     TEXT,
    UNIQUE (event_key, channel),
    CHECK ((state = 'planned') = (attempts = 0)),
    CHECK (state <> 'failed' OR last_error IS NOT NULL)
);

-- Append-only guards for history tables.
CREATE TRIGGER IF NOT EXISTS trg_article_revisions_no_update BEFORE UPDATE ON article_revisions
BEGIN SELECT RAISE(ABORT, 'article_revisions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_article_revisions_no_delete BEFORE DELETE ON article_revisions
BEGIN SELECT RAISE(ABORT, 'article_revisions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_assessment_history_no_update BEFORE UPDATE ON assessment_history
BEGIN SELECT RAISE(ABORT, 'assessment_history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_assessment_history_no_delete BEFORE DELETE ON assessment_history
BEGIN SELECT RAISE(ABORT, 'assessment_history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_phase2_migrations_no_update BEFORE UPDATE ON phase2_migrations
BEGIN SELECT RAISE(ABORT, 'phase2_migrations is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_phase2_migrations_no_delete BEFORE DELETE ON phase2_migrations
BEGIN SELECT RAISE(ABORT, 'phase2_migrations is append-only'); END;

-- A superseding row must be about the same subject and claim as the row it supersedes.
CREATE TRIGGER IF NOT EXISTS trg_evidence_supersedes_same_subject BEFORE INSERT ON evidence
WHEN NEW.supersedes_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM evidence e WHERE e.id = NEW.supersedes_id AND e.claim = NEW.claim
      AND COALESCE(e.incident_id, -1) = COALESCE(NEW.incident_id, -1)
      AND COALESCE(e.cve_id, '') = COALESCE(NEW.cve_id, ''))
BEGIN SELECT RAISE(ABORT, 'supersedes_id must reference evidence with the same subject and claim'); END;
