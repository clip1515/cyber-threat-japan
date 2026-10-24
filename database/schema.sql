-- cyber-threat-japan データベーススキーマ
-- 事実(confirmed)と未確認/推測(unconfirmed / analysis)を必ずカラムレベルで分離する。

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    id              TEXT PRIMARY KEY,       -- config/sources.yaml の id
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    url             TEXT NOT NULL,
    trust_level     INTEGER NOT NULL,       -- 1=一次情報 2=ベンダーTI 3=二次解説/国内報道 4=SNS等
    lang            TEXT,
    region          TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key               TEXT UNIQUE,        -- 重複排除用ハッシュ

    title                   TEXT NOT NULL,
    first_seen_at           TEXT,               -- 発生日 (ISO8601, 不明ならNULL)
    published_at            TEXT,               -- 公表日
    source_updated_at       TEXT,               -- 情報源での更新日（収集日時とは別）
    last_updated_at         TEXT,               -- 最終更新日 (このシステムでの最終更新)

    target_org              TEXT,               -- 組織名
    sector                  TEXT,               -- 業種
    country                 TEXT,               -- 国

    attack_vector           TEXT,               -- 攻撃手法
    cve_ids                 TEXT,               -- カンマ区切り
    cvss                    REAL,
    in_kev                  INTEGER DEFAULT 0,  -- 0/1
    epss                    REAL,
    malware                 TEXT,               -- 使用マルウェア
    threat_actor            TEXT,               -- 攻撃グループ
    intrusion_vector        TEXT,               -- 侵入経路
    impact                  TEXT,               -- 影響

    japan_relevance_score   INTEGER DEFAULT 0,  -- 0-100
    japan_relevance_reasons TEXT,               -- JSON配列(加点根拠)

    severity                TEXT,               -- Critical/High/Medium/Low
    status                  TEXT DEFAULT 'NEW', -- NEW/ACTIVE/ESCALATED/MITIGATED/CLOSED

    recommended_actions     TEXT,               -- 推奨対策

    confirmed_facts         TEXT,               -- 確認済み事実(一次情報に基づく記述のみ)
    unconfirmed_info        TEXT,               -- 未確認情報(一次情報で裏取りできていない報道等)
    analysis_notes          TEXT,               -- 分析・推測(本システム/収集者による推測であることを明記)

    source_url              TEXT,
    source_name             TEXT,
    source_trust_level      INTEGER,

    raw_hash                TEXT,               -- 元記事本文のハッシュ(変更検知用)
    last_run_id             INTEGER,            -- この事案を最後に触れた run_log.id (差分レポート用)
    created_at              TEXT DEFAULT (datetime('now')),
    updated_at              TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_published_at ON incidents(published_at);
CREATE INDEX IF NOT EXISTS idx_incidents_japan_score ON incidents(japan_relevance_score);

-- Keep every known article URL when a CVE incident is shared by multiple sources.
CREATE TABLE IF NOT EXISTS incident_urls (
    source_url TEXT PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_type        TEXT NOT NULL,   -- ip / domain / url / hash_md5 / hash_sha256 / email 等
    ioc_value       TEXT NOT NULL,
    source_url      TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(incident_id, ioc_type, ioc_value)
);

-- 出典が公開したIOCを、出典・種別・観測期間・確認日・信頼性・用途とともに保持する(config/reported_iocs.yaml から同期)。
-- iocs(RSS本文からの自動抽出・ヒューリスティック)とは別に管理する。遮断リストではなく、攻撃者の特定にも使わない。
-- このテーブルの制約が保証するのは、NOT NULL・列挙値・信頼度の範囲・https で始まること・日付の書式・一意性まで。
-- 型は保証しない(SQLiteの型親和性で 1 と '1' が相互に変換されるため)。型・URLの形式・アドレスの種別
-- (global unicast か)・日付の範囲・文字数・制御文字・YAMLの重複キー・ファイル全体の形は
-- parsers/reported_ioc.py が検証する。
CREATE TABLE IF NOT EXISTS reported_iocs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type            TEXT NOT NULL CHECK (ioc_type IN ('ip')),
    ioc_value           TEXT NOT NULL,   -- 正規化済み(ipaddress の表記)
    source_url          TEXT NOT NULL CHECK (source_url LIKE 'https://%'),
    source_name         TEXT NOT NULL,
    -- official_advisory: 公的機関・ベンダーの公式文書 / external_observation: 外部の観測情報(別の出典として扱う)
    source_kind         TEXT NOT NULL CHECK (source_kind IN ('official_advisory', 'external_observation')),
    source_trust_level  INTEGER NOT NULL CHECK (source_trust_level IN (1, 2, 3)),
    source_published_at TEXT CHECK (source_published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    -- その出典が示す観測期間(活動が観測された期間)。記載がなければ NULL
    observed_from       TEXT CHECK (observed_from GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    observed_to         TEXT CHECK (observed_to GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    -- その出典に掲載されていることを人が確認した日(観測期間とは別)
    source_checked_at   TEXT NOT NULL CHECK (source_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    confidence          TEXT NOT NULL CHECK (confidence IN ('reported', 'corroborated')),
    usage               TEXT NOT NULL CHECK (usage IN ('reference', 'detection')),
    context             TEXT,            -- 出典の記載内容の要約
    UNIQUE(ioc_type, ioc_value, source_url)
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    cvss            REAL,
    epss            REAL,
    in_kev          INTEGER DEFAULT 0,
    kev_date_added  TEXT,
    kev_first_seen_run_id INTEGER, -- KEVを初めて確認したrun_id
    description     TEXT,
    last_checked_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS status_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    old_status      TEXT,
    new_status      TEXT NOT NULL,
    reason          TEXT,
    run_id          INTEGER,            -- この遷移を発生させた run_log.id (差分レポート用)
    changed_at      TEXT DEFAULT (datetime('now'))
);

-- idx_status_history_run_id / idx_incidents_last_run_id は database/db.py の
-- _migrate_legacy_schema() 側で、列追加(ALTER TABLE)の後に作成する。
-- (旧DBではCREATE TABLE IF NOT EXISTSの時点でこれらの列が存在せず、
--  ここでインデックスを直接作成すると "no such column" になるため)

CREATE TABLE IF NOT EXISTS run_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT DEFAULT (datetime('now')),
    finished_at     TEXT,
    sources_ok      INTEGER DEFAULT 0,
    sources_failed  INTEGER DEFAULT 0,
    items_fetched   INTEGER DEFAULT 0,
    items_new       INTEGER DEFAULT 0,
    items_updated   INTEGER DEFAULT 0,
    notes           TEXT
);
