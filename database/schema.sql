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

    -- 2026-10監査で追加: KEVカタログの「属性」の変化(新規掲載そのものだけでなく、
    -- ランサムウェア悪用の確認・対応期限)を追跡するための保持値。
    -- in_kev/cvss とは異なり、これらは value自体をそのまま持ち回り、
    -- update.py側で「前回の値」と比較することで変更イベントを検出する。
    kev_known_ransomware_use TEXT,              -- CISA KEVの knownRansomwareCampaignUse
    kev_due_date             TEXT,              -- CISA KEVの dueDate

    -- 2026-10監査(Round3)で追加: cvssの非後退マージはtrust_levelだけでは
    -- 不十分(同じtrust_levelのソースが、古い/低バージョンのCVSSで
    -- 新しい/高バージョンの値を上書きしてしまう余地が残るため)。
    -- cvss_version(例: "3.1"/"3.0"/"2.0")とcvss_as_of(そのCVSS値の
    -- 公式な更新日時。例: NVDのcve.lastModified)、cvss_source_id
    -- (どのsourceから採用した値か)を併せて持ち回り、update.py側の
    -- process_item()でバージョン・更新日時を加味した比較を行う。
    cvss_version             TEXT,
    cvss_as_of               TEXT,
    cvss_source_id           TEXT,

    created_at              TEXT DEFAULT (datetime('now')),
    updated_at              TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_published_at ON incidents(published_at);
CREATE INDEX IF NOT EXISTS idx_incidents_japan_score ON incidents(japan_relevance_score);

CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_type        TEXT NOT NULL,   -- ip / domain / url / hash_md5 / hash_sha256 / email 等
    ioc_value       TEXT NOT NULL,
    source_url      TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(incident_id, ioc_type, ioc_value)
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    cvss            REAL,
    epss            REAL,
    in_kev          INTEGER DEFAULT 0,
    kev_date_added  TEXT,
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

-- 2026-10監査で追加: 「KEVカタログの日次再同期」と「実際に意味のある変化」を
-- 区別するための変更履歴台帳。update.py の process_item() が検出した変更
-- (新規KEV掲載・ランサムウェア悪用確認・対応期限変更・CVSS訂正・
-- Japan Risk Scoreの大幅上昇)だけをここに記録する。
-- reporting/daily_report.py の significant_change は、このテーブルの
-- 当該run分のレコードを主な判定材料として使う(「touchedになった件数」では
-- なく「実際に値が変わった件数」で判定するため)。
CREATE TABLE IF NOT EXISTS kev_change_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    run_id          INTEGER,
    change_type     TEXT NOT NULL,   -- newly_kev_listed / ransomware_use_confirmed /
                                      -- kev_due_date_changed / kev_required_action_changed /
                                      -- cvss_corrected_up / cvss_corrected_down /
                                      -- cvss_version_changed(2026-10 Round4で追加。
                                      --   v3.1→v4.0等のCVSSバージョン移行そのものを記録。
                                      --   スコアが同一/近似でも発生し得る) /
                                      -- japan_relevance_jump
    old_value       TEXT,
    new_value       TEXT,
    detected_at     TEXT DEFAULT (datetime('now'))
);

-- idx_kev_change_events_run_id は db.py の _migrate_legacy_schema() 側で作成する
-- (incidents同様、旧DBに対する後付け運用を統一するため)。

-- 2026-10監査で追加: 「ソースの取得が失敗したのか、正当に0件だったのか」を
-- 区別して記録する診断台帳。GitHub Actions実行ログに依存せず、
-- data/collector_health.json としてリポジトリにも書き出す(update.py参照)。
CREATE TABLE IF NOT EXISTS source_health (
    source_id           TEXT PRIMARY KEY,
    last_attempt_at      TEXT,
    last_success_at       TEXT,
    last_item_count       INTEGER,
    last_error_type       TEXT,       -- 例: HTTPError, Timeout, ConnectionError, ParseError
    last_error_message    TEXT,
    last_http_status       INTEGER,
    consecutive_failures   INTEGER DEFAULT 0
);

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