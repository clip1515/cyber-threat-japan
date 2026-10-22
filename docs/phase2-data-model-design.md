# Phase 2-B 詳細設計: 記事・事案・根拠・通知の分離

基準コミット: `05f7aab`(PR #12 ブランチ `audit/pr8-pr10-mainbased`)。
本書は設計のみで、実装・移行は未実施。現行動作は `tests/test_characterization_phase2.py`(27件)で固定済み。§2.1 の DDL は既存 schema.sql と合わせて SQLite 3.45.1 で構文・制約を検証済み。
本番DBの数値は 2026-10-21 時点のブランチ同梱DBを読み取り専用で集計したもの(main最新DBは未集計)。

## 0. 設計原則(Phase 2-B 追加方針との対応)

| # | 方針 | 本設計での扱い |
|---|---|---|
| P1 | 同一CVE ≠ 同一事案 | 自動結合は**元URLの完全一致のみ**。主題CVE集合の完全一致でも別URLなら候補止まり(§3) |
| P2 | 既存の重要度・ステータス・ID・IOC・CVE・履歴を維持、過去データ再計算禁止 | 既存テーブルの既存行は UPDATE しない。移行は新テーブルへの INSERT のみ(§5) |
| P3 | 更新のない再取得は脅威イベントではない | 「変化なし」判定時は新テーブルの取得記録のみ。incidents・status_history・run の更新件数に触れない(§4) |
| P4 | 関連候補は人間の承認制 | 未承認候補は既存データに一切作用しない。承認時も事案IDは削除しない(§3.4) |
| P5 | 元URL保持、正規化URLは別フィールド | `original_url` を同一性の正とし、`normalized_url` は候補生成と衝突検査専用(§2.2) |
| P6 | 通知は送信予定・成功・失敗を区別 | チャネル別の状態機械と再送規則(§6) |
| P7 | 一次情報源の記載 ≠ 独立検証 | 根拠に `statement_type` と `verification` を分離。信頼度だけで侵害成功にしない(§7) |
| P8 | 既存行不更新と first_observed_at 初期値の両立 | 初期値は新テーブル `incident_observations` に INSERT。バックフィルは移行トランザクション内の1回のみ(§5.2) |

## 1. 現行コードの根拠(要約)

| ID | 根拠 | 固定テスト |
|---|---|---|
| F1 主題/言及CVE混同 | `update.py:135-137` | c04 |
| F2 完全一致CVEで自動統合 | `update.py:142-153` | c05, c05b, c06 |
| 部分重複は別件・候補なし | `update.py:152-153` | c07 |
| F3/F4 fuzzy不使用・クエリ/日付窓の欠陥 | `update.py:154-156`, `analyzers/dedup.py:39-52` | c09, c10, c11 |
| F5 定型タイトルが閾値超え | `config/settings.py:75`, `dedup.py:53-55` | c12 |
| F14 候補走査が最新500件 | `dedup.py:42` | c13 |
| F6 変化なし再取得で CLOSED/MITIGATED → ACTIVE | `analyzers/status.py:21-23, 28-40` | c14, c14b |
| F7 低信頼キーワードで ESCALATED | `update.py:169`, `analyzers/severity.py:105-106`, `status.py:25-26` | c15 |
| F8 重要度は下がらない | `database/db.py:159-164`, `update.py:172-174` | c16 |
| F10 事案KEVは3経路で固定 | `update.py:166-167`(既存値・cves表), `db.py:161` | c17 |
| F11 信頼度1の要約=確認済み事実 | `update.py:87-92` | c18 |
| F9 first_seen_at=最初の記事の公開日 | `update.py:102`, `db.py:179-183`(上書き対象外) | c19, c20 |
| F12 変化なし再取得も「更新」かつ当該runで touched | `update.py:200`, `db.py:175`, `daily_report.py:81` | c21 |
| 有意判定は新規/上昇/被害/新規KEVのみ | `reporting/daily_report.py:132-137` | c22, c23 |
| IOCは事案単位で重複排除 | `schema.sql:80` | c24 |
| 1件ごとのトランザクション | `update.py:272-273`, `db.py:27-33` | c25 |
| 通知はDB push後にワークフローのcurl/actionで送信 | `.github/workflows/daily.yml:61-65, 83-106` | (ワークフロー。テスト対象外) |

## 2. データモデル

### 2.1 新テーブル DDL(既存テーブルは変更しない)

```sql
-- 記事(同一性は original_url の完全一致)
CREATE TABLE articles (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url      TEXT NOT NULL UNIQUE,      -- 取得したURLをそのまま保存(P5)
    normalized_url    TEXT NOT NULL,             -- 候補生成・衝突検査専用。UNIQUEにしない
    source_id         TEXT REFERENCES sources(id),
    trust_level       INTEGER,
    title             TEXT,
    published_at      TEXT,                      -- 最新版の値(履歴は article_revisions)
    source_updated_at TEXT,
    content_hash      TEXT,                      -- 正規化本文ハッシュ(§4.1)
    first_fetched_at  TEXT NOT NULL,
    last_fetched_at   TEXT NOT NULL,
    fetch_count       INTEGER NOT NULL DEFAULT 1,
    first_run_id      INTEGER,
    last_run_id       INTEGER,
    provenance        TEXT NOT NULL DEFAULT 'collected'  -- collected / migrated_primary / migrated_alias
);
CREATE INDEX idx_articles_normalized_url ON articles(normalized_url);

-- 記事の版履歴(内容または日付が変わった時だけ追加)
CREATE TABLE article_revisions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id        INTEGER NOT NULL REFERENCES articles(id),
    run_id            INTEGER,
    observed_at       TEXT NOT NULL,
    title             TEXT,
    published_at      TEXT,
    source_updated_at TEXT,
    content_hash      TEXT,
    change_kind       TEXT NOT NULL   -- initial / content / dates / migrated
);
-- SQLite の UNIQUE は NULL 同士を重複とみなさない(3.45.1 で実測)ため式インデックスを使う
CREATE UNIQUE INDEX ux_article_revisions ON article_revisions(
    article_id, COALESCE(content_hash,''), COALESCE(published_at,''), COALESCE(source_updated_at,''));

-- 記事とCVE(役割を区別)
CREATE TABLE article_cves (
    article_id INTEGER NOT NULL REFERENCES articles(id),
    cve_id     TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('subject','mentioned','unknown')),
    PRIMARY KEY (article_id, cve_id)
);

-- 事案と記事の結合(incident_urls の後継。移行期間は incident_urls にも二重書き込み)
CREATE TABLE incident_articles (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    article_id  INTEGER NOT NULL REFERENCES articles(id),
    link_reason TEXT NOT NULL CHECK (link_reason IN ('same_original_url','human_approved','migrated','created_incident')),
    decided_by  TEXT NOT NULL CHECK (decided_by IN ('auto','human','migration')),
    candidate_id INTEGER REFERENCES incident_candidates(id),
    linked_at   TEXT NOT NULL,
    run_id      INTEGER,
    PRIMARY KEY (incident_id, article_id)
);

-- 事案の初回確認日時(P8: incidents に列を足さず別表にする)
CREATE TABLE incident_observations (
    incident_id       INTEGER PRIMARY KEY REFERENCES incidents(id),
    first_observed_at TEXT NOT NULL,
    basis             TEXT NOT NULL CHECK (basis IN ('legacy_created_at','observed'))
);

-- 関連候補(P4: 状態変化は人間のみ)
CREATE TABLE incident_candidates (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id         INTEGER REFERENCES articles(id),
    incident_id        INTEGER NOT NULL REFERENCES incidents(id),
    other_incident_id  INTEGER REFERENCES incidents(id),   -- 事案同士の候補(移行時の既存重複)
    reason             TEXT NOT NULL CHECK (reason IN (
                         'subject_cve_exact','subject_cve_partial','mentioned_cve',
                         'normalized_url','title_similar')),
    score              REAL,
    details_json       TEXT,
    state              TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','accepted','rejected','superseded')),
    created_run_id     INTEGER,
    created_at         TEXT NOT NULL,
    decided_at         TEXT,
    decided_by         TEXT,
    decision_note      TEXT,
    CHECK ((article_id IS NULL) <> (other_incident_id IS NULL))
);
CREATE UNIQUE INDEX ux_candidates ON incident_candidates(
    incident_id, COALESCE(article_id,-1), COALESCE(other_incident_id,-1), reason);

-- 事案同士の統合(承認時のみ。事案IDは削除しない。取り消しは revoked_at)
CREATE TABLE incident_merges (
    merged_id     INTEGER NOT NULL REFERENCES incidents(id),
    into_id       INTEGER NOT NULL REFERENCES incidents(id),
    candidate_id  INTEGER NOT NULL REFERENCES incident_candidates(id),
    decided_by    TEXT NOT NULL,
    decided_at    TEXT NOT NULL,
    revoked_at    TEXT,
    CHECK (merged_id <> into_id),
    PRIMARY KEY (merged_id, candidate_id)
);

-- 根拠(追加のみ。訂正・撤回は新行で表現)
CREATE TABLE evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER REFERENCES incidents(id),
    cve_id          TEXT,
    claim           TEXT NOT NULL CHECK (claim IN (
                      'kev_listed','exploited_in_wild','exploitation_attempted',
                      'compromise','ransomware_associated','patch_available')),
    polarity        TEXT NOT NULL CHECK (polarity IN ('asserted','denied')),
    statement_type  TEXT NOT NULL CHECK (statement_type IN (
                      'first_party_statement','third_party_report','catalog_listing','keyword_signal')),
    source_role     TEXT NOT NULL,     -- victim_org / vendor / gov_cert / researcher / media / social / catalog
    verification    TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN (
                      'unverified','corroborated','analyst_verified')),
    article_id      INTEGER REFERENCES articles(id),
    source_url      TEXT NOT NULL,     -- 記事の original_url をコピー(記事削除に依存しない)
    trust_level     INTEGER,
    published_at    TEXT,
    observed_at     TEXT NOT NULL,
    run_id          INTEGER,
    supersedes_id   INTEGER REFERENCES evidence(id),
    retraction_reason TEXT             -- 撤回は denied 行で表す(§7.3)。既存行は更新しない
);
CREATE UNIQUE INDEX ux_evidence ON evidence(
    COALESCE(incident_id,-1), COALESCE(cve_id,''), claim, polarity,
    COALESCE(article_id,-1), COALESCE(published_at,''));

-- 評価値の変更履歴(重要度・侵害状況)
CREATE TABLE assessment_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id   INTEGER NOT NULL REFERENCES incidents(id),
    field         TEXT NOT NULL,     -- severity / compromise_level
    old_value     TEXT,
    new_value     TEXT,
    evidence_ids  TEXT NOT NULL,     -- JSON配列。根拠なしの変更は禁止
    run_id        INTEGER,
    changed_at    TEXT NOT NULL
);

-- 通知(§6)
CREATE TABLE notification_events (
    event_key    TEXT PRIMARY KEY,   -- 例 "incident:42:escalated:evidence:17"
    incident_id  INTEGER REFERENCES incidents(id),
    event_type   TEXT NOT NULL,
    run_id       INTEGER NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE notification_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key     TEXT NOT NULL REFERENCES notification_events(event_key),
    channel       TEXT NOT NULL CHECK (channel IN ('ntfy','email')),
    state         TEXT NOT NULL CHECK (state IN ('planned','sending','sent','failed','unknown','abandoned')),
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    last_error    TEXT,
    delivery_id   TEXT,              -- 送信ごとの一意ID(本文に埋め込み、重複検出用)
    UNIQUE(event_key, channel)
);
```

既存テーブル(`incidents`, `incident_urls`, `iocs`, `cves`, `status_history`, `run_log`, `sources`)は列追加も含め変更しない。
旧コードは新テーブルを無視するため、コードを戻すだけで旧動作に戻る(§5.4)。

### 2.2 元URLと正規化URL(P5)

- `original_url`: 取得URLをバイト単位でそのまま保存。**記事の同一性・自動結合の唯一の根拠**。
- `normalized_url`: 次の規則で生成し、**候補生成と衝突監視にのみ使う**。
  1. スキームとホストを小文字化、既定ポート(80/443)を除去
  2. `utm_*`, `fbclid`, `gclid`, `mc_cid`, `mc_eid` のクエリを除去
  3. **フラグメントは保持**、パスの大文字小文字・末尾スラッシュは保持
- 根拠(本番DB読み取り専用で実測、`incident_urls` 4,698件):
  - 上記規則での衝突: **0件**
  - フラグメントを除去した場合の衝突: **3グループ・54URL**(JPCERT Weekly Report の項目 `wr260902.html#1`〜`#N` 等が1つに潰れる)。→ フラグメント除去は誤統合を起こすため不採用
  - クエリ付きURL 0件、http 0件、末尾スラッシュ 215件
- 衝突時の扱い: `normalized_url` が一致し `original_url` が異なる新記事は、自動結合せず `reason='normalized_url'` の候補にする。
- 監視: 移行後と各run後に `SELECT normalized_url, count(*) FROM articles GROUP BY 1 HAVING count(*)>1` を品質ゲートの情報項目として記録する(失敗扱いにはしない)。

## 3. 結合・候補の判定(P1, P4)

### 3.1 処理順序(新記事 `A` を受け取った時)

1. `original_url` が既存記事に一致 → 同一記事。§4 の変化判定へ。結合済み事案はそのまま。
2. 一致しない → 新しい `articles` 行を作成し、`article_cves` を役割付きで記録:
   - `subject`: 収集元メタデータの `extra.cve_ids`(NVD/KEV/GHSA が設定。`collectors/nvd_collector.py:50`, `kev_collector.py:29`, `github_advisory_collector.py:41`)
   - `mentioned`: 本文抽出のうち subject 以外
   - メタデータを持たない収集元(RSS)の本文CVEは `unknown`
3. 候補探索(いずれも**候補を作るだけ**):

| 条件 | reason | 備考 |
|---|---|---|
| 主題CVE集合が既存事案の主題CVE集合と完全一致 | `subject_cve_exact` | P1により自動結合しない |
| 主題CVEの一部が重なる(包含含む) | `subject_cve_partial` | score = Jaccard |
| subject/unknown と既存の mentioned、または mentioned 同士のみの重なり | `mentioned_cve` | 低優先 |
| normalized_url 一致・original_url 不一致 | `normalized_url` | §2.2 |
| CVEなし・タイトル類似 ≥ 0.8・両日付あり・差 ≤ 3日・定型タイトル除外 | `title_similar` | F3/F4/F14 修正版で全件対象 |

4. 事案の作成:**判断事項 D1**(下表)。

| 案 | 内容 | 長所 | 短所 |
|---|---|---|---|
| D1-a | 候補の有無に関わらず常に新規事案を作成し、候補を併記 | 実装単純、記事が必ず報告に出る | 同一CVEの別ソース記事が別事案として並び、件数と「新規」通知が増える |
| D1-b(推奨) | `subject_cve_exact` 候補がある記事は**事案を作らず「未割当記事」**として保持し、承認待ち。他は新規事案 | 重複事案と重複通知を防ぐ。CVE単位の事実(CVSS/KEV)は既存どおり `cves` 表に反映 | 承認まで事案に結合されない。日報に「未割当記事」欄が必要 |

本番の履歴では複数URLを持つ事案は12件のみで、別URL・同一主題CVEの頻度は低い見込み(LIKELY。将来の収集元追加で変わり得る)。

### 3.2 定型タイトル除外(F5)

`^Weekly Report:`、`^注意喚起: \d{4}年\d{1,2}月.*セキュリティ更新プログラム` など、設定ファイルで管理する正規表現に一致するタイトル同士は `title_similar` 候補にしない。本番で類似度 ≥0.8 の CVEなしペア 107組の大半がこの形(Phase 2-A で確認)。

### 3.3 禁止事項

- 未承認候補(`open`/`rejected`/`superseded`)を根拠に、事案・IOC・CVE・status_history・重要度を変更しない。
- タイトル類似・言及CVE・正規化URLのみを根拠とする自動結合はしない。

### 3.4 承認・却下(人間のみ)

- **承認(記事候補)**: `incident_articles` に `link_reason='human_approved'` を追加。記事由来の根拠を事案に紐づける。IOCは承認時点で `iocs` に追加(既存行は変更しない)。
- **承認(事案同士)**: 事案IDは削除しない。`incident_merges(merged_id, into_id, candidate_id, decided_by, decided_at)` を追加し、表示時のみ統合。元に戻す時は行を論理削除。
- **却下**: `state='rejected'`。同じ (記事, 事案, reason) は UNIQUE により再提示されない。
- 操作は CLI(`scripts/review_candidates.py`)で行い、決定者と理由を必須にする。

## 4. 変化判定と「脅威イベント」(P3)

### 4.1 変化なしの定義

同一 `original_url` で、次がすべて前回版と同じ場合を「変化なし」とする。

- `content_hash` = sha256(タイトル + 要約 + 本文から取得日時やナビゲーション等の可変部分を除いたもの)
  ※ 現行の `RawItem.raw_hash()`(`collectors/base.py:34-37`)は title+url+summary のみで本文追記(`rss_collector.py:75`)を含まない。本文可変部の除去規則は未設計(UNVERIFIED: 実データでの揺らぎ量)。
- `published_at`, `source_updated_at`
- 主題CVE集合と収集元メタデータ(CVSS, KEV, kev_date_added)

### 4.2 変化なしの時に行うこと / 行わないこと

| 行う | 行わない |
|---|---|
| `articles.last_fetched_at`, `fetch_count`, `last_run_id` 更新(新テーブル) | `incidents` の UPDATE(`last_run_id` を含む) |
|  | `status_history` 追加、ステータス遷移(F6/c14/c14b 解消) |
|  | `run_log.items_updated` への計上(新設 `items_unchanged` 相当を notes に記録) |
|  | 通知イベントの生成 |

### 4.3 変化ありの時

`article_revisions` に1行追加し、変化種別に応じて根拠・評価を更新。`status_history` の遷移は「新しい記事・新しい版・新しい根拠」がある時のみ。

## 5. 移行(P2, P8)

### 5.1 原則

- 既存テーブルの既存行は **UPDATE/DELETE しない**。スキーマ変更は `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` のみ。
- 過去の重要度・ステータスは再計算しない。新規の評価規則は移行後に到着した記事・根拠にのみ適用する。

### 5.2 実施時期(P8 の矛盾解消)

- バックフィルは **スキーマ版 `PRAGMA user_version` が 0 → 2 に上がる、移行トランザクション内の1回だけ**実施する。
- `first_observed_at` は `incidents` に列を追加せず、`incident_observations` に INSERT する。
  - 既存事案: `first_observed_at = incidents.created_at`, `basis='legacy_created_at'`
    - 根拠(読み取り専用で確認): `created_at` NULL 0件、範囲 2026-09-04 05:39:41〜2026-10-21 00:36:50、最初の run(2026-09-04 05:39:40)より前の作成 0件、作成時刻より前の status_history を持つ事案 0件、`user_version` は現在 0
  - 移行後の新規事案: 事案 INSERT と同じトランザクションで `basis='observed'` を INSERT
- 既存の `first_seen_at` は値も意味も変えない(表示ラベルのみ「最初の記事の公開日」に変更)。
- 実行契機:移行専用スクリプト `scripts/migrate_phase2.py --db <path>` を、まず CI 上で合成DBと本番DBの複製に実行して検証する。本番適用はマージ後の最初の日次実行の `init_db()` で `user_version < 2` を検知して行う案と、手動実行案がある(**判断事項 D4**)。

### 5.3 バックフィル内容(すべて INSERT)

| 新テーブル | 元データ | 注意 |
|---|---|---|
| `articles` | `incidents.source_url`(published_at, source_updated_at, trust, raw_hash 付き, `provenance='migrated_primary'`)と、それ以外の `incident_urls`(日付不明, `migrated_alias`) | alias 記事の日付は NULL のまま。推定しない |
| `article_revisions` | 上記各記事に1行(`change_kind='migrated'`) |  |
| `incident_articles` | `incident_urls` の全行(`link_reason='migrated'`) | 4,698件 |
| `article_cves` | 事案の `cve_ids`。URL が `nvd.nist.gov/vuln/detail/CVE-…` 等で主題が確定できる場合のみ `subject`、他は `unknown` | 過去分の主題/言及は推定しない |
| `incident_observations` | §5.2 | 4,687件 |
| `evidence` | `cves.in_kev=1` → `kev_listed`(`statement_type='catalog_listing'`, `source_role='catalog'`, `verification='unverified'`) | KEVは「CISAが悪用を確認しカタログ化した」事実であり、日本組織の侵害成功ではない |
| `incident_candidates` | 既存の主題CVE部分重複ペア(65組)と、定型除外後のタイトル類似ペア | `other_incident_id` 形式。自動統合しない |

### 5.4 検証とロールバック

- 移行後検証(1つでも失敗すれば ROLLBACK):既存全テーブルの行数とチェックサム(全列連結のsha256)が移行前と一致、全事案が `incident_articles` を1件以上持つ、`incident_urls` 全行が対応、`incident_observations` 件数 = 事案数、`PRAGMA foreign_key_check` 空。
- ロールバック:
  1. 移行失敗時:トランザクションで自動的に元に戻る(c25 と同じ仕組みを移行にも適用)。
  2. 移行後に問題発覚:コードを戻すと旧コードは新テーブルを無視。DBは日次コミットで git 管理されているため(`git log -- data/threat_intel.db` で日次更新を確認済み)、移行直前のコミットのDBに戻せる。新テーブルだけ削除するスクリプトも用意する。
- 移行期間中、新コードは `incident_urls` と incidents の代表値にも従来どおり書き込む(旧コード・既存ダッシュボードとの互換)。

## 6. 通知の状態管理(P6)

### 6.1 現状の制約(CONFIRMED)

通知は `daily.yml` で DB の commit/push(61-65行)の**後**に curl(83-93行)と送信アクション(95-106行)で送られる。送信結果はDBに戻らず、ntfy とメールは独立に失敗し得る。本文は日次の要約1通(`reporting/notify_summary.py`)。

### 6.2 設計

- `update.py` が有意イベントごとに `notification_events` と、チャネル別の `notification_log(state='planned')` を作成(同一 event_key は UNIQUE で1回のみ)。
- 新スクリプト `scripts/send_notifications.py` がワークフローの curl/送信アクションを置き換える:
  1. `planned`/`failed`(attempts < 上限)/`unknown` を選択
  2. 送信前に `sending` と `delivery_id` を記録して**コミット**
  3. 送信し、結果に応じて `sent` / `failed(last_error)` を記録
  4. 結果をDBへ書いた後、既存の `publish_daily_update.py` で data/ のみを2回目の公開コミット
- 状態遷移:

```
planned ──send ok──▶ sent
   │  └─send ng──▶ failed ──retry ok──▶ sent
   │                  └─attempts上限──▶ abandoned(失敗アラート)
   └─(sending のまま異常終了)──▶ 次回 unknown ──再送(本文に「再送の可能性」を明記)──▶ sent / failed
```

- 保証: **消失なし(少なくとも1回)**。`sending` 中の異常終了時のみ最大1回の重複があり得て、その場合は本文で明示する。厳密な1回配送はできない(ntfy・SMTP側の重複排除機能の有無は UNVERIFIED)。
- 「新規」件数の数え方:送信済み(`sent`)のイベントは翌日以降の要約で「新規」に数えない。

## 7. 根拠と検証状態(P7, 要件6-8)

### 7.1 区別する軸

| 軸 | 値 | 意味 |
|---|---|---|
| `claim` | kev_listed / exploited_in_wild / exploitation_attempted / compromise / ransomware_associated / patch_available | 何についての主張か。KEV登録・実悪用・攻撃試行・侵害成功は別の値 |
| `statement_type` | first_party_statement / third_party_report / catalog_listing / keyword_signal | 誰の立場の記載か。被害組織・ベンダー自身の発表は first_party_statement |
| `verification` | unverified / corroborated / analyst_verified | その主張が独立に裏付けられたか |
| `polarity` | asserted / denied | 肯定か否定(訂正)か |

「一次情報源が記載した」は `statement_type='first_party_statement'` で表し、`verification` とは独立。信頼度(`trust_level`)は表示と優先度の参考のみで、`verification` を上げない。

### 7.2 判定規則

- `corroborated`:同一 claim について、**発行主体が異なり**、一方が他方の転載でない2件以上の asserted 根拠がある場合に、自動ではなく**候補として提示**し、人間が確定する(転載判定の自動化は UNVERIFIED のため)。
- `compromise`(侵害成功)の表示は `verification IN ('corroborated','analyst_verified')` の時のみ「侵害確認」とし、それ以外は「侵害の報告あり(未検証)」とする。
- `keyword_signal`(本文キーワード由来)は重要度・ステータスを変えない(F7/c15 解消)。表示上は「未確認の兆候」。
- 重要度の引き上げに使える根拠:CVSS(NVD)、`kev_listed`、`verification` が corroborated 以上の claim。変更は `assessment_history` に根拠ID付きで記録。

### 7.3 訂正・撤回

- 否定・訂正は `polarity='denied'` の新しい根拠行として追加し、`supersedes_id` で対象を指す。元の行は消さない。
- 撤回により根拠が無効化され重要度が下がる場合も、**自動では下げず**「引き下げ候補」として提示し、人間の承認で `assessment_history` に記録(P2: 過去データの自動再計算禁止を、移行後の評価にも適用)。**判断事項 D2**。

## 8. 回帰テスト計画(Phase 2-B 実装時)

| 区分 | テスト | 対応方針 |
|---|---|---|
| 正常系 | 新URLの記事 → articles/revisions/article_cves が役割付きで作成 | P1, P5 |
| P1 | 主題CVE完全一致・別URL → 自動結合されず `subject_cve_exact` 候補(c05 を更新) | P1 |
| 誤統合 | 主題が異なり言及CVEが同一のNVD型2件 → 別扱い(c06 を更新) | F2 |
| 誤統合 | JPCERT定型タイトル・フラグメント違いURL → 候補にもならない | F5, P5 |
| 過剰分割 | 同一URL・CVE追加 → 同一記事の新しい版(c08 維持) | P3 |
| P3/冪等性 | 同一入力を2回 → revisions/evidence/status_history/通知/incidents.last_run_id が増えない(c14, c14b, c21 を更新) | P3 |
| P4 | 未承認候補が incidents・iocs・cves・status_history を変えない。却下済みは再提示されない | P4 |
| P5 | 正規化URL衝突 → 候補化。フラグメント違いは衝突しない | P5 |
| P6 | 送信失敗 → failed のまま再送対象 / 再送成功で sent / 成功済みは再送されない / sending中断 → unknown → 再送本文に注記 / チャネル片方失敗で他方は sent | P6 |
| P7 | 被害組織の自社発表のみ → 「侵害の報告あり(未検証)」/ 信頼度1でも verification は unverified / キーワードのみで重要度不変(c15 を更新) | P7 |
| 訂正・撤回 | denied 根拠 → 引き下げ候補のみ、重要度は自動で変わらない(c16 を更新) | P2, P7 |
| P8/移行 | 合成DB移行:既存全テーブルのチェックサム不変、incident_observations 件数一致・basis 正しい、移行2回目は何もしない、途中失敗で全ROLLBACK | P2, P8 |
| 境界 | 日付欠落・タイムゾーンなし・日付のみ・類似度ちょうど0.8・日付差3日/4日・501件目以降の候補 | F4, F14 |
| 既存 | 既存180件(本テストを含む)は、PHASE2-CHANGE と明記したもの以外すべて維持 |  |

## 9. 実装順序

1. 特性テスト(本コミット候補、完了)
2. 新テーブル作成+移行スクリプト+移行後検証(読み書きの動作は変えない)
3. 記事・版・article_cves の記録(二重書き込み、レポートは未参照)
4. 変化なし判定(§4)と status 遷移条件の変更
5. 候補生成(§3)と承認CLI。fuzzy の修正と定型除外
6. 根拠モデル(§7)と重要度規則の切替(移行後到着分のみ)
7. 通知の状態管理(§6)とワークフローの送信ステップ置換
8. 日報・ダッシュボードの表示(未割当記事、候補、記事履歴、検証状態)

各段階を別PRとし、CI成功と人間のレビューを経て次へ進む。

## 10. 判断事項(実装前に決定が必要)

| ID | 内容 | 推奨 |
|---|---|---|
| D1 | 同一主題CVE・別URL記事を新規事案にするか、未割当記事として保留するか | D1-b(保留) |
| D2 | 撤回・否定時の重要度引き下げを自動にするか人間承認にするか | 人間承認 |
| D3 | 候補の承認者と確認頻度 | 未定 |
| D4 | 本番移行の実行契機(初回日次実行で自動 / 手動スクリプト) | 手動スクリプト+直前のDBコミットを復元点として記録 |
| D5 | Phase 2 の基点(PR #12 マージ後の main) | PR #12 マージ後 |
| D6 | 通知の2回目公開コミットを許容するか(1日2コミット) | 許容 |
