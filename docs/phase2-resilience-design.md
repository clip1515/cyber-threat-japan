# Phase 2-D 障害・競合時のデータ保全設計

基準: `phase2/characterization-and-design` @ `95c861e`。本書の判定はコード行と、合成データ・一時Git・一時SQLite・モックだけのテスト
(`tests/test_phase2_concurrency.py`, `tests/test_phase2_recovery_notifications.py`)に基づく。
`database/rollback_phase2.py` と `reporting/notification_ledger.py` は検証用の試作で、どのワークフローからも呼ばれない。

## 1. 監査した事実(コード根拠)

| 箇所 | 動作 |
|---|---|
| `daily.yml:20-22` | `concurrency: daily-update`, `cancel-in-progress: false`。日次ワークフロー同士だけを直列化する |
| `daily.yml:26, 32-36` | main でのみ実行し、`ref: main` をチェックアウト。再実行は常に最新 main から始まる |
| `daily.yml:50-59` | 通知本文は公開(61-65)より**前**に作られる |
| `daily.yml:83-106` | ntfy・メールの `if` に状態関数がない。GitHub の既定で `success()` が付くため、公開失敗や ntfy 失敗の後の通知は実行されない(GitHub の仕様。ローカル再現不可) |
| `daily.yml:108-121` | 失敗時アラートは同じジョブ内の ntfy。ランナー消失時は実行されない |
| `pr-check.yml:9-10, 21-24` | `contents: read`、Python 3.11、Secrets 参照なし |
| `scripts/publish_daily_update.py:37-44` | 公開前に生成物を退避(既存を上書きしない) |
| 同 `:72-83` | 公開直前に `origin/main` を取得し、収集の基点が祖先か(80)、main に新しい生成データがないか(82)を検査。あれば拒否 |
| 同 `:84-89` | 生成物以外の進みだけ rebase し、通常 push(force なし) |
| 同 `:78-79, 95` | 前進のない拒否や再試行上限で停止 |
| `database/migrate_phase2.py` | 単一トランザクション・`BEGIN IMMEDIATE`。公開の仕組みは持たない |
| `database/db.py:20` | `sqlite3.connect` は既定の5秒待機 |
| `update.py:269-285` | アイテム単位でトランザクション。失敗は記録して続行(DEGRADED) |
| `reporting/daily_report.py:99-103, 132-137` | 新規KEV・有意判定は**その回に触れた事案**だけが対象 |
| `reporting/notify_summary.py:42-49` | 有意でなければ「重要な新規変化はありません」 |
| `reporting/publish_outputs.py:58-59` | `reports/before_run_{run_id}` を `exist_ok=False` で作成 |

## 2. 競合(合成データ・一時Gitで再現)

前提: GitHub 上では日次と移行は別ランナー・別チェックアウトで動くため、SQLite のロックでは排他できない。排他点は git の公開処理(§1 の 72-89 行)。
`concurrency` グループは手動実行やローカル実行の移行を直列化しない。

| 状況 | 再現 | 結果 |
|---|---|---|
| C+D 同じ古い main から日次→移行の順に公開 | `test_c_d_same_old_base_daily_first_migration_refused` | 2番目は 82 行で拒否。main は日次の世代のみ、移行結果は退避アーカイブに残る |
| D 移行が先、古い日次が後 | `test_d_migration_first_then_stale_daily_refused_e_rerun_from_latest` | 古い日次は拒否。最新 main からの再実行で公開成功。ただし旧コードは Phase 2 表に書かないため、新規事案は次の移行実行まで Phase 2 表に反映されない |
| E 拒否後に最新 main から移行を再実行 | `test_e_refused_migration_rerun_…` | 差分移行で欠落分のみ追加。重複なし、KEV 初回確認 run は日次のまま |
| 取得後・push 前に相手が push | `test_push_race_between_fetch_and_push_…` | push 拒否 → 再取得で 82 行が拒否。上書きなし |
| 公開成功後の再実行 | `test_rerun_after_successful_publish_adds_nothing` | 事案・KEV初回確認とも増えない |
| A 日次の書き込み中に移行開始(同一ファイル) | `test_a_migration_started_during_daily_write_fails_cleanly` | 移行は `database is locked` で開始せず無変更。日次完了後の再実行で成功 |
| B 移行中に日次アイテム(同一ファイル) | `test_b_daily_item_during_migration_fails_without_partial_writes` | アイテムはロックで失敗し部分書き込みなし。再処理で成功 |

ネガティブコントロール(検出器 `assert_publication_invariants` が危険な公開を捕捉):
force push(履歴喪失)、`rebase -X theirs`(古いDBで上書き → 事案喪失)、82 行を除去した公開処理(別世代の DB と JSON が混在して公開される)。

## 3. 復旧方式の比較

| 方式 | 既存データ | RSS 記事 | KEV 初回確認 | 根拠 |
|---|---|---|---|---|
| コードのみロールバック | 失われない | 影響なし | 影響なし | `test_code_only_rollback_keeps_everything`。Phase 2 表は放置され遅れる |
| Phase 2 表の無効化(読まない) | 失われない | 影響なし | 影響なし | 現時点では Phase 2 表を読むコードがないため、コードのみロールバックと同じ |
| Phase 2 表の安全な削除(`drop_phase2`) | 失われない(既存表の指紋一致を確認して COMMIT) | 影響なし | 影響なし | `test_safe_drop_…` 4件。Phase 2 にしかないデータがあれば既定で拒否 |
| 移行直前バックアップの復元 | **移行後の事案・状態履歴・KEV初回確認が消える** | 掲載期間を過ぎた記事は**再収集不能** | 再収集で別 run として記録され、**通知済みKEVが再び「新規」になる**。run_log の ID が巻き戻り、**失われた run の ID が別の run に再利用される** | `test_backup_restore_loses_data_…` |
| 最新 main からの再収集 | 失われない | 過去分は取り戻せない | 重複しない | `test_rerun_after_successful_publish_adds_nothing` |

推奨順位: (1) コードのみロールバック → (2) Phase 2 表の安全な削除 → (3) 既存表が壊れた場合に限り、最新 main の DB を正として再収集。
移行直前バックアップへの巻き戻しは、既存表の破損が確認され、かつ失われる範囲を数え上げた上でのみ行う。
なお、復元後は run ID が再利用されるため `reports/before_run_{id}` が既に存在し、出力生成が `FileExistsError` で失敗する見込み
(`publish_outputs.py:58-59`。コード読解のみ、未実行)。

## 4. 通知

現行で再現した事実:

- DB 公開成功・通知失敗: 次の回は同じ項目が新規でなくなり、本文は「重要な新規変化はありません」になる。**見逃した重要イベントは二度と通知されず、誤解を招く本文が送られる**(`test_publish_ok_notify_failed_event_is_never_sent_again`)。
- ntfy 成功・メール失敗、ntfy 失敗後のメール: ワークフローの順序と条件で決まる(`test_workflow_notification_ordering_and_conditions`)。実際のスキップ挙動は GitHub の仕様に依存し、ローカルでは再現できない。
- ランナー消失: 失敗時アラートも同じランナー上のため送られない(コード読解。再現不可)。

試作 `reporting/notification_ledger.py` で検証した設計:

| 障害 | 結果 | テスト |
|---|---|---|
| ntfy 成功・メール失敗 | メールだけ再送、ntfy は再送しない | `test_ntfy_ok_email_failed_retries_only_email` |
| 送信成功・結果のDB保存失敗 | 送信前に `sending` を確定しているため、次回 `unknown` として「再送の可能性あり」付きで再送 | `test_sent_but_result_not_saved_…` |
| 送信途中でランナー終了 | 同上。消失なし | `test_runner_killed_mid_delivery_loses_nothing` |
| 再実行 | 送信済みは再送しない | `test_rerun_does_not_renotify` |
| 公開失敗で計画行ごと消失 | イベントは CVE の永続状態から導出するため、次回に同じイベントを再導出して1回だけ送る | `test_publish_failure_discards_plan_…` |
| 恒久的な失敗 | 上限回数で `abandoned`、無限再試行しない | `test_repeated_failure_is_abandoned_…` |
| 導入時 | 既存 KEV は基準線として記録し通知しない | `test_baseline_does_not_notify_existing_kev` |

## 5. 未割当記事(保留)と重要警告

- 再現: 同一CVEの別URL記事を保留して事案に触れないと、現行の日報は新規KEVを出さない(`daily_report.py:99-103`)。
- 設計: 通知イベントを事案ではなく CVE の永続状態(`cves.in_kev`, `cves.cvss`)から導出する。KEV 登録と CVSS 9.0 以上への上昇は、記事が保留中でも必ずイベントになり、イベントキーは CVE 単位なので後で記事が事案に結び付いても重複しない(`UnassignedArticles` 2件)。
- 自動統合は行わないまま、警告だけは CVE 単位で出す。保留件数と経過日数は日報・通知に常時表示する(未実装)。

## 6. 残るリスク

- GitHub の `success()` 既定、ランナー消失、`concurrency` の待機置換は実環境で未確認。
- 実ファイルへの移行(数千件規模)の所要時間と、その間の日次5秒待機の超過有無は未計測。
- 旧コードは Phase 2 表に書かないため、移行後に新規事案が Phase 2 表に反映されるのは次の移行実行時。
- 試作の通知台帳は実配信・メールアクションと未接続。ntfy/SMTP 側の重複排除機能は未確認。
- 2回目の公開コミット(通知結果の記録)の運用は未設計。
