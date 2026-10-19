# 日次生成データの安全な公開

`daily.yml` は定期実行・手動実行の両方に同じ `daily-update` concurrency groupを使い、実行中ジョブをキャンセルしません。main以外からの実行は公開せず、実行開始時の最新mainを履歴付きでチェックアウトします。GitHubのconcurrencyは全イベントをFIFOで処理する保証ではなく、待機中実行が新しい待機実行に置き換わる場合があります。未開始の実行はまだ収集データを生成していません。

`publish_daily_update.py` はリポジトリルートで、収集・レポート生成完了後に実行します。

```bash
python scripts/publish_daily_update.py --backup-dir "$RUNNER_TEMP/daily-update-recovery"
```

- 変更前に生成データとログを別ディレクトリの一意な `generation-*` にtar保存し、収集元コミットをmanifestへ記録します。既存バックアップを上書き・削除しません。
- 生成対象以外のローカル変更や、既存生成ファイルの削除があれば公開を拒否します。
- 生成データを通常のコミットにし、各試行前に復旧用Git bundleを残します。
- 最新mainに生成データの変更がなければ、必要に応じてrebaseして通常のfast-forward pushを最大3回試みます。push直前の競合も再取得して判定します。force pushは使いません。
- mainに新しい生成データがある場合、SQLite・レポート等をどちらか一方で上書きしたり、自動マージしたりせず失敗終了します。最新mainから収集をやり直してください。
- 権限・保護設定等による、mainの進行を伴わないpush拒否は繰り返しません。rebase失敗時もreset・clean・ours/theirsによる競合解消は行いません。

workflowは成功・失敗の両方で `prepare_recovery_artifact.py` を実行し、SQLiteとSHA-256 manifestだけを専用ディレクトリに出力します。artifactにはその2種類のファイルだけを許可リストで指定します。元のログ・レポート・他のdataファイル・Git bundle・履歴・設定・環境変数はアップロードしません。既存ローカルバックアップは変更・削除しません。

publisherが動いた場合はrebase前のtar中のSQLiteを優先し、未到達なら作業ツリーのSQLiteを読み取り専用接続から整合したコピーにします。SQLite整合性検査を通ったDBだけをtar化します。DBがなければmanifestのsnapshotsは空になります。manifestにはファイル名・サイズ・ハッシュだけを記録します。

artifact名は `daily-update-recovery-<run_id>-<run_attempt>` のままです。保存期間はGitHubの設定に従います。停止・upload失敗・強制終了時の永続化は保証しません。SQLiteそのものには取得記事等の生データが含まれます。復旧性を壊すためDBを自動墨消しせず、非公開検証repoでは合成DBのみを使用します。

ntfyは既存の成功／失敗条件と優先度を維持し、両方で `--fail`、最大2回のretry、接続10秒・リクエスト30秒のtimeoutを使います。成功本文は環境変数経由で渡し、shellコードへ直接埋め込みません。成功通知のHTTP失敗はworkflowを失敗にし、失敗通知の対象となります。再送により重複通知が起きる可能性は残ります。artifact処理の失敗もworkflow失敗通知の対象です。

## 復旧

ダウンロードしたartifactではmanifestのsnapshotsを確認し、`database-*.tar.gz` の唯一のメンバー `data/threat_intel.db` を新しいディレクトリへ取り出し、サイズ・SHA-256・SQLite整合性を照合してください。既存作業ディレクトリや本番DBへ直接展開・置換しません。レポート等は復旧DBから再生成します。

ローカルrunner上には従来の `generated.tar.gz` と `attempt-*.bundle` を残しますが、artifactへは公開しません。runner終了後のbundle利用は保証しません。bundleの確認が必要ならrunner内で `git bundle verify <bundle>` を行います。

mainに新しい生成データがある場合は、まず最新mainから日次収集を再実行し、その後で失敗分にしかない観測値がないかバックアップと比較します。再取得不能な観測値のSQLiteへの統合は、行と参照関係を確認した別のデータ修復として扱います。バックアップ・既存データは削除しません。

## 検証範囲

テストはローカルbare Gitリポジトリだけを使用します。旧方式のfetch-first拒否・SQLite競合、新方式の通常公開・再実行・コード変更とのrebase・push直前の競合・生成データ競合・権限拒否・rebase失敗・試行上限・復旧用bundleとSQLite tarの検証を含みます。実際のGitHubへのpushやActions起動をテストのために行いません。
