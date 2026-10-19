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

workflowは成功・失敗の両方で、復旧ファイルと生成データ・ログを `daily-update-recovery-<run_id>-<run_attempt>` artifactへアップロードします。artifactの保存期間はGitHubの設定に従います。GitHub側の停止やupload失敗、ジョブ強制終了時まで永続化を保証するものではありません。失敗時はartifact保存結果も確認してください。

## 復旧

失敗時の生成データは `generated.tar.gz`、コミットは `attempt-*.bundle` にあります。既存作業ディレクトリへ直接展開したり、本番SQLiteを丸ごと置換したりしないでください。bundleは `git bundle verify <bundle>` で確認できます。独立した新規ディレクトリで `git init` → `git fetch <bundleの絶対パス> HEAD` として取り込み、`git show FETCH_HEAD:<path>` 等で比較できます。

mainに新しい生成データがある場合は、まず最新mainから日次収集を再実行し、その後で失敗分にしかない観測値がないかバックアップと比較します。再取得不能な観測値のSQLiteへの統合は、行と参照関係を確認した別のデータ修復として扱います。バックアップ・既存データは削除しません。

## 検証範囲

テストはローカルbare Gitリポジトリだけを使用します。旧方式のfetch-first拒否・SQLite競合、新方式の通常公開・再実行・コード変更とのrebase・push直前の競合・生成データ競合・権限拒否・rebase失敗・試行上限・復旧用bundleとSQLite tarの検証を含みます。実際のGitHubへのpushやActions起動をテストのために行いません。
