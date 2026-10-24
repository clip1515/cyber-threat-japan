# 非公開リポジトリによる実機検証計画（未実施）

## 承認境界

本番repoへのpush、mainマージ、本番DBの変更は禁止。検証repoの作成・コードや合成データのGitHub送信・Actions起動・artifact取得・ntfy外部送信は、下記の具体的範囲をユーザーが承認してから実施します。本計画の作成とローカルテストは外部送信を行いません。

候補repo: `clip1515/cyber-threat-japan-validation`（private、未作成・存在未照会）。本番repoをfork/mirrorせず、空の履歴から必要なソース・テストだけを明示的にコピーします。本番のdata、logs、reports、docs/data、Git履歴、ローカル復旧物、.git/config、.env、Secretsはコピーしません。repo名・所有者・実行回数・配送先は承認時に確定します。

## 検証環境

- workflow_dispatchのみ。scheduleと本番への昇格経路は用意しません。
- GitHub-hosted Ubuntu、Python 3.11。読み取り専用テストjobと、検証repoのみにcontents:writeを持つ公開試験jobを分けます。
- originの所有者/repoが承認済み検証先に完全一致し、visibilityがprivateであることを実行前に確認。不一致なら即時停止。本番repo用token、PAT、SMTP資格情報は設定しません。
- SQLite・RSS/API応答・通知文は全て合成。観測値は `base`, `local`, `remote` と連番のみ。update.pyで実際の公開フィードを収集せず、合成入力またはmock HTTPを使います。依存導入先・GitHub API/リポジトリ/Actionsへの通信も承認対象です。
- curl/requestsの収集・通知は通常mock化。実配送ケースのみ、別途承認した検証専用ntfy topicへ固定の「synthetic validation」本文を送ります。本番topicを再利用しません。topicはURL上の購読・投稿能力に関係する値としてSecretsで管理し、ログやartifactに残しません。

## ケースと合格条件

| ケース | 実施方法 | 合格条件 |
|---|---|---|
| 基本動作 | 全ローカルテストをrunnerで実行、検証mainへ合成生成を通常push | 全テスト成功、宛先は検証repoのみ、再実行で不要な新規commitなし |
| 定期・手動相当の重なり | 同じconcurrency groupで手動dispatchを重ねる | 実行中jobを中断しない。待機の置換は記録しFIFO保証とは扱わない |
| push競合 | runner内bare repoでrebase後push直前に別writerを進める。必要時のみ検証repoでコード変更競合 | 正常pushの最大3回再試行、forceなし、双方の変更保持 |
| SQLite競合 | 2つの合成DBにlocal/remote観測を追加 | 上書きせず安全停止。main側remoteとローカルlocalが残る |
| 権限拒否・rebase失敗・試行上限 | runner内bare repoのhook/mockで再現 | 非0終了、無限retryなし、復旧物保持 |
| 最小artifact | 成功・publisher失敗・収集失敗を個別実行 | prepare/uploadが実行され、DBが存在するケースはDBとmanifestのみ保存。DBなしは空snapshotと明示 |
| artifact復旧 | 検証artifactを新しい空ディレクトリへ取得 | tarメンバー1件のみ、サイズ/SHA-256/SQLite integrity一致、local観測復元。ログ・bundle・秘密用canaryファイルは含まない |
| artifact処理失敗 | 不正な合成DB等でprepare失敗を注入 | workflow失敗、成功通知を出さず、失敗通知経路へ。保存不能なDBの完全復旧は合格条件にしない |
| ntfy成功 | mock 2xx→承認済み検証topicへの実配送 | default優先度、固定本文、HTTP成功と受信端末で一致 |
| ntfy失敗 | mockでHTTP 401/403/500・timeoutを再現 | --failで非0、成功通知失敗後は失敗経路、失敗通知high優先度、再送上限あり |
| topic未設定 | 検証secretを持たない独立job | 外部通知を送らない |

実際の401/403等を外部へ故意に送ることは承認対象に含めず、HTTPエラー注入はmockまたはrunner内loopbackの合成サービスで実施します。GitHub上でartifact uploadが本当に失敗する条件は、専用の失敗注入ケースとしてレビューし、本番設定を変更せず確認します。

## 証跡と終了条件

run URL、対象commit、通常pushの試行数、合成DBの観測値件数・ハッシュ、artifactメンバー、HTTP結果、端末到達結果を記録します。機密文字列・topic・認証ヘッダー・環境変数ダンプは記録しません。既存データ・バックアップ・artifactを削除しません。保存期間は検証repo設定に従い、変更する場合は承認範囲に明記します。

全ケース合格後も、本番適用は別の承認・PRレビューで判断します。この計画の承認は本番repoへのpushやマージを許可するものではありません。

## 作成前に求める承認

1. 上記のprivate repo名・所有者での作成と、明示的に選別したコード／合成データの送信。
2. 手動Actions実行、依存取得、検証repoへの通常push、artifactの保存・取得（実行回数と費用枠も確定）。
3. 任意の別承認: 検証専用ntfy topicへの固定テスト通知と受信確認。GitHub検証だけの承認では通知送信しません。
