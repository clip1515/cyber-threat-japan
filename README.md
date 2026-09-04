# cyber-threat-japan

日本を標的とする/日本へ影響しうるサイバー脅威を、公開情報(JPCERT/CC、IPA、CISA、NVD、
GitHub Security Advisories、主要ベンダーTIブログ、国内セキュリティ報道など)から収集・整理し、
Japan Risk Scoreでスクリーニングするパイプラインです。iPhoneなどのモバイル端末からブラウザで
確認できる、レスポンシブな静的ダッシュボード(`docs/index.html`)を主な閲覧手段としています。

**Blue Team / Threat Intelligence用途専用です。** 攻撃的な機能は一切持たず、公開されている
RSS/JSON/APIへの読み取り専用アクセスのみを行います(詳細は「安全上の制約」を参照)。

## ⚠️ Claudeアプリ単体では毎日の自動実行・自動通知はできません(重要)

本プロジェクトの開発中に実際に確認した内容として、Claudeが動作するクラウドサンドボックス環境は、
組織のネットワークポリシーにより **JPCERT/CC・CISA・PyPIなど大半の外部サイトへの通信がブロック
されています**(`pypi.org`へのアクセスが403、`jpcert.or.jp`へのアクセスが `organization policy`
により拒否されることを確認済みです)。またClaudeアプリ自体には、iPhoneに向けて「毎日決まった時刻に
プッシュ通知を送る」ための一般的な仕組みはありません。

そのため、**このプロジェクトの日次自動実行は、Claudeのセッションではなく GitHub Actions で行う
構成にしています。** GitHub Actionsのランナーは通常のインターネットアクセスを持つため、
JPCERT/CC等への収集を確実に行えます。通知については、GitHub Actions からメール、または
ntfy.sh(iPhone用の無料プッシュ通知アプリ)へ送る方法を用意しました(下記「iPhoneへの通知設定」)。
どちらも安全性の観点から選んだ、広く使われている標準的な方法です。

## 構成

```
cyber-threat-japan/
├── .github/workflows/daily.yml # GitHub Actionsによる毎日の自動実行定義
├── docs/                         # ★iPhone等で見る静的ダッシュボード(GitHub Pagesで公開)
│   ├── index.html                 # レスポンシブなダッシュボード本体(単一HTMLファイル)
│   └── data/dashboard_data.json    # update.py実行のたびに自動生成されるデータ
├── app.py                    # (オプション)ローカルPC向けStreamlitダッシュボード
├── update.py                  # 収集→解析→保存→daily_report.md/ダッシュボードデータ生成
├── run_daily_update.bat        # (オプション)Windowsタスクスケジューラ用の起動バッチ
├── daily_report.md              # 最新の実行結果レポート(update.py実行のたびに上書き)
├── collectors/                   # RSS/NVD API/CISA KEV/GitHub Advisories 収集
├── parsers/                       # CVE抽出・IOC抽出・日付/タイトル正規化
├── analyzers/                      # Japan Risk Score・重要度・重複排除・ステータス遷移
├── database/                        # SQLiteスキーマとCRUD
├── dashboard/                         # (オプション)Streamlit画面本体
├── reporting/                          # daily_report.md / ダッシュボードデータ / 通知文の生成ロジック
├── config/                              # sources.yaml(情報源一覧)・settings.py(しきい値等)
├── data/                                 # SQLiteデータベース本体(初回実行で自動生成)
├── logs/                                  # 実行ログ
├── reports/                                # 日付付きdaily_reportのアーカイブ(自動生成)
└── tests/                                   # pytest / unittest 互換のテスト
```

## iPhoneからの利用方法(GitHub Actions + GitHub Pages)★推奨

PCを常時起動しておく必要はありません。GitHub(無料アカウントで可)にこのプロジェクトを置くだけで、
毎日自動的にデータが更新され、iPhoneのSafari等からダッシュボードを確認できるようになります。

1. **GitHubにリポジトリを作成し、このプロジェクト一式をpushする。**
```bash
   cd cyber-threat-japan
   git init
   git add .
   git commit -m "initial commit"
   git branch -M main
   git remote add origin https://github.com/<your-account>/cyber-threat-japan.git
   git push -u origin main
```
2. **Actionsに書き込み権限を与える。**
   リポジトリの `Settings > Actions > General > Workflow permissions` で
   「Read and write permissions」を選択して保存してください
   (`update.py`の実行結果をリポジトリへコミットし直すために必要です)。
3. **GitHub Pagesを有効化する。**
   `Settings > Pages` で `Source: Deploy from a branch`、`Branch: main` / `/docs` を選択して保存します。
   数分後、`https://<your-account>.github.io/cyber-threat-japan/` でダッシュボードが公開されます。
   このURLをiPhoneのホーム画面に追加(Safariの共有メニュー→「ホーム画面に追加」)しておくと、
   アプリのように毎日開けて便利です。
4. **動作確認のため、初回は手動で実行する。**
   リポジトリの `Actions` タブ → `Daily Cyber Threat Japan Update` → `Run workflow` で
   即座に1回実行できます(スケジュールを待たなくてOKです)。成功すると数分でPagesに反映されます。
5. 以降は `.github/workflows/daily.yml` の設定により **毎日07:00(JST)に自動実行**されます
   (スケジュールは cron `0 22 * * *` = UTC 22:00 で定義。変更したい場合はこのファイルを編集してください)。

実行のたびに、収集→解析→保存→`daily_report.md`生成→`docs/data/dashboard_data.json`生成、が
まとめて行われ、結果はリポジトリに自動コミットされます。1つの情報源の取得失敗や1件のアイテムの
解析失敗があっても、GitHub Actions全体は止まらず、他の情報源/アイテムの処理を継続します。

## ダッシュボードの見方(docs/index.html)

先頭から、優先度の高い情報→詳細情報の順に並んでいます。

1. **前回実行との差分バナー**: 「重要な変化なし」または「新規◯件・重要度上昇◯件…」を一目で表示
2. **サマリー(KPI)**: 総事案数・新規・Critical/High・日本関連・悪用確認済みCVE 等の件数
3. **Critical / High**(先頭表示)
4. **日本関連度の高い事案**(Japan Risk Score上位、先頭表示)
5. **悪用確認済みCVE(KEV等)**(先頭表示)
6. 業種別/攻撃手法別の件数、直近7日間の推移(グラフ)
7. 全事案一覧(検索ボックス・重要度フィルタ付き)
8. 情報源一覧

スマートフォンでの閲覧を前提に、1カラムのカードレイアウト・タップしやすいボタン・
端末のダーク/ライトモードへの自動追従に対応しています。ローカルでプレビューしたい場合は
`python -m http.server 8000` を `docs/` ディレクトリで実行し、`http://localhost:8000/` を
開いてください(直接 `file://` で開くとJSON読み込みがブラウザにブロックされるため動作しません)。

## iPhoneへの通知設定(任意)

GitHub Actionsのワークフローには、以下2つの通知方法をあらかじめ組み込んであります。
**どちらもGitHubリポジトリの Secrets を設定した場合のみ有効化される**任意機能なので、
何も設定しなければ通知は送られず、ダッシュボードを見に行く運用のままで構いません。

**方法A: メール通知(推奨・最も手軽)**
iPhoneの標準メールアプリで通知を受け取れます。新しいアプリのインストールが不要です。
1. Gmailなどで送信専用の「アプリパスワード」を発行する(通常のパスワードは使わないでください)。
2. リポジトリの `Settings > Secrets and variables > Actions` で以下を追加:
   - `SMTP_USERNAME`: 送信元メールアドレス
   - `SMTP_PASSWORD`: 発行したアプリパスワード
   - `NOTIFY_EMAIL_TO`: 通知を受け取りたいメールアドレス(iPhoneで使っているアドレス)
3. 以降、実行完了のたびに要約メールが届きます。

**方法B: ntfy.sh によるプッシュ通知**
1. iPhoneに無料アプリ「[ntfy](https://ntfy.sh/)」をApp Storeからインストールする。
2. 誰にも推測されない、ランダムな文字列のトピック名を決める(例: `ctjp-9f3a2c7e-alerts`)。
   トピック名を知っている人は誰でも購読できてしまうため、**推測困難な文字列にすることが安全上重要**です。
3. ntfyアプリでそのトピック名を「購読」する。
4. リポジトリの Secrets に `NTFY_TOPIC` としてそのトピック名を追加する。
5. 以降、実行完了のたびにiPhoneへプッシュ通知が届きます。

どちらも通知本文は `reporting/notify_summary.py` が生成する短い要約
(重要な変化の有無、新規/重要度上昇/実被害/新規KEVの件数)です。詳細はダッシュボードで確認してください。

## (オプション)PC上でのローカル実行

iPhoneのみで運用する場合はこのセクションは不要です。手元のPCでも動かしたい場合の手順です。

```bash
cd cyber-threat-japan
python3 -m venv .venv && source .venv/bin/activate   # 任意だが推奨
pip install -r requirements.txt

# 1. まず一度データを収集する(初回はDBが自動作成されます)
python update.py

# 2. (任意)ローカル専用のStreamlitダッシュボードを起動
streamlit run app.py
```

- 特定ソースだけ試したい場合: `python update.py --source jpcert_alert`
- レポート/ダッシュボードデータ生成だけスキップしたい場合(デバッグ用): `python update.py --no-report`
- 実行ログは `logs/update_YYYYMMDD.log` に、実行サマリは SQLiteの `run_log` テーブルにも記録されます。

**Windowsタスクスケジューラで毎日実行したい場合**は `run_daily_update.bat` を使います。
```bat
schtasks /Create /TN "CyberThreatJapanDailyUpdate" ^
  /TR "C:\path\to\cyber-threat-japan\run_daily_update.bat" ^
  /SC DAILY /ST 07:00 /RL LIMITED
```
GUIから登録する場合は「タスクスケジューラ」→「基本タスクの作成」→トリガー「毎日」→
操作に `run_daily_update.bat` のフルパスを指定してください。削除は
`schtasks /Delete /TN "CyberThreatJapanDailyUpdate" /F`。

**macOS/Linuxでcronから実行したい場合**は以下を1日1回のスケジュールで登録してください。
```
0 7 * * * cd /path/to/cyber-threat-japan && /path/to/.venv/bin/python update.py >> logs/cron.log 2>&1
```

`config/sources.yaml` にエントリを1つ追加するだけです。

```yaml
  - id: my_new_source
    name: "追加したい情報源の名前"
    type: rss              # rss / nvd_api / kev_json / github_advisory_api のいずれか
    url: "https://example.com/feed.xml"
    trust_level: 2         # 1=一次情報 2=ベンダーTI 3=二次解説/国内報道 4=SNS等
    lang: ja                # ja / en など
    region: jp               # jp / us / global など(Japan Risk Scoreの判定に使われる)
```

`type: rss` であれば、feedparserが解釈できるRSS/AtomのURLを指定するだけで動作します。
`nvd_api` / `kev_json` / `github_advisory_api` は構造化APIに特化した専用collectorを使うため、
基本的には追加不要ですが、同種のAPIを増やしたい場合は `collectors/` に新しいクラスを追加し、
`collectors/__init__.py` の `_REGISTRY_LOADERS` に登録してください。

## Japan Risk Scoreの考え方

各事案について 0〜100 点のスコアを付与します。CVSSベースの「世界的な重要度(severity)」とは
**意図的に独立**させています。CVSSが低くても日本への影響が大きいケース(日本を明示的に狙った
標的型攻撃など)や、逆にCVSSが高くても日本への実影響が薄いケースの両方を潰さないためです。

加点表 (`config/settings.py` の `JAPAN_RISK_WEIGHTS` で調整可能):

| シグナル | 加点 |
|---|---|
| 日本企業/組織で実被害確認 | +40 |
| 日本を明示的に標的 | +30 |
| 日本で広く利用されている製品への言及 | +20 |
| 悪用確認済み(KEV等) | +20 |
| CISA KEV掲載 | +15 |
| ランサムウェア/APT関連 | +10 |
| 日本語フィッシング確認 | +15 |
| 信頼度の低い情報源のみ | −20 |

判定には、情報源の地域(`region: jp`かどうか)、本文中の日本語/日本関連キーワード、
「日本で広く利用されている製品」リスト(`WIDELY_USED_IN_JAPAN_PRODUCTS`)、KEV掲載有無、
ランサムウェア/APT関連語句、日本語フィッシングを示す語句などを組み合わせています。
根拠は各事案の `japan_relevance_reasons` に記録され、ダッシュボードの
「事実 / 未確認情報 / 分析・推測を確認する」から確認できます。

これは**あくまで一次スクリーニング用のヒューリスティック**です。最終判断は必ず
`source_url` の一次情報を人間が確認してから行ってください。

## daily_report.md について

`update.py` の実行完了時に自動生成される、その回の実行で新規/更新された事案の差分レポートです。
プロジェクト直下の `daily_report.md` は常に最新の実行結果に上書きされ、`reports/` 配下には
`daily_report_YYYY-MM-DD_run<run_id>.md` として日付・実行ごとのアーカイブが残ります。

含まれるセクション:

- 本日の新規脅威(このシステムが今回の実行で初めて検出した事案)
- Critical / High(今回の実行で検出・更新された、重要度Critical/High案件)
- 日本企業・日本組織への実被害(日本国内情報源かつ被害を示す語句を検出した事案)
- 悪用確認済みCVE(CISA KEV等で悪用が確認されているもの)
- APT / ランサムウェア / DDoS(該当キーワードで分類)
- 前日から重要度が上がった事案(ステータスがESCALATEDになったもの)
- 推奨対策(各情報源に明記された対策の集約)
- 一次情報源(今回の実行で参照した公式機関/ベンダーの一次情報)

該当する変化が一切ない場合は、冒頭に **「本日は前回から重要な新規変化はありません」** と明示されます
(Critical/Highの新規案件・重要度上昇・日本組織への実被害・新規KEV掲載のいずれも無い場合)。
判定ロジックは `reporting/daily_report.py` にあります。

内部的には、`update.py`実行ごとに発行される `run_id` を `incidents.last_run_id` /
`status_history.run_id` に記録することで「今回の実行で何が起きたか」を正確に差分抽出しています
(以前のDBにも自動的に列が追加されるため、既存データを作り直す必要はありません)。

## 誤検知の確認方法

1. ダッシュボード(`docs/index.html`)の各事案カードにある「事実 / 未確認情報 / 分析・推測を見る」を
   開き、`confirmed_facts`(確認済み事実)・`unconfirmed_info`(未確認情報)・
   `analysis_notes`(分析・推測)が明確に分離されているかを確認してください。
   このシステムは**事実と推測を混在させない**ことを設計上の前提にしています。
2. `japan_relevance_reasons` を確認し、どのキーワード/シグナルでスコアが加点されたかを
   確認してください。キーワードの表層一致による過検知が疑われる場合は、
   `source_url` の一次情報を直接確認してください。
3. よくある誤検知パターン:
   - 一般的なIT製品名が日本以外の文脈で使われているのに「日本で広く利用されている製品」と
     誤判定するケース → `config/settings.py` の `WIDELY_USED_IN_JAPAN_PRODUCTS` を見直す。
   - 「日本」という語が地名以外の文脈(人名・製品名等)で出現しているケース。
   - 複数の別事案が誤って重複統合されているケース → `analyzers/dedup.py` の
     `DEDUP_TITLE_SIMILARITY_THRESHOLD` / `DEDUP_DATE_WINDOW_DAYS` を厳しくする。
4. 誤検知が繰り返し発生するキーワード/情報源が見つかった場合は、
   `config/settings.py` や `config/sources.yaml` を調整し、`tests/` に再発防止のための
   テストケースを追加することを推奨します。

## テストの実行方法

```bash
pip install pytest
pytest tests/ -v
# pytest未導入でも標準ライブラリのみで実行可能:
python -m unittest discover -s tests -v
```

## 安全上の制約

本プロジェクトは完全にBlue Team / Threat Intelligence用途として設計されています。
以下は明確に禁止し、実装にも含めていません。

- 許可のない第三者システムへのスキャン
- ポートスキャン
- 脆弱性の能動的な悪用(PoC実行や攻撃コードの実行)
- 認証回避
- ペイロード送信
- 不正アクセス、その他あらゆる侵入行為

収集対象は **公開情報・公式API・公開JSON** のみです(JPCERT/CC、IPA、CISA、NVD、
GitHub Security Advisories、主要ベンダーの公開ブログ/アドバイザリ、国内セキュリティ報道)。
IOC(IP/ドメイン/ハッシュ)は記事本文からの抽出情報の保存に留め、これらに対する
アクセス・通信・スキャンなどのアクティブな検証は本システムでは一切行いません。
自組織が保有・管理するログを取り込みたい場合は、`collectors/` に読み取り専用の
importコレクターを追加する形での拡張を想定しています(他者のシステムやログへの
アクセスを伴う拡張は行わないでください)。