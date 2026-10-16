"""daily.yml自体が「予定時刻を大幅に超過した」「実行されなかった」ことを
検知するための、daily.yml本体に依存しない独立監視(2026-10監査Round4⑤)。

設計方針(なぜ別ワークフローが必要か):
  daily.yml内部にタイムアウトや失敗検知を仕込んでも、「daily.yml自体が
  トリガーされなかった」(GitHub Actions側のスケジューラ障害、リポジトリ側の
  Actions無効化、同時実行枠の恒久的な専有等)ケースは検知できない。
  これを検知するには、daily.ymlとは独立したスケジュール・独立したジョブで、
  「daily.ymlの最後の成功実行がいつだったか」をGitHub Actions REST API
  (GET /repos/{owner}/{repo}/actions/workflows/daily.yml/runs)経由で外部から
  確認する「心拍監視(heartbeat)」が必要。

このモジュールは判定ロジック(is_overdue)のみを純粋関数として提供する。
GitHub APIへの実際の問い合わせ・通知送信は main() / check_and_notify() に
分離してあり、ユニットテストはis_overdue()のみを対象にする
(API呼び出し・通知送信は本番環境でのみ動作確認する。ローカルsandboxからは
GitHub Actions REST APIへの認証付きアクセスができないため、未確認のまま)。
"""
from datetime import datetime, timedelta, timezone


def is_overdue(last_success_at: datetime, now: datetime, max_gap: timedelta) -> bool:
    """最後の成功実行時刻(last_success_at)から、現在時刻(now)までの間隔が
    max_gapを超えていればTrue。

    last_success_atがNone(=一度も成功実行が記録されていない、または
    GitHub API自体に到達できず確認不能)の場合もTrue(=安全側に倒して
    「過剰超過」と判定する。理由: 「分からない」を「問題なし」として
    扱うと、本来検知すべき「全く実行されていない」ケースを見逃すため)。
    """
    if last_success_at is None:
        return True
    return (now - last_success_at) > max_gap


def classify_gap(last_success_at, now: datetime, expected_interval: timedelta,
                  warn_multiplier: float = 2.0, critical_multiplier: float = 4.0) -> str:
    """間隔の大きさに応じて "ok" / "warn" / "critical" を返す。

    expected_interval: 本来の実行間隔(daily.ymlはcron「17 22 * * *」=24時間間隔)。
    warn_multiplier: 2倍(=48時間)を超えたら警告。GitHub Actionsのcronは
      "best effort"であり数時間の遅延自体は正常範囲(本監査Round1-3で確認済み)
      なため、2倍という閾値は「1回分完全に飛んだ」ことを捉える値として設定した。
    critical_multiplier: 4倍(=96時間)を超えたら重大。
    """
    if last_success_at is None:
        return "critical"
    gap = now - last_success_at
    if gap > expected_interval * critical_multiplier:
        return "critical"
    if gap > expected_interval * warn_multiplier:
        return "warn"
    return "ok"


def build_alert_message(gap_status: str, last_success_at, now: datetime) -> str:
    if gap_status == "ok":
        return ""
    last_str = last_success_at.isoformat() if last_success_at else "不明(一度も確認できていない)"
    return (
        f"【{'重大' if gap_status == 'critical' else '警告'}】"
        f"cyber-threat-japan: daily.ymlの最終成功実行が確認できません。\n"
        f"最終成功実行: {last_str}\n"
        f"現在時刻: {now.isoformat()}\n"
        "GitHub Actionsのスケジュール自体が実行されていない、"
        "または直近の実行がすべて失敗している可能性があります。"
        "リポジトリのActionsタブを確認してください。"
    )


def main():  # pragma: no cover - 本番(GitHub Actions)環境でのみ実行される経路
    """実際の問い合わせ・通知送信。ローカルsandboxでは実行・検証していない
    (GitHub Actions REST APIへの認証付きアクセス手段がこのセッションに
    無いため)。本番適用時は、別ワークフロー(heartbeat.yml、提案のみ・
    未適用)から呼び出すことを想定する。
    """
    import os
    import sys
    import urllib.request
    import json

    repo = os.environ.get("GITHUB_REPOSITORY", "clip1515/cyber-threat-japan")
    token = os.environ.get("GITHUB_TOKEN")
    url = f"https://api.github.com/repos/{repo}/actions/workflows/daily.yml/runs?status=success&per_page=1"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}" if token else "",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        data = json.loads(resp.read())

    runs = data.get("workflow_runs", [])
    last_success_at = None
    if runs:
        last_success_at = datetime.fromisoformat(runs[0]["run_started_at"].replace("Z", "+00:00"))

    now = datetime.now(timezone.utc)
    status = classify_gap(last_success_at, now, timedelta(hours=24))
    message = build_alert_message(status, last_success_at, now)
    if message:
        print(message)
        sys.exit(1)  # ワークフロー側でこの終了コードを見て通知ステップを起動する想定
    print("OK: daily.ymlは最終成功実行から24時間x2以内です。")


if __name__ == "__main__":  # pragma: no cover
    main()
