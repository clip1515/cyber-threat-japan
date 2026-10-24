"""日次ワークフローの通知・公開・収集結果の安全性(Phase 2-E 段階0)。

ネットワーク・本番DB・Secretsを使わない: ntfyと収集元はプロセス内のHTTPスタブ、gitは一時リポジトリ、
DBは一時SQLiteを使う。受信側が受け取った内容(スタブの記録)と終了コードを別々に検証する。
"""
import contextlib
import http.server
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT))

from collectors.base import BaseCollector, RawItem
from collectors.github_advisory_collector import GithubAdvisoryCollector
from collectors.kev_collector import KevCollector
from collectors.nvd_collector import NvdCollector
from collectors.rss_collector import RssCollector
from database import db as dbmod
from reporting import daily_report, dashboard_export, notify_summary
import update as update_mod

NTFY_SCRIPT = ROOT / "scripts" / "notify_ntfy.sh"
PUBLISH_SCRIPT = ROOT / "scripts" / "publish_daily_data.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "daily.yml"
NO_PROXY_ENV = {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}


def without_proxy(env):
    return {**{k: v for k, v in env.items() if "proxy" not in k.lower()}, **NO_PROXY_ENV}


class Stub:
    """ローカルHTTPスタブ。POSTは responses の順に応答(最後の値を繰り返す)し、GETは routes で応答する。

    応答値: HTTPステータス(int)、'hang'(受理後に応答しない)、'stall_after_200'(200のヘッダー後に
    本文が届かない)、'drop'(本文受信後に応答せず切断)。
    """

    def __init__(self, responses=(200,), routes=None):
        self.received = []
        self.gets = []
        responses, routes = list(responses), routes or {}
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                stub.received.append((self.path, body.decode("utf-8")))
                mode = responses[min(len(stub.received), len(responses)) - 1]
                if mode == "hang":
                    time.sleep(3)
                    return
                if mode == "drop":
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                if mode == "stall_after_200":
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    self.wfile.write(b"{")
                    self.wfile.flush()
                    time.sleep(3)
                    return
                self.send_response(mode)
                self.end_headers()
                self.wfile.write(b"{}")

            def do_GET(self):
                path, _, query = self.path.partition("?")
                stub.gets.append((path, urllib.parse.parse_qs(query), dict(self.headers)))
                route = routes[path]
                # 値が関数ならクエリ(dict)を渡して (status, content-type, body) を得る(NVDのページング用)。
                status, ctype, body = route(urllib.parse.parse_qs(query)) if callable(route) else route
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def unused_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# ntfy(H1, H2, M2, N1-N3)
# ---------------------------------------------------------------------------

class TestNtfyScript(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.body_file = self.dir / "notify_body.txt"
        self.body_file.write_text("【要確認】synthetic summary\n新規 1件\n", encoding="utf-8")
        self.outcome_file = self.dir / "outcome.txt"

    def tearDown(self):
        self._tmp.cleanup()

    def send(self, url, **overrides):
        env = without_proxy(os.environ)
        env.update(NTFY_URL=url, NTFY_TOPIC="synthetic-topic", NOTIFY_BODY_FILE=str(self.body_file),
                   NTFY_OUTCOME_FILE=str(self.outcome_file), NTFY_CONNECT_TIMEOUT="1", NTFY_MAX_TIME="1",
                   NTFY_RETRY_DELAY="0")
        env.update(overrides)
        return subprocess.run(["bash", str(NTFY_SCRIPT)], env=env, capture_output=True, text=True, timeout=30)

    def with_stub(self, *responses, **overrides):
        stub = Stub(responses)
        try:
            return self.send(stub.url, **overrides), stub.received
        finally:
            stub.close()

    def outcome(self):
        return self.outcome_file.read_text().strip() if self.outcome_file.exists() else None

    def test_accepted_message_is_sent_once_with_exact_body(self):
        result, received = self.with_stub(200)
        self.assertEqual((result.returncode, self.outcome()), (0, "sent"))
        self.assertEqual(received, [("/synthetic-topic", self.body_file.read_text(encoding="utf-8"))])

    def test_definite_rejections_are_failed_definite(self):
        """要求を処理前に拒否したと判断できるステータスだけを確実な未送信とする。"""
        for status in (400, 401, 403, 404, 405, 411, 413, 414, 415, 429):
            with self.subTest(status=status):
                result, received = self.with_stub(status)
                self.assertEqual((result.returncode, self.outcome()), (1, "failed_definite"))
                self.assertIn(f"HTTP {status}", result.stderr)
                self.assertEqual(len(received), 1)  # 既定は再試行0回

    def test_server_errors_and_other_statuses_are_unknown(self):
        """5xx(ゲートウェイ経由を含む)や想定外の3xx/4xxは受理の可能性を否定できない。"""
        for status in (500, 502, 503, 504, 301, 409, 418):
            with self.subTest(status=status):
                result, received = self.with_stub(status)
                self.assertEqual((result.returncode, self.outcome()), (3, "unknown"))
                self.assertIn(f"HTTP {status}", result.stderr)
                self.assertEqual(len(received), 1)

    def test_retry_is_opt_in_and_only_for_429(self):
        for status, expected_requests, outcome in ((429, 3, "failed_definite"), (503, 1, "unknown"),
                                                   (500, 1, "unknown"), (403, 1, "failed_definite")):
            with self.subTest(status=status):
                result, received = self.with_stub(status, NTFY_RETRY="2")
                self.assertEqual(self.outcome(), outcome)
                self.assertEqual(len(received), expected_requests)

    def test_retry_stops_at_first_success(self):
        result, received = self.with_stub(429, 200, NTFY_RETRY="2")
        self.assertEqual((result.returncode, self.outcome(), len(received)), (0, "sent", 2))

    def test_timeout_after_the_body_was_sent_is_unknown_and_not_retried(self):
        """受理後に応答が失われた場合は配信済みかもしれない: unknown とし、再試行もしない。"""
        for retry in ("0", "2"):
            with self.subTest(retry=retry):
                started = time.monotonic()
                result, received = self.with_stub("hang", NTFY_RETRY=retry)
                self.assertLess(time.monotonic() - started, 2.5)  # NTFY_MAX_TIME=1 で打ち切る(スタブは3秒応答しない)
                self.assertEqual((result.returncode, self.outcome()), (3, "unknown"))
                self.assertEqual(len(received), 1)

    def test_2xx_header_followed_by_transport_failure_is_not_sent(self):
        """200のヘッダーを受信してもcurlが正常完了しなければsentと断定しない。"""
        result, received = self.with_stub("stall_after_200")
        self.assertEqual((result.returncode, self.outcome()), (3, "unknown"))
        self.assertEqual(len(received), 1)

    def test_connection_dropped_after_the_body_is_unknown(self):
        result, received = self.with_stub("drop")
        self.assertEqual((result.returncode, self.outcome()), (3, "unknown"))
        self.assertEqual(len(received), 1)

    def test_refused_connection_is_failed_definite(self):
        result = self.send(f"http://127.0.0.1:{unused_port()}")
        self.assertEqual((result.returncode, self.outcome()), (1, "failed_definite"))

    def test_shell_metacharacters_in_body_are_sent_verbatim_and_not_executed(self):
        marker = self.dir / "executed"
        body = f'a" ; touch {marker} ; echo "b $(touch {marker}) `touch {marker}` $NTFY_TOPIC $HOME\nEOF\n'
        self.body_file.write_text(body, encoding="utf-8")
        result, received = self.with_stub(200)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(received[0][1], body)

    def test_errors_do_not_reveal_topic_or_body(self):
        self.body_file.write_text("CONFIDENTIAL-BODY\n", encoding="utf-8")
        for responses in ((403,), (500,), ("hang",)):
            with self.subTest(responses=responses):
                result, _ = self.with_stub(*responses, NTFY_TOPIC="SECRET-TOPIC")
                output = result.stdout + result.stderr
                self.assertNotIn("SECRET-TOPIC", output)
                self.assertNotIn("CONFIDENTIAL-BODY", output)

    def test_missing_or_empty_body_fails_without_sending(self):
        for content in (None, ""):
            with self.subTest(content=content):
                if content is None:
                    self.body_file.unlink(missing_ok=True)
                else:
                    self.body_file.write_text(content, encoding="utf-8")
                result, received = self.with_stub(200)
                self.assertEqual((result.returncode, self.outcome()), (1, "failed_definite"))
                self.assertEqual(received, [])


# ---------------------------------------------------------------------------
# daily.yml の静的検査(M1, M2, A3)
# ---------------------------------------------------------------------------

class TestWorkflowDefinition(unittest.TestCase):
    NOTIFY_STEPS = ("Notify via ntfy.sh (push notification)", "Notify via email")

    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.job = yaml.safe_load(self.text)["jobs"]["update"]
        self.steps = {s.get("name"): s for s in self.job["steps"]}

    def test_job_runs_only_on_main(self):
        self.assertEqual(self.job.get("if"), "github.ref == 'refs/heads/main'")

    def test_no_expression_is_expanded_into_a_shell_script(self):
        for step in self.job["steps"]:
            with self.subTest(step=step.get("name")):
                self.assertNotIn("${{", step.get("run", ""))

    def test_notifications_require_publish_success_and_not_each_other(self):
        """既定の success() 条件のままだと ntfy の失敗でメールが実行されない(A3)。"""
        self.assertEqual(self.steps["Commit and push updated data"].get("id"), "publish")
        for name in self.NOTIFY_STEPS:
            with self.subTest(step=name):
                condition = self.steps[name]["if"]
                self.assertIn("!cancelled()", condition)
                self.assertIn("steps.publish.outcome == 'success'", condition)
                self.assertNotIn("success()", condition)
                self.assertNotIn("failure()", condition)
                self.assertFalse(self.steps[name].get("continue-on-error", False))

    def test_channels_are_enabled_by_their_own_secret(self):
        self.assertIn("env.NTFY_TOPIC != ''", self.steps[self.NOTIFY_STEPS[0]]["if"])
        self.assertEqual(self.steps[self.NOTIFY_STEPS[0]]["env"]["NTFY_TOPIC"], "${{ secrets.NTFY_TOPIC }}")
        self.assertIn("env.SMTP_USERNAME != ''", self.steps[self.NOTIFY_STEPS[1]]["if"])
        self.assertEqual(self.steps[self.NOTIFY_STEPS[1]]["env"]["SMTP_USERNAME"], "${{ secrets.SMTP_USERNAME }}")

    def test_ntfy_step_uses_the_script_with_body_and_outcome_files(self):
        step = self.steps[self.NOTIFY_STEPS[0]]
        self.assertEqual(step["run"].strip(), "bash scripts/notify_ntfy.sh")
        self.assertIn("notify_body.txt", step["env"]["NOTIFY_BODY_FILE"])
        self.assertIn("ntfy_outcome.txt", step["env"]["NTFY_OUTCOME_FILE"])

    def test_publish_step_uses_the_guarded_script_and_no_pull_rebase(self):
        self.assertIn("bash scripts/publish_daily_data.sh", self.steps["Commit and push updated data"]["run"])
        self.assertNotIn("pull --rebase", self.text)

    def test_summary_output_delimiter_is_not_a_fixed_word(self):
        run = self.steps["Build notification summary"]["run"]
        self.assertNotIn('echo "EOF"', run)
        self.assertIn("uuid", run)

    def test_publication_requires_successful_collection_and_summary(self):
        """P1-1: update.py やサマリーが非ゼロ終了したら、既定の success() 条件で公開・通知は実行されない。"""
        names = [s.get("name") for s in self.job["steps"]]
        update_step, summary_step = "Run collection pipeline (update.py)", "Build notification summary"
        publish_step = "Commit and push updated data"
        self.assertLess(names.index(update_step), names.index(summary_step))
        self.assertLess(names.index(summary_step), names.index(publish_step))
        for name in (update_step, summary_step, publish_step):
            with self.subTest(step=name):
                self.assertNotIn("if", self.steps[name])
                self.assertFalse(self.steps[name].get("continue-on-error", False))
        self.assertEqual(self.steps[update_step]["run"].strip(), "python update.py")

    def test_failure_alert_reports_ntfy_outcome_with_timeouts(self):
        step = self.steps["Alert on workflow failure"]
        self.assertEqual(step["if"], "${{ failure() }}")
        self.assertIn("ntfy_outcome.txt", step["run"])
        self.assertIn("--max-time", step["run"])
        self.assertIn("--connect-timeout", step["run"])
        self.assertNotIn("--retry", step["run"])  # 失敗アラートも自動再試行は既定0回


# ---------------------------------------------------------------------------
# publish(M1, M3, B3): 一時Gitリポジトリ
# ---------------------------------------------------------------------------

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


class TestPublishScript(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.remote = self.dir / "remote.git"
        self.git("init", "-q", "--bare", "-b", "main", str(self.remote))
        seed = self.clone("seed")
        report = "".join(f"{i}\n" for i in range(1, 201))
        for path, content in (("data/threat_intel.db", "\x00db-base"), ("daily_report.md", report),
                              ("docs/data/dashboard_data.json", "{}\n"),
                              ("reports/daily_report_2026-10-01_run1.md", "r1\n"), ("update.py", "code\n"),
                              ("data/.gitkeep", ""), ("reports/.gitkeep", ""), ("docs/data/.gitkeep", ""),
                              (".gitignore", "__pycache__/\n*.pyc\n*.log\n")):
            (seed / path).parent.mkdir(parents=True, exist_ok=True)
            (seed / path).write_text(content)
        self.git("add", "-A", cwd=seed)
        self.git("commit", "-q", "-m", "base", cwd=seed)
        self.git("push", "-q", "origin", "HEAD:main", cwd=seed)
        self.seed = seed

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd, env={**os.environ, **GIT_ENV},
                              capture_output=True, text=True, check=True).stdout.strip()

    def clone(self, name, *extra):
        self.git("clone", "-q", *extra, f"file://{self.remote}", str(self.dir / name))
        return self.dir / name

    def commit_on_main(self, path, content, message):
        (self.seed / path).parent.mkdir(parents=True, exist_ok=True)
        (self.seed / path).write_text(content)
        self.git("add", "-A", cwd=self.seed)
        self.git("commit", "-q", "-m", message, cwd=self.seed)
        self.git("push", "-q", "origin", "HEAD:main", cwd=self.seed)

    def collect(self, repo):
        (repo / "data/threat_intel.db").write_text("\x00db-new-run")
        lines = (repo / "daily_report.md").read_text().splitlines()
        lines[149] = "run-edit"
        (repo / "daily_report.md").write_text("\n".join(lines) + "\n")

    def publish(self, repo, ref="refs/heads/main"):
        return subprocess.run(["bash", str(PUBLISH_SCRIPT)], cwd=repo, capture_output=True, text=True,
                              env={**os.environ, **GIT_ENV, "GITHUB_REF": ref})

    def main_log(self):
        return self.git("--git-dir", str(self.remote), "log", "--format=%s", "main").splitlines()

    def main_files(self):
        return set(self.git("--git-dir", str(self.remote), "ls-tree", "-r", "--name-only", "main").splitlines())

    def test_normal_run_publishes_only_generated_files(self):
        run = self.clone("run")
        self.collect(run)
        self.assertEqual(self.publish(run).returncode, 0)
        self.assertTrue(self.main_log()[0].startswith("chore: daily update"))
        changed = self.git("--git-dir", str(self.remote), "diff", "--name-only", "main~1", "main").splitlines()
        self.assertEqual(sorted(changed), ["daily_report.md", "data/threat_intel.db"])

    def test_ref_other_than_main_is_refused(self):
        run = self.clone("run")
        self.collect(run)
        self.assertNotEqual(self.publish(run, ref="refs/heads/feature").returncode, 0)
        self.assertEqual(self.main_log(), ["base"])

    def test_checkout_not_on_main_is_refused(self):
        """別ブランチのコミットを含む作業ツリーからはmainへ公開しない。"""
        run = self.clone("run")
        self.git("checkout", "-q", "-b", "feature", cwd=run)
        (run / "update.py").write_text("unreviewed\n")
        self.git("commit", "-q", "-am", "feat: unreviewed code", cwd=run)
        self.collect(run)
        self.assertNotEqual(self.publish(run).returncode, 0)
        self.assertEqual(self.main_log(), ["base"])

    def test_newer_generated_data_on_main_is_refused(self):
        run = self.clone("run")
        self.commit_on_main("data/threat_intel.db", "\x00db-other-run", "chore: newer daily update")
        self.collect(run)
        self.assertNotEqual(self.publish(run).returncode, 0)
        self.assertEqual(self.main_log()[0], "chore: newer daily update")

    def test_human_edit_of_generated_text_is_not_mixed(self):
        """別の行の編集はgitが自動マージできてしまう。生成ファイルへの変更があれば公開しない。"""
        run = self.clone("run")
        lines = (self.seed / "daily_report.md").read_text().splitlines()
        lines[0] = "human-edit"
        self.commit_on_main("daily_report.md", "\n".join(lines) + "\n", "docs: edit report")
        self.collect(run)
        self.assertNotEqual(self.publish(run).returncode, 0)
        self.assertNotIn("run-edit", self.git("--git-dir", str(self.remote), "show", "main:daily_report.md"))

    def test_new_generated_archive_on_main_is_not_mixed(self):
        """競合しない生成ファイル(別runのアーカイブ)が増えた場合も、混在させず公開しない。"""
        run = self.clone("run")
        self.commit_on_main("reports/daily_report_2026-10-02_run2.md", "r2\n", "chore: other run archive")
        self.collect(run)
        self.assertNotEqual(self.publish(run).returncode, 0)
        self.assertEqual(self.main_log()[0], "chore: other run archive")

    def test_code_only_commit_on_main_is_rebased_over(self):
        run = self.clone("run", "--depth", "1")
        self.commit_on_main("update.py", "fix\n", "fix: code")
        self.collect(run)
        result = self.publish(run)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.main_log()[1], "fix: code")

    SECRET = "TOKEN=synthetic-secret-value"

    def remote_contains_secret(self):
        """リモートの全オブジェクト(全ref・全コミット)に機密文字列が1件も含まれないか。"""
        objects = self.git("--git-dir", str(self.remote), "rev-list", "--all", "--objects").splitlines()
        for line in objects:
            sha = line.split()[0]
            if self.git("--git-dir", str(self.remote), "cat-file", "-t", sha) == "blob":
                if self.SECRET in self.git("--git-dir", str(self.remote), "cat-file", "-p", sha):
                    return True
        return False

    def test_normal_run_publishes_every_allowed_generated_file(self):
        run = self.clone("run")
        self.collect(run)
        (run / "docs/data/dashboard_data.json").write_text('{"run": 2}\n')
        (run / "reports/daily_report_2026-10-02_run2.md").write_text("r2\n")
        (run / "reports/daily_report_unknown-date_run3.md").write_text("r3\n")
        self.assertEqual(self.publish(run).returncode, 0)
        changed = self.git("--git-dir", str(self.remote), "diff", "--name-only", "main~1", "main").splitlines()
        self.assertEqual(sorted(changed), ["daily_report.md", "data/threat_intel.db", "docs/data/dashboard_data.json",
                                           "reports/daily_report_2026-10-02_run2.md",
                                           "reports/daily_report_unknown-date_run3.md"])

    def test_files_outside_the_allowlist_stop_publication(self):
        """P1-1: 生成ディレクトリ内の許可リスト外ファイル(.gitignore対象を含む)は1件もcommitされない。"""
        for name in ("data/.env", "docs/data/credentials.json", "reports/debug.log", "data/__pycache__/x.pyc",
                     "data/threat_intel.db-wal", "data/threat_intel.db-shm", "data/threat_intel.db-journal",
                     "reports/x.md", "reports/daily_report_2026-10-02_run2.md.bak", "data/sub/extra.db"):
            with self.subTest(file=name):
                run = self.clone(f"run-{name.replace('/', '_')}")
                self.collect(run)
                (run / name).parent.mkdir(parents=True, exist_ok=True)
                (run / name).write_text(self.SECRET + "\n")
                result = self.publish(run)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertEqual(self.main_log(), ["base"])
                self.assertFalse(self.remote_contains_secret())

    def test_tracked_generated_paths_outside_the_allowlist_stop_publication(self):
        """追跡済みの .gitkeep の変更、既存アーカイブの削除・改名は公開しない。"""
        def modify_gitkeep(run):
            (run / "data/.gitkeep").write_text(self.SECRET + "\n")

        def delete_archive(run):
            (run / "reports/daily_report_2026-10-01_run1.md").unlink()

        def rename_archive(run):
            (run / "reports/daily_report_2026-10-01_run1.md").rename(run / "reports/daily_report_2026-10-01_run9.md")

        for label, change in (("modified .gitkeep", modify_gitkeep), ("deleted archive", delete_archive),
                              ("renamed archive", rename_archive)):
            with self.subTest(change=label):
                run = self.clone(f"run-{label.replace(' ', '_')}")
                self.collect(run)
                change(run)
                self.assertNotEqual(self.publish(run).returncode, 0)
                self.assertEqual(self.main_log(), ["base"])
                self.assertIn("reports/daily_report_2026-10-01_run1.md", self.main_files())
                self.assertFalse(self.remote_contains_secret())

    def test_any_prestaged_change_stops_publication(self):
        """インデックスに事前ステージがあれば、許可対象ファイルであっても公開しない。"""
        for name in ("data/threat_intel.db", "docs/data/credentials.json"):
            with self.subTest(staged=name):
                run = self.clone(f"run-staged-{name.replace('/', '_')}")
                self.collect(run)
                if not (run / name).exists():
                    (run / name).write_text(self.SECRET + "\n")
                self.git("add", "--", name, cwd=run)
                self.assertNotEqual(self.publish(run).returncode, 0)
                self.assertEqual(self.main_log(), ["base"])
                self.assertFalse(self.remote_contains_secret())

    def test_staged_file_outside_generated_paths_is_refused(self):
        """B3: 事前にステージされた対象外ファイル(秘密情報を含み得る)を公開しない。"""
        for name in ("notes.txt", ".env", "config/credentials.json"):
            with self.subTest(staged=name):
                run = self.clone(f"run-{name.replace('/', '_')}")
                self.collect(run)
                (run / name).parent.mkdir(parents=True, exist_ok=True)
                (run / name).write_text(self.SECRET + "\n")
                self.git("add", "--", name, cwd=run)
                result = self.publish(run)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertEqual(self.main_log(), ["base"])
                self.assertNotIn(name, self.main_files())
                self.assertFalse(self.remote_contains_secret())

    def test_staged_change_to_tracked_file_outside_generated_paths_is_refused(self):
        run = self.clone("run")
        self.collect(run)
        (run / "update.py").write_text("local change\n")
        self.git("add", "update.py", cwd=run)
        self.assertNotEqual(self.publish(run).returncode, 0)
        self.assertEqual(self.main_log(), ["base"])

    def test_untracked_and_unstaged_files_are_not_published(self):
        run = self.clone("run")
        self.collect(run)
        (run / "scratch.txt").write_text("untracked\n")
        self.assertEqual(self.publish(run).returncode, 0)
        self.assertNotIn("scratch.txt", self.main_files())

    def test_no_changes_does_not_push(self):
        run = self.clone("run")
        result = self.publish(run)
        self.assertEqual(result.returncode, 0)
        self.assertIn("No changes to commit.", result.stdout)
        self.assertEqual(self.main_log(), ["base"])

    def publish_with_failing_git(self, repo, subcommand, match="", rc=128):
        """git の指定サブコマンド(引数に match を含む呼び出し)だけを、標準出力なしで rc で失敗させる。"""
        fake = self.dir / "fakebin"
        fake.mkdir(exist_ok=True)
        (fake / "git").write_text(
            "#!/usr/bin/env bash\n"
            'if [ "$1" = "$FAIL_SUBCMD" ] && [[ "$*" == *"$FAIL_MATCH"* ]]; then '
            'echo "injected failure" >&2; exit "$FAIL_RC"; fi\n'
            f'exec {shutil.which("git")} "$@"\n')
        (fake / "git").chmod(0o755)
        env = {**os.environ, **GIT_ENV, "GITHUB_REF": "refs/heads/main", "PATH": f"{fake}:{os.environ['PATH']}",
               "FAIL_SUBCMD": subcommand, "FAIL_MATCH": match, "FAIL_RC": str(rc)}
        return subprocess.run(["bash", str(PUBLISH_SCRIPT)], cwd=repo, capture_output=True, text=True, env=env)

    def test_failing_git_queries_stop_publication(self):
        """P1-2: 失敗したgitは何も出力しない。空の結果を「変更なし」「問題なし」と読まずに公開を止める。"""
        cases = (  # match は失敗させる呼び出しだけに一致させる(後段の別の検査で止まらないように)
            ("status", "", False), ("diff", "--cached --quiet", False), ("diff", "--cached --name-only", False),
            ("diff-tree", "", False), ("diff", "FETCH_HEAD -- data", True), ("merge-base", "", False),
            ("rev-list", "", False),
        )
        for i, (subcommand, match, newer_on_main) in enumerate(cases):
            for rc in (1, 128):
                with self.subTest(git=f"{subcommand} {match}".strip(), rc=rc):
                    run = self.clone(f"run-git-failure-{i}-{rc}")
                    if newer_on_main:
                        self.commit_on_main(f"reports/daily_report_2026-10-0{rc % 9}_run{rc}.md", "other\n",
                                            f"chore: other run archive {rc}")
                    expected_log = self.main_log()
                    self.collect(run)
                    result = self.publish_with_failing_git(run, subcommand, match, rc)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("No changes to commit.", result.stdout)
                    self.assertIn("Refusing to publish", result.stderr)
                    self.assertEqual(self.main_log(), expected_log)

    def test_successful_empty_status_still_means_no_changes(self):
        """P1-2: 正常終了した空の結果(変更なし)は、gitの失敗とは区別して終了コード0のまま。"""
        run = self.clone("run")
        result = self.publish_with_failing_git(run, "no-such-subcommand")
        self.assertEqual(result.returncode, 0)
        self.assertIn("No changes to commit.", result.stdout)
        self.assertEqual(self.main_log(), ["base"])

    def local_history_contains_secret(self, repo):
        """ローカルの全ref・reflogから到達できるオブジェクトに機密文字列が含まれるか。"""
        objects = self.git("rev-list", "--all", "--reflog", "--objects", cwd=repo).splitlines()
        return any(self.git("cat-file", "-t", line.split()[0], cwd=repo) == "blob"
                   and self.SECRET in self.git("cat-file", "-p", line.split()[0], cwd=repo) for line in objects)

    def test_refused_publish_leaves_no_local_commit_or_staged_secret(self):
        """P2-2: pushされなくても、拒否した公開がローカルのcommitやインデックスに機密ファイルを残さない。"""
        for name in ("data/.env", "reports/debug.log", "data/threat_intel.db-wal", "docs/data/credentials.json"):
            with self.subTest(file=name):
                run = self.clone(f"run-local-{name.replace('/', '_')}")
                base = self.git("rev-parse", "HEAD", cwd=run)
                self.collect(run)
                (run / name).write_text(self.SECRET + "\n")
                self.assertNotEqual(self.publish(run).returncode, 0)
                self.assertEqual(self.git("rev-parse", "HEAD", cwd=run), base)
                self.assertEqual(self.git("diff", "--cached", "--name-only", cwd=run), "")
                self.assertFalse(self.local_history_contains_secret(run))
                self.assertFalse(self.remote_contains_secret())


# ---------------------------------------------------------------------------
# 収集器の応答検証(A1): ローカルHTTPスタブ
# ---------------------------------------------------------------------------

HTML_ERROR = "<html><head><title>503</title></head><body>Service Unavailable</body></html>"
RSS_ITEM = "<item><title>CVE-2099-1111 synthetic</title><link>https://synthetic.test/a</link></item>"
RSS = '<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{}</channel></rss>'
ATOM_EMPTY = '<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title></feed>'
RSS_BOZO_WITH_ITEM = RSS.format(RSS_ITEM).replace("<title>t</title>", "<title>t &nbsp;</title>")
RSS_TRUNCATED = RSS.format(RSS_ITEM)[:-len("</channel></rss>")] + "<item><title>b"
NVD_PAGE = '{"resultsPerPage": 2000, "startIndex": 0, "totalResults": %s, "vulnerabilities": %s}'


class TestCollectorResponses(unittest.TestCase):
    """HTTP 200 でも不正な応答は取得失敗(None)、正常な空応答は成功0件([])。"""

    CASES = {
        RssCollector: [
            ("HTML error page", "text/html", HTML_ERROR, None),
            ("JSON body", "application/json", '{"error": "x"}', None),
            ("empty body", "text/plain", "", None),
            ("valid empty RSS", "application/rss+xml", RSS.format(""), 0),
            ("valid empty Atom", "application/atom+xml", ATOM_EMPTY, 0),
            ("valid RSS with item", "application/rss+xml", RSS.format(RSS_ITEM), 1),
            ("bozo feed that still has an item", "application/rss+xml", RSS_BOZO_WITH_ITEM, 1),
            # 2件目は途中で切れてリンクがないため既存の規則でスキップされ、完全な1件だけが残る。
            ("truncated feed with items", "application/rss+xml", RSS_TRUNCATED, 1),
            ("truncated feed without items", "application/rss+xml", RSS.format("")[:-len("</channel></rss>")], None),
        ],
        KevCollector: [
            ("HTML error page", "text/html", HTML_ERROR, None),
            ("missing key", "application/json", "{}", None),
            ("wrong type", "application/json", '{"vulnerabilities": "x"}', None),
            ("object instead of list", "application/json", '{"vulnerabilities": {}}', None),
            ("list root", "application/json", "[]", None),
            ("valid empty", "application/json", '{"vulnerabilities": []}', 0),
            ("valid entry", "application/json", '{"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}', 1),
        ],
        NvdCollector: [
            ("HTML error page", "text/html", HTML_ERROR, None),
            ("error JSON", "application/json", '{"message": "rate limited"}', None),
            ("wrong type", "application/json", NVD_PAGE % ('0', '{}'), None),
            ("paging fields missing", "application/json", '{"vulnerabilities": [{"cve": {"id": "CVE-2099-0002"}}]}',
             None),
            ("valid empty", "application/json", NVD_PAGE % ("0", "[]"), 0),
            ("valid entry", "application/json", NVD_PAGE % ("1", '[{"cve": {"id": "CVE-2099-0002"}}]'), 1),
        ],
        GithubAdvisoryCollector: [
            ("HTML error page", "text/html", HTML_ERROR, None),
            ("error object", "application/json", '{"message": "API rate limit exceeded"}', None),
            ("empty object", "application/json", "{}", None),
            ("list of non-objects", "application/json", "[1, 2]", None),
            ("valid empty", "application/json", "[]", 0),
            ("valid entry", "application/json", '[{"cve_id": "CVE-2099-0003", "summary": "s"}]', 1),
        ],
    }

    def setUp(self):
        patcher = mock.patch.dict(os.environ, NO_PROXY_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def collect(self, collector_cls, ctype, body):
        stub = Stub(routes={"/feed": (200, ctype, body)})
        try:
            conf = {"id": "synthetic", "name": "Synthetic", "type": "x", "url": stub.url + "/feed", "trust_level": 1}
            with mock.patch.object(update_mod, "build_collector", lambda c: collector_cls(c)):
                return update_mod.safe_collect_from_source(conf, mock.Mock())[0]
        finally:
            stub.close()

    def test_response_shapes(self):
        for collector_cls, cases in self.CASES.items():
            for label, ctype, body, expected in cases:
                with self.subTest(collector=collector_cls.__name__, case=label):
                    items = self.collect(collector_cls, ctype, body)
                    if expected is None:
                        self.assertIsNone(items)
                    else:
                        self.assertEqual(len(items), expected)


# ---------------------------------------------------------------------------
# 収集結果と通知(H4, H5, A1, A2, D1, Z1): 一時SQLite
# ---------------------------------------------------------------------------

def kev_item(source_id, cve):
    return RawItem(source_id=source_id, source_name=source_id, source_trust_level=1, title=f"{cve} synthetic",
                   url=f"https://synthetic.test/{cve}", published_at="2026-10-22T00:00:00+00:00",
                   summary="synthetic", raw_text=cve, extra={"cve_ids": [cve], "in_kev": True})


class FailingCollector(BaseCollector):
    def collect(self):
        raise RuntimeError("synthetic network failure")


class EmptyCollector(BaseCollector):
    def collect(self):
        return []


class PipelineCase(unittest.TestCase):
    SOURCES = [("src_rss", "Synthetic RSS", "rss"), ("src_kev", "CISA KEV (synthetic)", "kev_json")]

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.write_sources(tmp / "sources.yaml", self.SOURCES)
        self.patches = [
            (dbmod, "DB_PATH", tmp / "test.db"), (update_mod, "SOURCES_YAML", tmp / "sources.yaml"),
            (update_mod, "LOG_DIR", tmp / "logs"), (update_mod, "build_collector", update_mod.build_collector),
            (daily_report, "REPORTS_DIR", tmp / "reports"), (daily_report, "DAILY_REPORT_PATH", tmp / "daily_report.md"),
            (dashboard_export, "DASHBOARD_DATA_PATH", tmp / "dashboard_data.json"),
            (dashboard_export, "generate_and_save", dashboard_export.generate_and_save),
            (notify_summary, "DATA_PATH", tmp / "dashboard_data.json"), (notify_summary, "DB_PATH", tmp / "test.db"),
            (sys, "argv", sys.argv),
        ]
        self.saved = [(obj, name, getattr(obj, name)) for obj, name, _ in self.patches]
        for obj, name, value in self.patches:
            setattr(obj, name, value)
        self.tmp = tmp
        dbmod.init_db()

    def tearDown(self):
        for obj, name, value in self.saved:
            setattr(obj, name, value)
        self._tmp.cleanup()

    @staticmethod
    def write_sources(path, sources):
        path.write_text(yaml.safe_dump({"sources": [
            {"id": sid, "name": name, "type": typ, "url": f"https://{sid}.test/feed", "trust_level": 1,
             "lang": "en", "region": "global"} for sid, name, typ in sources]}), encoding="utf-8")

    def use_collectors(self, by_source):
        def build(conf):
            kind = by_source[conf["id"]]
            if isinstance(kind, list):
                class Fixed(BaseCollector):
                    def collect(self_inner):
                        return kind
                return Fixed(conf)
            return kind(conf)
        update_mod.build_collector = build

    def run_update(self, *args):
        sys.argv = ["update.py", *args]
        return update_mod.main()

    def runs(self):
        with dbmod.connection() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM run_log ORDER BY id")]

    def notify(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = notify_summary.main()
        return code, out.getvalue(), err.getvalue()


class TestCollectionOutcome(PipelineCase):
    def test_all_sources_failing_exits_nonzero_without_new_reports(self):
        self.use_collectors({"src_rss": FailingCollector, "src_kev": FailingCollector})
        self.assertEqual(self.run_update(), 2)
        self.assertEqual((self.runs()[-1]["sources_ok"], self.runs()[-1]["sources_failed"]), (0, 2))
        self.assertFalse((self.tmp / "dashboard_data.json").exists())
        self.assertFalse((self.tmp / "daily_report.md").exists())

    def test_successful_empty_fetch_is_not_a_failure(self):
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        self.assertEqual((self.runs()[-1]["sources_ok"], self.runs()[-1]["sources_failed"]), (2, 0))

    def test_partial_failure_still_exits_zero(self):
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0001")], "src_kev": FailingCollector})
        self.assertEqual(self.run_update(), 0)
        self.assertEqual((self.runs()[-1]["sources_ok"], self.runs()[-1]["sources_failed"]), (1, 1))

    def test_build_collector_exception_counts_as_failure(self):
        def build(conf):
            raise RuntimeError("synthetic config error")
        update_mod.build_collector = build
        self.assertEqual(self.run_update(), 2)

    def test_dashboard_json_failure_exits_nonzero(self):
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0002")], "src_kev": EmptyCollector})
        dashboard_export.generate_and_save = mock.Mock(side_effect=RuntimeError("synthetic"))
        self.assertEqual(self.run_update(), 3)

    def test_zero_configured_sources_is_a_configuration_error(self):
        self.write_sources(update_mod.SOURCES_YAML, [])
        self.assertEqual(self.run_update(), 4)
        self.assertEqual(self.runs(), [])

    def test_unknown_source_filter_is_a_configuration_error(self):
        self.assertEqual(self.run_update("--source", "no_such_source"), 4)
        self.assertEqual(self.runs(), [])


class TestNotificationGuard(PipelineCase):
    def test_complete_collection_has_no_partial_warning(self):
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0003")], "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        code, out, _ = self.notify()
        self.assertEqual(code, 0)
        self.assertIn("新規の悪用確認済みCVE 1件", out)
        self.assertNotIn("部分収集", out)

    def test_all_sources_failing_never_produces_no_change_message(self):
        """H4: 前回は正常、今回は全ソース失敗。'重要な変化なし' は出力されない。"""
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        self.use_collectors({"src_rss": FailingCollector, "src_kev": FailingCollector})
        self.assertEqual(self.run_update(), 2)
        code, out, err = self.notify()
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("一致しません", err)

    def test_partial_collection_warns_and_names_the_critical_failed_source(self):
        """A2: KEVが失敗した回は「変化なし」と断定せず、失敗ソースと件数を明示する。"""
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": FailingCollector})
        self.assertEqual(self.run_update(), 0)
        code, out, _ = self.notify()
        self.assertEqual(code, 0)
        self.assertIn("部分収集: 成功1 / 失敗1ソース、アイテム処理失敗0件", out)
        self.assertIn("取得に失敗したソース: CISA KEV (synthetic)", out)
        self.assertIn("重要ソース CISA KEV (synthetic) の取得に失敗", out)
        self.assertNotIn("本日は重要な新規変化はありません", out)
        self.assertIn("部分収集のため断定できません", out)

    def test_item_processing_failures_alone_are_reported(self):
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0004")], "src_kev": EmptyCollector})
        with mock.patch.object(update_mod, "process_item", side_effect=RuntimeError("synthetic parse failure")):
            self.assertEqual(self.run_update(), 0)
        code, out, _ = self.notify()
        self.assertEqual(code, 0)
        self.assertIn("アイテム処理失敗1件", out)
        self.assertNotIn("本日は重要な新規変化はありません", out)

    def test_update_records_versioned_quality(self):
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": FailingCollector})
        self.assertEqual(self.run_update(), 0)
        quality = json.loads(self.runs()[-1]["notes"].split(" quality=", 1)[1])
        self.assertEqual(quality, {"version": 1, "items_failed": 0, "incomplete_sources": [], "failed_sources": [
            {"id": "src_kev", "name": "CISA KEV (synthetic)", "type": "kev_json"}]})

    def test_missing_or_damaged_quality_is_reported_as_unknown(self):
        """P1-3: 品質情報が欠損・破損・旧形式・矛盾なら、監視品質が正常だったと推定しない。"""
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        kev = {"id": "src_kev", "name": "CISA KEV (synthetic)", "type": "kev_json"}
        variants = {
            "old format without quality": "2ソース中 成功2/失敗0",
            "old format with item failures": "2ソース中 成功2/失敗0 (アイテム処理失敗3件)",
            "truncated JSON": '2ソース中 quality={"version": 1, "failed_sources": [{"id"',
            "JSON is not an object": "2ソース中 quality=[1, 2]",
            "no version": '2ソース中 quality={"failed_sources": [], "incomplete_sources": [], "items_failed": 0}',
            "unknown version": '2ソース中 quality={"version": 2, "failed_sources": [], "incomplete_sources": [], '
                               '"items_failed": 0}',
            "items_failed as string": '2ソース中 quality={"version": 1, "failed_sources": [], '
                                      '"incomplete_sources": [], "items_failed": "0"}',
            "items_failed negative": '2ソース中 quality={"version": 1, "failed_sources": [], '
                                     '"incomplete_sources": [], "items_failed": -1}',
            "source without type": '2ソース中 quality={"version": 1, "failed_sources": [{"id": "x"}], '
                                   '"incomplete_sources": [], "items_failed": 0}',
            "count disagrees with run_log": "2ソース中 quality=" + json.dumps(
                {"version": 1, "failed_sources": [kev], "incomplete_sources": [], "items_failed": 0},
                ensure_ascii=False),
            "notes NULL": None,
        }
        data = json.loads(notify_summary.DATA_PATH.read_text(encoding="utf-8"))
        for label, notes in variants.items():
            with self.subTest(notes=label):
                with dbmod.connection() as conn:
                    conn.execute("UPDATE run_log SET notes = ? WHERE id = ?", (notes, data["last_run"]["id"]))
                changed = {**data, "last_run": {**data["last_run"], "notes": notes}}
                notify_summary.DATA_PATH.write_text(json.dumps(changed, ensure_ascii=False), encoding="utf-8")
                code, out, _ = self.notify()
                self.assertEqual(code, 0)  # 警告付きで通知する
                self.assertIn("収集品質を確認できません", out)
                self.assertIn("KEV・NVDを含む全ソースの取得状況は未確認", out)
                self.assertNotIn("本日は重要な新規変化はありません", out)

    def test_malformed_failed_source_with_matching_count_is_unknown(self):
        """件数が一致していても、失敗ソースの記録が不完全なら品質不明とする(例外で落ちない)。"""
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": FailingCollector})
        self.assertEqual(self.run_update(), 0)
        data = json.loads(notify_summary.DATA_PATH.read_text(encoding="utf-8"))
        for label, source in (("missing type", {"id": "src_kev"}), ("missing id", {"type": "kev_json"}),
                              ("type not a string", {"id": "src_kev", "type": 1})):
            with self.subTest(source=label):
                notes = "2ソース中 quality=" + json.dumps(
                    {"version": 1, "failed_sources": [source], "incomplete_sources": [], "items_failed": 0})
                with dbmod.connection() as conn:
                    conn.execute("UPDATE run_log SET notes = ? WHERE id = ?", (notes, data["last_run"]["id"]))
                changed = {**data, "last_run": {**data["last_run"], "notes": notes}}
                notify_summary.DATA_PATH.write_text(json.dumps(changed, ensure_ascii=False), encoding="utf-8")
                code, out, _ = self.notify()
                self.assertEqual(code, 0)
                self.assertIn("収集品質を確認できません", out)

    def test_stale_dashboard_after_export_failure_is_not_summarised(self):
        """H5: 前回のJSONが残ったまま今回のJSON生成に失敗した場合、古い要約を通知しない。"""
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0005")], "src_kev": EmptyCollector})
        dashboard_export.generate_and_save = mock.Mock(side_effect=RuntimeError("synthetic"))
        self.assertEqual(self.run_update(), 3)
        code, out, _ = self.notify()
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")

    def test_same_run_id_with_different_identity_is_refused(self):
        """D1: DB復元等でrun_idが再利用された場合、開始時刻などの不一致で拒否する。"""
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        data = json.loads(notify_summary.DATA_PATH.read_text(encoding="utf-8"))
        for key, value in (("started_at", "2026-10-01 00:00:00"), ("finished_at", "2026-10-01 00:01:00"),
                           ("sources_ok", 1), ("sources_failed", 1)):
            with self.subTest(field=key):
                changed = {**data, "last_run": {**data["last_run"], key: value}}
                notify_summary.DATA_PATH.write_text(json.dumps(changed), encoding="utf-8")
                code, out, err = self.notify()
                self.assertNotEqual(code, 0)
                self.assertEqual(out, "")
                self.assertIn(key, err)

    def test_missing_or_malformed_dashboard_is_refused(self):
        path = notify_summary.DATA_PATH
        for content in (None, "{", json.dumps([]), json.dumps({"last_run": None})):
            with self.subTest(content=content):
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(content, encoding="utf-8")
                code, out, _ = self.notify()
                self.assertNotEqual(code, 0)
                self.assertEqual(out, "")

    def test_unfinished_or_empty_run_is_refused(self):
        with dbmod.connection() as conn:
            run_id = dbmod.start_run(conn)
            row = dict(conn.execute("SELECT * FROM run_log WHERE id = ?", (run_id,)).fetchone())
        for override in ({"sources_ok": 2}, {"finished_at": "2026-10-22 00:00:00", "sources_ok": 0}):
            with self.subTest(override=override):
                with dbmod.connection() as conn:
                    conn.execute("UPDATE run_log SET finished_at = ?, sources_ok = ? WHERE id = ?",
                                 (override.get("finished_at"), override["sources_ok"], run_id))
                empty_diff = {"significant_change": False, "new_incidents": [], "escalated": [],
                              "japan_victims": [], "kev_items": []}
                notify_summary.DATA_PATH.write_text(json.dumps({"last_run": {**row, **override},
                                                                "diff_since_last_run": empty_diff}), encoding="utf-8")
                self.assertNotEqual(self.notify()[0], 0)

    def test_missing_database_is_refused(self):
        notify_summary.DATA_PATH.write_text(json.dumps({"last_run": {"id": 1, "finished_at": "x", "sources_ok": 1}}),
                                            encoding="utf-8")
        notify_summary.DB_PATH = self.tmp / "absent.db"
        self.assertNotEqual(self.notify()[0], 0)
        self.assertFalse((self.tmp / "absent.db").exists())


# ---------------------------------------------------------------------------
# Codex監査 P1-1: レポート生成・書き込みの失敗
# ---------------------------------------------------------------------------

class TestReportFailure(PipelineCase):
    SECRET = "TOKEN=synthetic-secret-value"

    def published_files(self):
        paths = [self.tmp / "daily_report.md", self.tmp / "dashboard_data.json", *sorted(self.tmp.glob("reports/*"))]
        return {p.relative_to(self.tmp).as_posix(): p.read_bytes() for p in paths if p.is_file()}

    def temporary_files(self):
        return sorted(p.name for p in self.tmp.rglob(".*.tmp"))

    def first_run(self):
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0101")], "src_kev": EmptyCollector})
        return self.published_files()

    def test_report_exception_exits_nonzero_without_touching_published_files(self):
        """例外文を公開レポートへ書かず、前回の成果物を残したまま非ゼロ終了する(通知も拒否される)。"""
        before = self.first_run()
        with mock.patch.object(daily_report, "build_report_markdown", side_effect=RuntimeError("boom " + self.SECRET)):
            self.assertEqual(self.run_update(), 5)
        self.assertEqual(self.published_files(), before)
        self.assertEqual(self.temporary_files(), [])
        self.assertNotEqual(self.notify()[0], 0)

    def test_failed_write_keeps_previous_report_and_leaves_no_temporary_file(self):
        """2つ目のファイルの置き換えに失敗しても daily_report.md は前回のまま。一時ファイルも残さない。"""
        before = self.first_run()
        real_replace, calls = os.replace, []

        def replace(src, dst):
            calls.append(Path(dst).name)
            if Path(dst).name == "daily_report.md":
                raise OSError("synthetic disk full")
            return real_replace(src, dst)
        with mock.patch.object(daily_report.os, "replace", replace):
            self.assertEqual(self.run_update(), 5)
        after = self.published_files()
        self.assertEqual(after["daily_report.md"], before["daily_report.md"])
        self.assertEqual(after["dashboard_data.json"], before["dashboard_data.json"])
        self.assertEqual(self.temporary_files(), [])
        self.assertEqual(calls[-1], "daily_report.md")

    def test_failed_temporary_write_replaces_nothing(self):
        """2つ目の一時ファイルを作れない場合、日付付きアーカイブも含めてどのファイルも置き換えない。"""
        before = self.first_run()
        real_mkstemp = tempfile.mkstemp

        def mkstemp(*args, **kwargs):
            if kwargs.get("prefix") == ".daily_report.md.":
                raise OSError("synthetic disk full")
            return real_mkstemp(*args, **kwargs)
        with mock.patch.object(daily_report.tempfile, "mkstemp", mkstemp):
            self.assertEqual(self.run_update(), 5)
        self.assertEqual(self.published_files(), before)
        self.assertEqual(self.temporary_files(), [])

    def test_failed_dashboard_write_keeps_previous_json(self):
        before = self.first_run()
        real_replace = os.replace

        def replace(src, dst):
            if Path(dst).name == "dashboard_data.json":
                raise OSError("synthetic disk full")
            return real_replace(src, dst)
        with mock.patch.object(daily_report.os, "replace", replace):
            self.assertEqual(self.run_update(), 3)
        self.assertEqual(self.published_files()["dashboard_data.json"], before["dashboard_data.json"])
        self.assertEqual(self.temporary_files(), [])
        self.assertNotEqual(self.notify()[0], 0)


# ---------------------------------------------------------------------------
# Codex監査 P1-3: 差分情報(diff_since_last_run)の欠損・破損・矛盾
# ---------------------------------------------------------------------------

class TestDiffValidation(PipelineCase):
    def run_with_new_kev(self):
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0301")], "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        return json.loads(notify_summary.DATA_PATH.read_text(encoding="utf-8"))

    def test_damaged_diff_with_a_new_kev_is_never_no_change(self):
        """新規KEVがある回の差分情報が欠損・破損・矛盾していれば、通知を中止し「変化なし」とも書かない。"""
        data = self.run_with_new_kev()
        diff = data["diff_since_last_run"]
        variants = {
            "diff null": None, "diff empty object": {}, "diff is a list": [],
            "significant_change missing": {k: v for k, v in diff.items() if k != "significant_change"},
            "significant_change as string": {**diff, "significant_change": "false"},
            "significant_change as number": {**diff, "significant_change": 0},
            "kev_items missing": {k: v for k, v in diff.items() if k != "kev_items"},
            "kev_items not a list": {**diff, "kev_items": "x", "significant_change": False},
            "kev_items entries not objects": {**diff, "kev_items": [1]},
            "new_incidents missing": {k: v for k, v in diff.items() if k != "new_incidents"},
            "significant_change false with kev_items": {**diff, "significant_change": False},
            "significant_change true with nothing": {**diff, "kev_items": [], "new_incidents": [],
                                                     "escalated": [], "japan_victims": []},
        }
        for label, changed in variants.items():
            with self.subTest(diff=label):
                notify_summary.DATA_PATH.write_text(json.dumps({**data, "diff_since_last_run": changed},
                                                               ensure_ascii=False), encoding="utf-8")
                code, out, err = self.notify()
                self.assertNotEqual(code, 0)
                self.assertEqual(out, "")
                self.assertIn("差分情報", err)
                self.assertNotIn("重要な新規変化はありません", notify_summary.build_summary_text())

    def test_new_kev_dropped_from_a_consistent_diff_is_refused(self):
        """差分のKEV一覧が欠けて「変化なし」と整合した形になっても、DBの新規KEVと照合して拒否する。"""
        data = self.run_with_new_kev()
        dropped = {**data["diff_since_last_run"], "kev_items": [], "new_incidents": [], "significant_change": False}
        notify_summary.DATA_PATH.write_text(json.dumps({**data, "diff_since_last_run": dropped}, ensure_ascii=False),
                                            encoding="utf-8")
        code, out, err = self.notify()
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("新規KEVがDBでは1件", err)

    def test_escalation_alone_requires_significant_change(self):
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        data = json.loads(notify_summary.DATA_PATH.read_text(encoding="utf-8"))
        diff = {**data["diff_since_last_run"], "escalated": [{"id": 1, "severity": "High"}], "significant_change": False}
        notify_summary.DATA_PATH.write_text(json.dumps({**data, "diff_since_last_run": diff}, ensure_ascii=False),
                                            encoding="utf-8")
        code, out, err = self.notify()
        self.assertNotEqual(code, 0)
        self.assertIn("significant_change", err)

    def test_complete_diff_without_changes_is_still_reported(self):
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        code, out, _ = self.notify()
        self.assertEqual(code, 0)
        self.assertIn("本日は重要な新規変化はありません", out)


# ---------------------------------------------------------------------------
# Codex監査 P1-4: NVDのページング
# ---------------------------------------------------------------------------

def nvd_pages(total, overrides=None, cap=2000):
    """NVD API 2.0 の形の応答を返すルート。overrides[startIndex] で特定ページの応答を差し替える。"""
    def route(query):
        start = int(query["startIndex"][0])
        per = min(int(query["resultsPerPage"][0]), cap)
        if overrides and start in overrides:
            return overrides[start](start, per)
        vulns = [{"cve": {"id": f"CVE-2099-{i:05d}"}} for i in range(start, min(start + per, total))]
        return 200, "application/json", json.dumps(
            {"resultsPerPage": per, "startIndex": start, "totalResults": total, "vulnerabilities": vulns})
    return route


def nvd_body(start, per, total, ids):
    return 200, "application/json", json.dumps({"resultsPerPage": per, "startIndex": start, "totalResults": total,
                                                "vulnerabilities": [{"cve": {"id": i}} for i in ids]})


class TestNvdPaging(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NO_PROXY_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("NVD_API_KEY", None)
        self.sleep = mock.patch("collectors.nvd_collector.time.sleep").start()
        self.addCleanup(mock.patch.stopall)

    def collect(self, route, **kwargs):
        """ページング自体を確かめるテストでは上限を広げる。既定の上限は test_default_limit_* で確かめる。"""
        if kwargs.pop("default_limit", False) is False:
            kwargs.setdefault("max_pages", 10)
        stub = Stub(routes={"/rest": route})
        try:
            conf = {"id": "nvd_cve", "name": "NVD", "type": "nvd_api", "url": stub.url + "/rest", "trust_level": 1}
            with mock.patch.object(update_mod, "build_collector", lambda c: NvdCollector(c, **kwargs)):
                items, incomplete = update_mod.safe_collect_from_source(conf, mock.Mock())
            return items, incomplete, [int(q["startIndex"][0]) for _, q, _ in stub.gets], stub.gets
        finally:
            stub.close()

    def test_every_page_is_fetched_until_total_results(self):
        items, incomplete, starts, gets = self.collect(nvd_pages(5), page_size=2)
        self.assertEqual([i.title for i in items], [f"CVE-2099-{i:05d}" for i in range(5)])
        self.assertIsNone(incomplete)
        self.assertEqual(starts, [0, 2, 4])
        self.assertEqual({q["resultsPerPage"][0] for _, q, _ in gets}, {"2"})
        self.assertEqual(self.sleep.call_args_list, [mock.call(6.0), mock.call(6.0)])

    def test_more_results_than_one_api_page(self):
        """修正前は resultsPerPage=200 の1回だけで、2500件中200件を完全な収集として扱っていた。"""
        items, incomplete, starts, _ = self.collect(nvd_pages(2500))
        self.assertEqual(len(items), 2500)
        self.assertEqual(len({i.title for i in items}), 2500)
        self.assertIsNone(incomplete)
        self.assertEqual(starts, [0, 2000])

    def test_default_limit_over_2000_results_is_partial(self):
        """既定の上限(1ページ・2000件)を超えたら部分収集として記録し、完全な収集とは扱わない。"""
        items, incomplete, starts, _ = self.collect(nvd_pages(2500), default_limit=True)
        self.assertEqual(len(items), 2000)
        self.assertEqual(starts, [0])
        self.assertIn("2500件中2000件のみ取得", incomplete)
        self.assertIn("残りは未取得", incomplete)

    def test_default_limit_within_2000_results_is_complete(self):
        items, incomplete, starts, _ = self.collect(nvd_pages(2000), default_limit=True)
        self.assertEqual(len(items), 2000)
        self.assertIsNone(incomplete)
        self.assertEqual(starts, [0])

    def test_inconsistent_or_failed_pages_fail_the_source(self):
        cases = {
            "middle page HTTP 503": {2: lambda start, per: (503, "text/plain", "")},
            "middle page HTML": {2: lambda start, per: (200, "text/html", HTML_ERROR)},
            "totalResults changes": {2: lambda start, per: nvd_body(start, per, 6, ["CVE-2099-00002"])},
            "startIndex differs": {2: lambda start, per: nvd_body(3, per, 5, ["CVE-2099-00099"])},
            "empty page before the end": {2: lambda start, per: nvd_body(start, per, 5, [])},
            "duplicate across pages": {2: lambda start, per: nvd_body(start, per, 5, ["CVE-2099-00001", "CVE-2099-00002"])},
            "more than resultsPerPage": {2: lambda start, per: nvd_body(start, per, 5, ["a", "b", "c"])},
            "past totalResults": {4: lambda start, per: nvd_body(start, per, 5, ["CVE-2099-00004", "CVE-2099-00005"])},
            "totalResults not an integer": {0: lambda start, per: (200, "application/json", json.dumps(
                {"resultsPerPage": per, "startIndex": 0, "totalResults": "5", "vulnerabilities": []}))},
            "totalResults boolean": {0: lambda start, per: (200, "application/json", json.dumps(
                {"resultsPerPage": per, "startIndex": 0, "totalResults": True, "vulnerabilities": []}))},
            "totalResults float": {0: lambda start, per: (200, "application/json", json.dumps(
                {"resultsPerPage": per, "startIndex": 0, "totalResults": 5.0,
                 "vulnerabilities": [{"cve": {"id": "CVE-2099-00000"}}, {"cve": {"id": "CVE-2099-00001"}}]}))},
            "entry without cve object": {2: lambda start, per: (200, "application/json", json.dumps(
                {"resultsPerPage": per, "startIndex": start, "totalResults": 5, "vulnerabilities": [{}, {}]}))},
            "entry is not an object": {2: lambda start, per: (200, "application/json", json.dumps(
                {"resultsPerPage": per, "startIndex": start, "totalResults": 5, "vulnerabilities": [1, 2]}))},
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                items, incomplete, starts, _ = self.collect(nvd_pages(5, overrides), page_size=2, max_pages=10)
                self.assertIsNone(items)
                self.assertLessEqual(len(starts), 3)

    def test_page_limit_is_reported_as_incomplete(self):
        items, incomplete, starts, _ = self.collect(nvd_pages(10), page_size=2, max_pages=3)
        self.assertEqual(len(items), 6)
        self.assertEqual(starts, [0, 2, 4])
        self.assertIn("10件中6件", incomplete)

    def test_incomplete_state_does_not_leak_into_the_next_collection(self):
        stub = Stub(routes={"/rest": nvd_pages(10)})
        try:
            collector = NvdCollector({"id": "nvd_cve", "name": "NVD", "type": "nvd_api", "url": stub.url + "/rest",
                                      "trust_level": 1}, page_size=2, max_pages=3)
            self.assertEqual(len(collector.safe_collect()), 6)
            self.assertIsNotNone(collector.incomplete)
            collector.max_pages = 10
            self.assertEqual(len(collector.safe_collect()), 10)
            self.assertIsNone(collector.incomplete)
        finally:
            stub.close()

    def test_api_key_is_sent_and_shortens_the_page_delay(self):
        with mock.patch.dict(os.environ, {"NVD_API_KEY": "synthetic-key"}):
            items, _, _, gets = self.collect(nvd_pages(3), page_size=2)
        self.assertEqual(len(items), 3)
        self.assertEqual({h.get("apiKey") for _, _, h in gets}, {"synthetic-key"})
        self.assertEqual(self.sleep.call_args_list, [mock.call(0.6)])


class IncompleteCollector(BaseCollector):
    REASON = "ページ上限(25ページ)に達したため60000件中50000件のみ取得"

    def collect(self):
        self.incomplete = self.REASON
        return []


class TestIncompleteSourceNotification(PipelineCase):
    SOURCES = PipelineCase.SOURCES + [("src_nvd", "NVD (synthetic)", "nvd_api")]

    def test_incomplete_nvd_is_a_partial_collection(self):
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector, "src_nvd": IncompleteCollector})
        self.assertEqual(self.run_update(), 0)
        quality = json.loads(self.runs()[-1]["notes"].split(" quality=", 1)[1])
        self.assertEqual(quality["incomplete_sources"], [{"id": "src_nvd", "name": "NVD (synthetic)", "type": "nvd_api",
                                                          "reason": IncompleteCollector.REASON}])
        code, out, _ = self.notify()
        self.assertEqual(code, 0)
        self.assertIn("全件を取得できなかったソース: NVD (synthetic)(ページ上限", out)
        self.assertIn("重要ソース NVD (synthetic) は全件を取得できなかったため、CVE・CVSSの変化は一部しか確認できていません", out)
        self.assertIn("部分収集のため断定できません", out)
        self.assertNotIn("本日は重要な新規変化はありません", out)


# ---------------------------------------------------------------------------
# Codex監査 P1-5 / H3(未解決): 通知されなかった新規KEVの持ち越し
# ---------------------------------------------------------------------------

class TestH3UnnotifiedContent(PipelineCase):
    """H3は未解決。通知台帳(案A)を実装するまで、次回の通知で未通知の新規KEVが消える反例をここに固定する。

    台帳を実装したら test_known_defect_... を削除し、test_unnotified_kev_is_carried_over の
    expectedFailure を外すこと。
    """

    def two_runs_where_the_first_notification_is_lost(self):
        self.use_collectors({"src_rss": [kev_item("src_rss", "CVE-2099-0501")], "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        code, body1, _ = self.notify()
        self.assertEqual(code, 0)
        self.assertIn("新規の悪用確認済みCVE 1件", body1)
        # 1回目の通知は失敗した(ntfy failed_definite / unknown、メール失敗)。その事実はどこにも記録されない。
        self.assertEqual(self.run_update(), 0)
        code, body2, _ = self.notify()
        self.assertEqual(code, 0)
        return body2

    def test_known_defect_unnotified_kev_disappears_on_the_next_run(self):
        body2 = self.two_runs_where_the_first_notification_is_lost()
        self.assertNotIn("CVE-2099-0501", body2)
        self.assertNotIn("新規の悪用確認済みCVE", body2)
        self.assertIn("本日は重要な新規変化はありません", body2)

    @unittest.expectedFailure
    def test_unnotified_kev_is_carried_over(self):
        body2 = self.two_runs_where_the_first_notification_is_lost()
        self.assertIn("新規の悪用確認済みCVE 1件", body2)


# ---------------------------------------------------------------------------
# Codex監査 P2-1: quality JSON の厳密な型検証
# ---------------------------------------------------------------------------

class TestStrictQuality(PipelineCase):
    def test_wrong_types_and_unknown_shapes_are_unknown_quality(self):
        self.use_collectors({"src_rss": EmptyCollector, "src_kev": EmptyCollector})
        self.assertEqual(self.run_update(), 0)
        data = json.loads(notify_summary.DATA_PATH.read_text(encoding="utf-8"))
        kev = {"id": "src_kev", "name": "CISA KEV (synthetic)", "type": "kev_json"}
        nvd = {"id": "src_nvd", "name": "NVD", "type": "nvd_api", "reason": "r"}

        def q(**fields):
            return {"version": 1, "failed_sources": [], "incomplete_sources": [], "items_failed": 0, **fields}
        variants = {  # (quality JSONテキスト, sources_ok, sources_failed)
            "version true": (json.dumps(q(version=True)), 2, 0),
            "version 1.0": (json.dumps(q(version=1.0)), 2, 0),
            "items_failed true": (json.dumps(q(items_failed=True)), 2, 0),
            "items_failed 1.5": (json.dumps(q(items_failed=1.5)), 2, 0),
            "items_failed NaN": (json.dumps(q(items_failed=0)).replace('"items_failed": 0', '"items_failed": NaN'), 2, 0),
            "items_failed Infinity": (json.dumps(q()).replace('"items_failed": 0', '"items_failed": Infinity'), 2, 0),
            "unknown top-level key": (json.dumps(q(extra=1)), 2, 0),
            "incomplete_sources missing": (json.dumps({k: v for k, v in q().items() if k != "incomplete_sources"}), 2, 0),
            "failed source name is a number": (json.dumps(q(failed_sources=[{**kev, "name": 5}])), 1, 1),
            "failed source with unknown key": (json.dumps(q(failed_sources=[{**kev, "x": 1}])), 1, 1),
            "failed source id empty": (json.dumps(q(failed_sources=[{**kev, "id": ""}])), 1, 1),
            "failed source ids duplicated": (json.dumps(q(failed_sources=[kev, kev])), 1, 2),
            "incomplete source without reason": (json.dumps(q(incomplete_sources=[
                {k: v for k, v in nvd.items() if k != "reason"}])), 2, 0),
            "incomplete source reason empty": (json.dumps(q(incomplete_sources=[{**nvd, "reason": ""}])), 2, 0),
            "incomplete source also failed": (json.dumps(q(failed_sources=[{**kev, "id": "src_nvd"}],
                                                           incomplete_sources=[nvd])), 1, 1),
            "more incomplete than successful sources": (json.dumps(q(incomplete_sources=[
                nvd, {**nvd, "id": "b"}, {**nvd, "id": "c"}])), 2, 0),
            "failed_sources is an object": (json.dumps(q(failed_sources={})), 2, 0),
        }
        for label, (quality, ok, failed) in variants.items():
            with self.subTest(quality=label):
                notes = "2ソース中 quality=" + quality
                with dbmod.connection() as conn:
                    conn.execute("UPDATE run_log SET notes = ?, sources_ok = ?, sources_failed = ? WHERE id = ?",
                                 (notes, ok, failed, data["last_run"]["id"]))
                last_run = {**data["last_run"], "notes": notes, "sources_ok": ok, "sources_failed": failed}
                notify_summary.DATA_PATH.write_text(json.dumps({**data, "last_run": last_run}, ensure_ascii=False),
                                                    encoding="utf-8")
                code, out, _ = self.notify()
                self.assertEqual(code, 0)
                self.assertIn("収集品質を確認できません", out)
                self.assertNotIn("本日は重要な新規変化はありません", out)


if __name__ == "__main__":
    unittest.main()
