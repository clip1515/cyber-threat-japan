"""出典が公開したIOC(config/reported_iocs.yaml → reported_iocs)の検証・同期・失敗時の扱い。

一時SQLiteと一時YAMLだけを使う。ネットワークと本番DBには触れない。
P1-1: 不正な設定で既存IOCを消さない(全件・IDを保持)。P1-2: IOC同期の失敗で日次収集を止めない。
"""
import contextlib
import io
import logging
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path
from unittest import mock

import yaml

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import BaseCollector, RawItem
from config import settings
from database import db as dbmod
from parsers.reported_ioc import DuplicateKeyError, load_document, normalize_ip, parse_document, validate_entries
from reporting import daily_report, dashboard_export
import update as update_mod

IP = "20.210.128.125"
TODAY = date(2026, 10, 24)
ENTRY = {
    "ioc_type": "ip", "ioc_value": IP, "source_url": "https://synthetic.test/advisory/1.html",
    "source_name": "Synthetic advisory", "source_kind": "official_advisory", "source_trust_level": 1,
    "source_published_at": "2026-10-01", "observed_from": "2026-09-01", "observed_to": "2026-09-30",
    "source_checked_at": "2026-10-23", "confidence": "reported", "usage": "reference", "context": "synthetic",
}
ENTRY2 = {**ENTRY, "source_url": "https://synthetic.test/advisory/2.html"}


def item_yaml(entry, extra=""):
    """1項目分のYAML。extra は項目の末尾に足す行(重複キーなど、safe_dump では作れない内容)。"""
    lines = yaml.safe_dump([entry], allow_unicode=True, sort_keys=False).splitlines()
    return "\n".join(lines) + "\n" + "".join(f"  {line}\n" for line in extra.splitlines())


VALID_YAML = "iocs:\n" + item_yaml(ENTRY) + item_yaml(ENTRY2)
# YAMLの重複キー・マージキー(safe_load は重複を黙って後の値で上書きする)。
DUPLICATE_KEY_DOCUMENTS = {
    "iocs twice, later empty list": VALID_YAML + "iocs: []\n",
    "iocs twice, later partial list": VALID_YAML + "iocs:\n" + item_yaml(ENTRY),
    "source_url twice in an item": "iocs:\n" + item_yaml(ENTRY, "source_url: https://synthetic.test/advisory/9.html")
                                   + item_yaml(ENTRY2),
    "source_name twice in an item": "iocs:\n" + item_yaml(ENTRY, "source_name: Other name") + item_yaml(ENTRY2),
    "usage twice in an item": "iocs:\n" + item_yaml(ENTRY, "usage: detection") + item_yaml(ENTRY2),
    "merge key from another item": "iocs:\n" + item_yaml(ENTRY).replace("- ioc_type:", "- &first\n  ioc_type:", 1)
                                   + item_yaml(ENTRY2, "<<: *first"),
}
MALFORMED_DOCUMENTS = {
    "empty file": "", "{}": "{}", "null": "null", "false": "false", "0": "0", "top-level list": "[]",
    "iocs without value": "iocs:\n", "iocs: null": "iocs: null", "iocs: false": "iocs: false",
    "iocs: {}": "iocs: {}", "iocs: 0": "iocs: 0", "iocs: string": "iocs: x",
    "other key only": "entries: []", "iocs plus unknown key": "iocs: []\nextra: 1",
}


def validate(entries):
    return validate_entries(entries, today=TODAY)


class TestNormalize(unittest.TestCase):
    def test_defanged_and_padded_forms_are_normalized(self):
        for value in (IP, f" {IP} ", "20[.]210[.]128[.]125"):
            with self.subTest(value=value):
                self.assertEqual(normalize_ip(value), IP)

    def test_only_global_unicast_addresses_are_accepted(self):
        """P2: is_global が真でもマルチキャスト・スコープ付き・IPv4埋め込みIPv6は受け付けない。"""
        for value in ("224.0.0.1", "239.255.255.250", "ff0e::1", "ff02::1", "2606:4700::1%eth0",
                      "::ffff:8.8.8.8", "64:ff9b::808:808"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_ip(value)
        for value, expected in ((IP, IP), ("2606:4700:4700::1111", "2606:4700:4700::1111"),
                                ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111")):
            with self.subTest(value=value):
                self.assertEqual(normalize_ip(value), expected)

    def test_non_global_invalid_and_non_string_addresses_are_rejected(self):
        for value in ("10.0.0.50", "192.168.1.1", "127.0.0.1", "203.0.113.5", "1.5.05.46", "256.1.1.1",
                      "2.2.3", "not-an-ip", "::1", "fe80::1", 337477757, None, ["20.210.128.125"]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_ip(value)


class TestStrictYaml(unittest.TestCase):
    def test_duplicate_and_merge_keys_are_rejected_at_every_level(self):
        for label, text in DUPLICATE_KEY_DOCUMENTS.items():
            with self.subTest(document=label):
                with self.assertRaises(DuplicateKeyError) as caught:
                    load_document(text)
                self.assertRegex(str(caught.exception), r"(重複したキー|マージキー).*\d+行目")
                self.assertNotIn("source_", str(caught.exception))  # キー名や値はメッセージに含めない

    def test_valid_documents_load_like_safe_load(self):
        for text in (VALID_YAML, "iocs: []\n", "iocs:\n  - source_checked_at: 2026-10-23\n"):
            with self.subTest(text=text[:30]):
                self.assertEqual(load_document(text), yaml.safe_load(text))

    def test_duplicates_never_become_a_valid_empty_list(self):
        """不正な設定が正当な空一覧(iocs: [])に変換されない。"""
        with self.assertRaises(DuplicateKeyError):
            load_document(DUPLICATE_KEY_DOCUMENTS["iocs twice, later empty list"])
        self.assertEqual(parse_document(load_document("iocs: []\n"), today=TODAY), ([], []))


class TestDocument(unittest.TestCase):
    def test_iocs_key_is_required_and_only_an_explicit_empty_list_is_empty(self):
        """P1-1: 空ファイル・{}・null・false・型違いは「登録なし」と解釈せず拒否する。"""
        for label, text in MALFORMED_DOCUMENTS.items():
            with self.subTest(document=label):
                rows, errors = parse_document(yaml.safe_load(text), today=TODAY)
                self.assertEqual(rows, [])
                self.assertEqual(len(errors), 1)
        self.assertEqual(parse_document(yaml.safe_load("iocs: []"), today=TODAY), ([], []))

    def test_repository_file_is_valid(self):
        """リポジトリに置くファイル自体がPRの段階で検証されるようにする。"""
        data = yaml.safe_load(settings.REPORTED_IOCS_YAML.read_text(encoding="utf-8"))
        self.assertEqual(parse_document(data)[1], [])


class TestValidate(unittest.TestCase):
    def test_valid_entry(self):
        rows, errors = validate([ENTRY])
        self.assertEqual(errors, [])
        self.assertEqual((rows[0]["ioc_value"], rows[0]["source_checked_at"]), (IP, "2026-10-23"))

    def test_every_field_is_type_checked(self):
        """P1-2: どの項目に辞書・一覧・数値などを書いても例外にならず、項目のエラーになる。"""
        bad_values = {"dict": {"a": 1}, "list": ["a"], "int": 1, "float": 1.5, "bool": True}
        for field in sorted(ENTRY):
            for kind, value in bad_values.items():
                if field == "source_trust_level" and kind == "int":
                    continue
                with self.subTest(field=field, value=kind):
                    rows, errors = validate([{**ENTRY, field: value}])
                    self.assertEqual(rows, [])
                    self.assertEqual(len(errors), 1)

    def test_invalid_entries_are_reported(self):
        cases = {
            "missing source_checked_at": {k: v for k, v in ENTRY.items() if k != "source_checked_at"},
            "missing source_kind": {k: v for k, v in ENTRY.items() if k != "source_kind"},
            "blocking usage": {**ENTRY, "usage": "block"},
            "attribution field": {**ENTRY, "threat_actor": "x"},
            "non-string field name": {**ENTRY, 1: "x"},
            "unknown confidence": {**ENTRY, "confidence": "confirmed_malicious"},
            "unknown source kind": {**ENTRY, "source_kind": "rumour"},
            "http source": {**ENTRY, "source_url": "http://synthetic.test/a"},
            "url with credentials": {**ENTRY, "source_url": "https://user:pw@synthetic.test/a"},
            "url without host": {**ENTRY, "source_url": "https:///a"},
            "url with space": {**ENTRY, "source_url": "https://synthetic.test/a b"},
            "url with bad port": {**ENTRY, "source_url": "https://synthetic.test:99999/a"},
            "url too long": {**ENTRY, "source_url": "https://synthetic.test/" + "a" * 2100},
            "empty source_name": {**ENTRY, "source_name": "  "},
            "source_name too long": {**ENTRY, "source_name": "a" * 201},
            "context too long": {**ENTRY, "context": "a" * 501},
            "newline in context": {**ENTRY, "context": "a\nb"},
            "line separator in source_name": {**ENTRY, "source_name": "a\u2028b"},
            "trust level as string": {**ENTRY, "source_trust_level": "1"},
            "trust level out of range": {**ENTRY, "source_trust_level": 4},
            "nonexistent date": {**ENTRY, "source_checked_at": "2026-02-30"},
            "basic-format date": {**ENTRY, "source_checked_at": "20261023"},
            "datetime value": {**ENTRY, "source_checked_at": datetime(2026, 10, 23, 1, 2)},
            "future date": {**ENTRY, "source_checked_at": "2026-12-31"},
            "date before 2000": {**ENTRY, "observed_from": "1999-12-31"},
            "observed range reversed": {**ENTRY, "observed_from": "2026-10-01", "observed_to": "2026-09-01"},
            "private address": {**ENTRY, "ioc_value": "10.0.0.50"},
            "unsupported type": {**ENTRY, "ioc_type": "domain"},
            "not a dict": "x",
        }
        for label, entry in cases.items():
            with self.subTest(case=label):
                rows, errors = validate([entry])
                self.assertEqual(rows, [])
                self.assertEqual(len(errors), 1)

    def test_error_text_does_not_echo_input_values(self):
        for entry in ({**ENTRY, "ioc_type": "ip\n::error::spoof", "context": "SECRET-LIKE\nvalue"},
                      {**ENTRY, "ioc_value": "spoof-not-an-ip"}, {**ENTRY, "source_url": "https://spoof host/"},
                      {**ENTRY, "source_checked_at": "spoof-date"}, {**ENTRY, "confidence": "spoof"}):
            with self.subTest(entry=sorted(set(entry.items()) - set(ENTRY.items()))):
                rows, errors = validate([entry])
                self.assertEqual(len(errors), 1)
                self.assertNotIn("spoof", errors[0])
                self.assertNotIn("SECRET-LIKE", errors[0])
                self.assertNotIn("\n", errors[0])

    def test_yaml_dates_are_accepted(self):
        loaded = yaml.safe_load("iocs:\n  - source_checked_at: 2026-10-23\n")["iocs"][0]
        rows, errors = validate([{**ENTRY, **loaded}])
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["source_checked_at"], "2026-10-23")

    def test_same_ioc_same_source_is_a_duplicate_even_if_written_differently(self):
        rows, errors = validate([ENTRY, {**ENTRY, "ioc_value": "20[.]210[.]128[.]125"}])
        self.assertEqual(len(errors), 1)

    def test_external_observation_keeps_its_own_period_and_check_date(self):
        observed = {**ENTRY, "source_url": "https://observer.synthetic.test/ip/1", "source_name": "Synthetic observer",
                    "source_kind": "external_observation", "source_trust_level": 3,
                    "observed_from": "2026-10-10", "observed_to": "2026-10-20", "source_checked_at": "2026-10-22"}
        rows, errors = validate([ENTRY, observed])
        self.assertEqual(errors, [])
        by_kind = {r["source_kind"]: r for r in rows}
        self.assertEqual((by_kind["official_advisory"]["observed_from"], by_kind["official_advisory"]["source_checked_at"]),
                         ("2026-09-01", "2026-10-23"))
        self.assertEqual((by_kind["external_observation"]["observed_from"],
                          by_kind["external_observation"]["source_checked_at"]), ("2026-10-10", "2026-10-22"))


class SyncCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = self.tmp = Path(self._tmp.name)
        self.yaml_path = tmp / "reported_iocs.yaml"
        (tmp / "sources.yaml").write_text(yaml.safe_dump({"sources": [
            {"id": "src", "name": "Synthetic", "type": "rss", "url": "https://src.synthetic.test/feed",
             "trust_level": 1, "lang": "en", "region": "global"}]}), encoding="utf-8")
        patches = [(dbmod, "DB_PATH", tmp / "test.db"), (dbmod, "REPORTED_IOCS_YAML", self.yaml_path),
                   (dbmod, "SOURCES_YAML", tmp / "sources.yaml")]
        for obj, name, value in patches:
            p = mock.patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)

    def write(self, entries):
        self.yaml_path.write_text(yaml.safe_dump({"iocs": entries}, allow_unicode=True), encoding="utf-8")

    def rows(self):
        with dbmod.connection() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM reported_iocs ORDER BY id")]

    def seed(self):
        self.write([ENTRY, ENTRY2])
        dbmod.init_db()
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        return rows

    def init_db_capturing(self, actions=True):
        """init_db を実行し、(stdout, ログ) を返す。例外が出ればテストは失敗する。"""
        out = io.StringIO()
        environ = {"GITHUB_ACTIONS": "true"} if actions else {}
        with mock.patch.dict(os.environ, environ), contextlib.redirect_stdout(out):
            with self.assertLogs("db", level="ERROR") as logs:
                dbmod.init_db()
        return out.getvalue(), "\n".join(logs.output)

    def assert_warned_and_kept(self, before, stdout, log, reason=None):
        self.assertEqual(self.rows(), before)  # 全件・全項目・ID が変わらない
        self.assertTrue(stdout.startswith("::warning title=IOC同期失敗 (reported_iocs)::"))
        self.assertEqual(stdout.count("\n"), 1)
        self.assertIn("前回の内容を維持しました", stdout)
        self.assertIn("IOC同期失敗", log)
        if reason:  # 失敗の原因が警告から分かること(汎用の「予期しないエラー」にならないこと)
            self.assertIn(reason, stdout)


class TestSync(SyncCase):
    def test_sync_stores_all_provenance_fields(self):
        self.write([{**ENTRY, "ioc_value": "20[.]210[.]128[.]125"}])
        dbmod.init_db()
        row, = self.rows()
        self.assertEqual({k: row[k] for k in ENTRY}, ENTRY)

    def test_resync_keeps_ids_updates_in_place_and_removes_only_dropped_entries(self):
        before = self.seed()
        dbmod.init_db()
        self.assertEqual(self.rows(), before)
        self.write([{**ENTRY, "context": "updated"}])
        dbmod.init_db()
        row, = self.rows()
        self.assertEqual((row["id"], row["context"]), (before[0]["id"], "updated"))

    def test_explicit_empty_list_clears_the_table(self):
        self.seed()
        self.yaml_path.write_text("iocs: []\n", encoding="utf-8")
        dbmod.init_db()
        self.assertEqual(self.rows(), [])

    def test_malformed_documents_keep_every_row_and_id(self):
        """P1-1: 空ファイル・{}・null・false・型違いでも既存IOCの全データとIDを保持し、警告する。"""
        before = self.seed()
        for label, text in MALFORMED_DOCUMENTS.items():
            with self.subTest(document=label):
                self.yaml_path.write_text(text, encoding="utf-8")
                self.assert_warned_and_kept(before, *self.init_db_capturing())

    def test_duplicate_keys_keep_every_row_id_and_attribute(self):
        """P1(v3): iocs やIOC項目内の重複キーで同期せず、既存IOCの行数・値・属性・IDを完全に保持する。"""
        before = self.seed()
        for label, text in DUPLICATE_KEY_DOCUMENTS.items():
            with self.subTest(document=label):
                self.yaml_path.write_text(text, encoding="utf-8")
                reason = "マージキー" if "merge" in label else "重複したキーがあります"
                self.assert_warned_and_kept(before, *self.init_db_capturing(), reason=reason)

    def test_valid_file_still_syncs_after_a_duplicate_key_failure(self):
        before = self.seed()
        self.yaml_path.write_text(DUPLICATE_KEY_DOCUMENTS["iocs twice, later empty list"], encoding="utf-8")
        self.init_db_capturing()
        self.yaml_path.write_text("iocs:\n" + item_yaml({**ENTRY, "context": "updated"}) + item_yaml(ENTRY2),
                                  encoding="utf-8")
        dbmod.init_db()
        after = self.rows()
        self.assertEqual([r["id"] for r in after], [r["id"] for r in before])
        self.assertEqual(after[0]["context"], "updated")

    def test_one_bad_entry_blocks_the_whole_update(self):
        """削除・置換の前に全件を検証する。正しい項目だけが部分的に反映されることもない。"""
        before = self.seed()
        self.write([{**ENTRY, "context": "would change"}, {**ENTRY2, "usage": "block"}])
        self.assert_warned_and_kept(before, *self.init_db_capturing())

    def test_bad_field_types_do_not_raise(self):
        """P1-2: context・source_name などの型違いで init_db が例外を出さない。"""
        before = self.seed()
        for field in ("context", "source_name", "source_url", "ioc_value", "ioc_type", "usage", "source_kind"):
            for value in ({"a": 1}, ["a"]):
                with self.subTest(field=field, value=type(value).__name__):
                    self.write([{**ENTRY, field: value}, ENTRY2])
                    self.assert_warned_and_kept(before, *self.init_db_capturing())

    def test_read_and_parse_failures_do_not_raise(self):
        before = self.seed()
        real_read_text = Path.read_text

        def denied(path, *args, **kwargs):
            if path == self.yaml_path:
                raise PermissionError(13, "Permission denied")
            return real_read_text(path, *args, **kwargs)
        with self.subTest(case="PermissionError"):
            with mock.patch.object(Path, "read_text", denied):
                self.assert_warned_and_kept(before, *self.init_db_capturing(), reason="読めません(PermissionError)")
        with self.subTest(case="invalid UTF-8"):
            self.yaml_path.write_bytes(b"iocs:\n  - ioc_value: \xff\xfe\n")
            self.assert_warned_and_kept(before, *self.init_db_capturing(), reason="読めません(UnicodeDecodeError)")
        with self.subTest(case="unreadable YAML"):
            self.yaml_path.write_text("iocs: [", encoding="utf-8")
            self.assert_warned_and_kept(before, *self.init_db_capturing(), reason="YAMLとして読めません")
        with self.subTest(case="missing file"):
            self.yaml_path.unlink()
            self.assert_warned_and_kept(before, *self.init_db_capturing(), reason="がありません")

    def failing_connection(self, fail_on):
        real = dbmod.get_connection

        class Failing:
            def __init__(self, conn):
                self._conn = conn

            def _check(self, sql):
                if fail_on in sql and "reported_iocs" in sql:
                    raise sqlite3.OperationalError("database is locked (synthetic)")

            def execute(self, sql, *args):
                self._check(sql)
                return self._conn.execute(sql, *args)

            def executemany(self, sql, *args):
                self._check(sql)
                return self._conn.executemany(sql, *args)

            def __getattr__(self, name):
                return getattr(self._conn, name)
        return mock.patch.object(dbmod, "get_connection", lambda: Failing(real()))

    def test_sqlite_write_failure_rolls_back_and_does_not_raise(self):
        """P1-2: 書き込みの途中(更新後の削除)で失敗しても、更新分も含めて取り消される。"""
        before = self.seed()
        self.write([{**ENTRY, "context": "would change"}])  # ENTRY を更新し ENTRY2 を削除する変更
        for step in ("INSERT", "DELETE"):
            with self.subTest(failing_step=step):
                with self.failing_connection(step):
                    self.assert_warned_and_kept(before, *self.init_db_capturing(),
                                                reason="反映に失敗しました(OperationalError)")

    def test_unexpected_error_is_contained(self):
        before = self.seed()
        with mock.patch("parsers.reported_ioc.parse_document", side_effect=RuntimeError("synthetic bug")):
            self.assert_warned_and_kept(before, *self.init_db_capturing(), reason="予期しないエラー")

    def test_table_constraints_back_up_the_validator(self):
        dbmod.init_db()
        base = {"ioc_type": "ip", "ioc_value": IP, "source_url": "https://synthetic.test/x", "source_name": "s",
                "source_kind": "official_advisory", "source_trust_level": 1, "source_checked_at": "2026-10-23",
                "confidence": "reported", "usage": "reference"}
        # 型は検証しない(SQLiteの型親和性で変換される)。型の保証は validator 側にある。
        for label, override in (("blocking usage", {"usage": "block"}), ("http url", {"source_url": "http://x"}),
                                ("trust out of range", {"source_trust_level": 4}), ("missing name", {"source_name": None}),
                                ("bad date", {"source_checked_at": "2026/10/23"})):
            with self.subTest(case=label):
                row = {**base, **override}
                with dbmod.connection() as conn:
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute(f"INSERT INTO reported_iocs ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                                     list(row.values()))


class TestWarnings(SyncCase):
    def test_no_annotation_on_success_or_outside_actions(self):
        self.write([ENTRY])
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), contextlib.redirect_stdout(out):
            dbmod.init_db()
        self.assertEqual(out.getvalue(), "")
        self.yaml_path.write_text("", encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
        with mock.patch.dict(os.environ, env, clear=True):
            stdout, log = self.init_db_capturing(actions=False)
        self.assertEqual(stdout, "")
        self.assertIn("IOC同期失敗", log)

    def test_newlines_cannot_inject_workflow_commands_on_stdout_or_stderr(self):
        """P2-1: 値や理由文に改行が入っても、`::` で始まる行は自分の警告1行だけになる。"""
        self.seed()
        self.write([{**ENTRY, "ioc_type": "ip\n::error title=spoofed::x"}, {**ENTRY2, "source_name": "a\r\n::error::y"}])
        stderr = io.StringIO()
        handler = logging.StreamHandler(stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger("db").addHandler(handler)
        self.addCleanup(logging.getLogger("db").removeHandler, handler)
        stdout, _ = self.init_db_capturing()
        lines = [ln for ln in (stdout + stderr.getvalue()).splitlines() if ln.startswith("::")]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("::warning title=IOC同期失敗 (reported_iocs)::"))
        self.assertNotIn("spoofed", stdout + stderr.getvalue())

    def test_direct_warning_text_is_made_single_line_and_escaped(self):
        out, err = io.StringIO(), io.StringIO()
        handler = logging.StreamHandler(err)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger("db").addHandler(handler)
        self.addCleanup(logging.getLogger("db").removeHandler, handler)
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), contextlib.redirect_stdout(out):
            dbmod._warn_reported_iocs("100% bad\n::error::x\u2028y")
        self.assertEqual(out.getvalue(), "::warning title=IOC同期失敗 (reported_iocs)::100%25 bad\\x0a::error::x\\x2028y\n")
        self.assertEqual(err.getvalue().count("\n"), 1)
        self.assertFalse(err.getvalue().startswith("::"))


class TestDailyRunContinues(SyncCase):
    """P1-2: update.main() 相当の実行で、IOC同期だけが失敗しても collector が実行され、runが完了する。"""

    def setUp(self):
        super().setUp()
        tmp = self.tmp
        for obj, name, value in ((update_mod, "SOURCES_YAML", tmp / "sources.yaml"), (update_mod, "LOG_DIR", tmp / "logs"),
                                 (daily_report, "REPORTS_DIR", tmp / "reports"),
                                 (daily_report, "DAILY_REPORT_PATH", tmp / "daily_report.md"),
                                 (settings, "DAILY_REPORT_PATH", tmp / "daily_report.md"),
                                 (dashboard_export, "DASHBOARD_DATA_PATH", tmp / "dashboard_data.json"),
                                 (sys, "argv", ["update.py"])):
            p = mock.patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(lambda: [h.close() or logging.getLogger().removeHandler(h)
                                 for h in list(logging.getLogger().handlers)])

    def test_collector_runs_when_only_the_ioc_sync_fails(self):
        for label, content in (("invalid context type", yaml.safe_dump({"iocs": [{**ENTRY, "context": {"a": 1}}]})),
                               ("empty file", ""),
                               ("duplicate iocs key", DUPLICATE_KEY_DOCUMENTS["iocs twice, later empty list"])):
            with self.subTest(case=label):
                before = self.seed()
                self.yaml_path.write_text(content, encoding="utf-8")
                ran = []

                class Recording(BaseCollector):
                    def collect(self_inner):
                        ran.append(self_inner.source_id)
                        return [RawItem(source_id="src", source_name="Synthetic", source_trust_level=1,
                                        title="synthetic item", url=f"https://src.synthetic.test/{label}",
                                        summary="synthetic", raw_text="synthetic")]
                out = io.StringIO()
                with mock.patch.object(update_mod, "build_collector", lambda conf: Recording(conf)), \
                        mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), contextlib.redirect_stdout(out), \
                        contextlib.redirect_stderr(io.StringIO()):
                    result = update_mod.main()
                self.assertIn(result, (None, 0))  # main は戻り値なし、PR #14 適用後は 0
                self.assertEqual(ran, ["src"])
                with dbmod.connection() as conn:
                    last = conn.execute("SELECT finished_at, sources_ok FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
                self.assertIsNotNone(last["finished_at"])
                self.assertEqual(last["sources_ok"], 1)
                self.assertEqual(self.rows(), before)
                self.assertIn("::warning title=IOC同期失敗 (reported_iocs)::", out.getvalue())


if __name__ == "__main__":
    unittest.main()
