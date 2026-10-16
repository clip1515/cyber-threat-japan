"""2026-10監査 第2ラウンドで追加したテスト。

ユーザーからの追加検証依頼に基づき、以下を検証する:
  - 正常取得0件 と API取得失敗 の区別(①③)
  - 全ソース取得失敗時にパイプラインが完走すること(①)
  - KEV全件再同期が significant_change にならないこと(②, 第1ラウンドの再確認)
  - 既存CVEの新規KEV登録が検出されること(②)
  - severityの不正な後退が起きないこと、かつ公式の訂正(上昇・下降とも)は
    反映されること(③)
  - 同一CVEの複数ソース統合(既存機能の再確認)
  - レポート生成失敗時の安全網(_write_report_failure_notice)が機能すること
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import BaseCollector, RawItem
from database import db as dbmod
import update as update_mod
from reporting.daily_report import build_report_data


def _kev_item(cve_id="CVE-2020-9999", cvss=None):
    extra = {"cve_ids": [cve_id], "in_kev": True, "kev_date_added": "2020-01-01"}
    if cvss is not None:
        extra["cvss"] = cvss
    return RawItem(
        source_id="cisa_kev", source_name="CISA KEV", source_trust_level=1,
        title=f"[KEV] {cve_id}: Example vulnerability",
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published_at="2020-01-01T00:00:00+00:00",
        summary="Example vulnerability.",
        raw_text=f"[KEV] {cve_id}: Example vulnerability\nExample vulnerability.",
        extra=extra,
    )


def _nvd_item(cve_id="CVE-2020-9999", cvss=5.0, trust_level=1, source_id="nvd_cve", source_name="NVD CVE API 2.0"):
    return RawItem(
        source_id=source_id, source_name=source_name, source_trust_level=trust_level,
        title=cve_id,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published_at="2020-01-01T00:00:00+00:00",
        summary="NVD description.",
        raw_text=f"{cve_id}\nNVD description.",
        extra={"cve_ids": [cve_id], "cvss": cvss},
    )


class DbTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DB_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.init_db()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _run(self, items, run_id=None):
        if run_id is None:
            with dbmod.connection() as conn:
                run_id = dbmod.start_run(conn)
        for item in items:
            with dbmod.connection() as conn:
                update_mod.process_item(conn, item, run_id=run_id)
        return run_id


# ---------------------------------------------------------------------------
# ① 正常0件 / 取得失敗 / 全ソース失敗
# ---------------------------------------------------------------------------

class TestCollectorFailureVsEmpty(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        dbmod.DB_PATH = tmp / "test.db"
        self.tmp_sources_yaml = tmp / "sources.yaml"
        self._logger_patch = mock.patch("update.logging.getLogger")
        self.tearDown_targets = []

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_legitimate_empty_result_is_not_counted_as_failure(self):
        """フィード取得は成功したが0件(例外なし)の場合、sources_failedに数えない。"""
        class EmptyOkCollector(BaseCollector):
            def collect(self):
                return []

        with mock.patch("update.build_collector", return_value=EmptyOkCollector({"id": "x", "name": "X", "trust_level": 1, "url": "https://x.test"})):
            items, failed, error_detail = update_mod.safe_collect_from_source(
                {"id": "x", "name": "X", "trust_level": 1, "url": "https://x.test"}, logger=mock.Mock()
            )
        self.assertEqual(items, [])
        self.assertFalse(failed, "正当な0件はfailedとして扱われるべきではない")
        self.assertIsNone(error_detail)

    def test_fetch_exception_is_counted_as_failure_with_detail(self):
        """例外(ネットワークエラー等)が起きた場合はfailed=Trueかつ診断情報を持つ。"""
        class BrokenCollector(BaseCollector):
            def collect(self):
                raise ConnectionError("simulated DNS failure")

        with mock.patch("update.build_collector", return_value=BrokenCollector({"id": "y", "name": "Y", "trust_level": 1, "url": "https://y.test"})):
            items, failed, error_detail = update_mod.safe_collect_from_source(
                {"id": "y", "name": "Y", "trust_level": 1, "url": "https://y.test"}, logger=mock.Mock()
            )
        self.assertEqual(items, [])
        self.assertTrue(failed)
        self.assertEqual(error_detail["type"], "ConnectionError")
        self.assertIn("DNS", error_detail["message"])

    def test_all_sources_failing_completes_without_crashing(self):
        """17ソースすべてが失敗しても、パイプライン全体は例外なく完走する。"""
        import yaml
        self.tmp_sources_yaml.write_text(
            yaml.safe_dump({"sources": [
                {"id": f"broken_{i}", "name": f"Broken {i}", "type": "rss",
                 "url": f"https://broken{i}.test/feed", "trust_level": 2, "lang": "en", "region": "global"}
                for i in range(5)
            ]}),
            encoding="utf-8",
        )
        update_mod.SOURCES_YAML = self.tmp_sources_yaml
        update_mod.LOG_DIR = Path(self._tmpdir.name) / "logs"

        def always_fail(source_conf):
            raise RuntimeError("simulated total outage")

        orig_build_collector = update_mod.build_collector
        update_mod.build_collector = always_fail
        try:
            dbmod.init_db()
            sys.argv = ["update.py", "--no-report"]
            update_mod.main()  # 例外を投げずに完走することが主な検証ポイント
            with dbmod.connection() as conn:
                run = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
                health = dbmod.get_all_source_health(conn)
            self.assertEqual(run["sources_ok"], 0)
            self.assertEqual(run["sources_failed"], 5)
            self.assertEqual(len(health), 5)
            self.assertTrue(all(h["consecutive_failures"] >= 1 for h in health))
        finally:
            update_mod.build_collector = orig_build_collector


# ---------------------------------------------------------------------------
# ② KEV変更検出(全件再同期との区別)
# ---------------------------------------------------------------------------

class TestKevChangeDetection(DbTestCase):
    def test_full_catalog_resync_produces_no_change_events(self):
        """新規事案も無く、値も何も変わらない日次再同期では kev_changes が空であること。"""
        self._run([_kev_item("CVE-2020-3333")])
        run_id2 = self._run([_kev_item("CVE-2020-3333")])  # 完全に同じ内容を再同期
        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id2)
        self.assertEqual(data["kev_changes"], [])
        self.assertFalse(data["significant_change"])

    def test_existing_cve_newly_added_to_kev_is_detected_and_significant(self):
        """既にNVD経由等で把握済みのCVEが、翌日KEVに新規掲載された場合を検出する。"""
        self._run([_nvd_item("CVE-2020-4444", cvss=5.0)])  # Day1: KEV未掲載、severityはMedium程度
        with dbmod.connection() as conn:
            before = dbmod.find_incident_by_dedup_key(
                conn, __import__("parsers.normalizer", fromlist=["make_dedup_key"]).make_dedup_key(["CVE-2020-4444"], "")
            )
        self.assertEqual(before["in_kev"], 0)

        run_id2 = self._run([_kev_item("CVE-2020-4444")])  # Day2: CISAがKEVに新規掲載
        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id2)

        self.assertEqual(len(data["newly_kev_listed"]), 1)
        self.assertTrue(
            data["significant_change"],
            "既存CVEの新規KEV登録は重要な変化として検出されるべき",
        )

    def test_ransomware_use_newly_confirmed_is_detected(self):
        """CISAがknownRansomwareCampaignUseを Unknown→Known に更新した場合を検出する。"""
        item1 = _kev_item("CVE-2020-5555")
        item1.extra["known_ransomware_use"] = "Unknown"
        self._run([item1])

        item2 = _kev_item("CVE-2020-5555")
        item2.extra["known_ransomware_use"] = "Known"
        run_id2 = self._run([item2])

        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id2)
        self.assertEqual(len(data["ransomware_confirmed"]), 1)
        self.assertTrue(data["significant_change"])

    def test_kev_due_date_change_is_detected(self):
        """CISAが対応期限(dueDate)を変更した場合を検出する。"""
        item1 = _kev_item("CVE-2020-6666")
        item1.extra["due_date"] = "2026-11-01"
        self._run([item1])

        item2 = _kev_item("CVE-2020-6666")
        item2.extra["due_date"] = "2026-10-20"  # 前倒しされた
        run_id2 = self._run([item2])

        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id2)
        self.assertEqual(len(data["kev_due_date_changes"]), 1)
        self.assertTrue(data["significant_change"])


# ---------------------------------------------------------------------------
# ③ severityの整合性(後退防止 + 正規の訂正の反映)
# ---------------------------------------------------------------------------

class TestSeverityIntegrity(DbTestCase):
    def test_lower_trust_source_cannot_override_known_cvss(self):
        """信頼度の低いソース(trust_level=3)が異なる(低い)CVSSを出しても、
        既に分かっている高信頼ソース(trust_level=1)のCVSSを後退させない。"""
        self._run([_nvd_item("CVE-2020-7777", cvss=9.8, trust_level=1)])
        low_trust_item = _nvd_item(
            "CVE-2020-7777", cvss=2.0, trust_level=3,
            source_id="scan_netsecurity", source_name="ScanNetSecurity",
        )
        self._run([low_trust_item])

        with dbmod.connection() as conn:
            row = dbmod.find_incident_by_dedup_key(
                conn, __import__("parsers.normalizer", fromlist=["make_dedup_key"]).make_dedup_key(["CVE-2020-7777"], "")
            )
        self.assertEqual(row["cvss"], 9.8, "信頼度の低いソースによる値でCVSSが後退してはならない")

    def test_official_source_can_correct_cvss_downward(self):
        """同等以上に信頼できるソース(NVD自身)がCVSSを訂正(下方)した場合は反映する。"""
        self._run([_nvd_item("CVE-2020-8888", cvss=9.8, trust_level=1)])
        run_id2 = self._run([_nvd_item("CVE-2020-8888", cvss=6.5, trust_level=1)])  # NVD自身の再評価

        with dbmod.connection() as conn:
            row = dbmod.find_incident_by_dedup_key(
                conn, __import__("parsers.normalizer", fromlist=["make_dedup_key"]).make_dedup_key(["CVE-2020-8888"], "")
            )
            data = build_report_data(conn, run_id2)
        self.assertEqual(row["cvss"], 6.5, "同等以上に信頼できるソース自身による訂正は反映されるべき")
        self.assertEqual(len(data["cvss_corrected_down"]), 1)
        self.assertFalse(
            data["significant_change"],
            "下方訂正は良いニュースであり、それ単体でsignificantにする必要は無い",
        )

    def test_official_source_can_correct_cvss_upward(self):
        """同等以上に信頼できるソースがCVSSを訂正(上方)した場合は反映し、重要な変化として扱う。"""
        self._run([_nvd_item("CVE-2020-9000", cvss=4.0, trust_level=1)])
        run_id2 = self._run([_nvd_item("CVE-2020-9000", cvss=9.1, trust_level=1)])

        with dbmod.connection() as conn:
            row = dbmod.find_incident_by_dedup_key(
                conn, __import__("parsers.normalizer", fromlist=["make_dedup_key"]).make_dedup_key(["CVE-2020-9000"], "")
            )
            data = build_report_data(conn, run_id2)
        self.assertEqual(row["cvss"], 9.1)
        self.assertEqual(len(data["cvss_corrected_up"]), 1)
        self.assertTrue(data["significant_change"])

    def test_same_cve_from_multiple_sources_in_one_run_keeps_highest_known_severity(self):
        """同一CVEが同一run内で複数ソース(KEV + 情報不足な別ソース)から届いても、
        既知の重要度(High、KEV掲載)より下がらないこと(フラッピング再防止の実データ確認)。"""
        self._run([_kev_item("CVE-2020-1234")])  # Day1: KEV掲載、High
        run_id2 = self._run([
            RawItem(
                source_id="scan_netsecurity", source_name="ScanNetSecurity", source_trust_level=3,
                title="CVE-2020-1234に関する解説記事", url="https://example.test/article",
                published_at="2020-01-02T00:00:00+00:00", summary="CVE-2020-1234について解説。",
                raw_text="CVE-2020-1234に関する解説記事\nCVE-2020-1234について解説。", extra={},
            ),
            _kev_item("CVE-2020-1234"),
        ])
        with dbmod.connection() as conn:
            row = dbmod.find_incident_by_dedup_key(
                conn, __import__("parsers.normalizer", fromlist=["make_dedup_key"]).make_dedup_key(["CVE-2020-1234"], "")
            )
            escalated_this_run = conn.execute(
                "SELECT COUNT(*) c FROM status_history WHERE run_id=? AND new_status='ESCALATED'", (run_id2,)
            ).fetchone()["c"]
        self.assertEqual(row["severity"], "High")
        self.assertEqual(escalated_this_run, 0, "実際には何も変化していないのにESCALATEDが記録されてはならない")


# ---------------------------------------------------------------------------
# レポート生成失敗時の安全網(既存の_write_report_failure_noticeの動作確認)
# ---------------------------------------------------------------------------

class TestReportFailureSafetyNet(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DB_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.init_db()
        self._report_path = Path(self._tmpdir.name) / "daily_report.md"
        self._patch = mock.patch("config.settings.DAILY_REPORT_PATH", self._report_path)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._tmpdir.cleanup()

    def test_report_generation_exception_leaves_explicit_failure_notice(self):
        with dbmod.connection() as conn:
            run_id = dbmod.start_run(conn)
            dbmod.finish_run(conn, run_id, 1, 0, 0, 0, 0, notes="test")

        with mock.patch(
            "reporting.daily_report.generate_and_save",
            side_effect=TypeError("simulated unknown bug: unhashable type"),
        ):
            with dbmod.connection() as conn:
                run_meta = dict(conn.execute("SELECT * FROM run_log WHERE id=?", (run_id,)).fetchone())
            try:
                from reporting.daily_report import generate_and_save
                with dbmod.connection() as conn:
                    generate_and_save(conn, run_id, run_meta)
            except TypeError as e:
                update_mod._write_report_failure_notice(run_id, e)

        self.assertTrue(self._report_path.exists())
        content = self._report_path.read_text(encoding="utf-8")
        self.assertIn("エラーが発生したため", content)
        self.assertIn("simulated unknown bug", content)


if __name__ == "__main__":
    unittest.main()
