"""reporting/daily_report.py の集計・Markdown生成ロジックを検証する。"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import RawItem
from database import db as dbmod
import update as update_mod
from reporting.daily_report import build_report_data, build_report_markdown


class TestDailyReport(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_db_path = Path(self._tmpdir.name) / "test.db"
        dbmod.DB_PATH = self.tmp_db_path
        dbmod.init_db()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _run_with_items(self, items):
        with dbmod.connection() as conn:
            run_id = dbmod.start_run(conn)
        for item in items:
            with dbmod.connection() as conn:
                update_mod.process_item(conn, item, run_id=run_id)
        with dbmod.connection() as conn:
            dbmod.finish_run(conn, run_id, sources_ok=1, sources_failed=0,
                              items_fetched=len(items), items_new=len(items), items_updated=0)
            run_meta = dict(conn.execute("SELECT * FROM run_log WHERE id=?", (run_id,)).fetchone())
        return run_id, run_meta

    def test_no_significant_change_when_nothing_notable(self):
        item = RawItem(
            source_id="scan_netsecurity", source_name="ScanNetSecurity", source_trust_level=3,
            title="General IT news with no security relevance",
            url="https://example.test/none", published_at="2026-09-05T00:00:00+00:00",
            summary="Nothing notable here.",
            raw_text="General IT news with no security relevance\nNothing notable here.",
            extra={},
        )
        item.source_region = "global"
        run_id, run_meta = self._run_with_items([item])

        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id)
            markdown = build_report_markdown(conn, run_id, run_meta)

        self.assertFalse(data["significant_change"])
        self.assertIn("重要な新規変化はありません", markdown)

    def test_significant_change_detected_and_categorized(self):
        item = RawItem(
            source_id="jpcert_alert", source_name="JPCERT/CC", source_trust_level=1,
            title="CVE-2026-9001: 日本の自治体を狙ったランサムウェア攻撃、実被害を確認",
            url="https://example.test/1", published_at="2026-09-05T00:00:00+00:00",
            summary="複数の自治体で個人情報流出等の被害が確認された。FortiGate製品の脆弱性が悪用された。",
            raw_text=(
                "CVE-2026-9001: 日本の自治体を狙ったランサムウェア攻撃、実被害を確認\n"
                "複数の自治体で個人情報流出等の被害が確認された。FortiGate製品の脆弱性が悪用された。"
            ),
            extra={"cve_ids": ["CVE-2026-9001"], "in_kev": True},
        )
        item.source_region = "jp"
        run_id, run_meta = self._run_with_items([item])

        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id)
            markdown = build_report_markdown(conn, run_id, run_meta)

        self.assertTrue(data["significant_change"])
        self.assertEqual(len(data["new_incidents"]), 1)
        self.assertEqual(len(data["critical_high"]), 1)
        self.assertEqual(len(data["kev_items"]), 1)
        self.assertEqual(len(data["ransomware_items"]), 1)
        self.assertEqual(len(data["japan_victims"]), 1)
        self.assertIn("重要な変化を検出しました", markdown)
        self.assertIn("CVE-2026-9001", markdown)

    def test_escalation_appears_in_next_run_report(self):
        base_kwargs = dict(
            source_id="cisa_advisories", source_name="CISA", source_trust_level=1,
            url="https://example.test/2", published_at="2026-09-05T00:00:00+00:00",
        )
        first = RawItem(
            title="CVE-2026-4321 initial low-severity report", summary="minor issue",
            raw_text="CVE-2026-4321 initial low-severity report\nminor issue",
            extra={"cve_ids": ["CVE-2026-4321"]}, **base_kwargs,
        )
        first.source_region = "global"
        self._run_with_items([first])

        second = RawItem(
            title="CVE-2026-4321 now confirmed critical, exploited in the wild", summary="critical update",
            raw_text="CVE-2026-4321 now confirmed critical, exploited in the wild\ncritical update",
            extra={"cve_ids": ["CVE-2026-4321"], "cvss": 9.8}, **base_kwargs,
        )
        second.source_region = "global"
        run_id2, run_meta2 = self._run_with_items([second])

        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id2)
            markdown = build_report_markdown(conn, run_id2, run_meta2)

        self.assertEqual(len(data["escalated"]), 1)
        self.assertIn("CVE-2026-4321", markdown)
        self.assertIn("ESCALATED", markdown)


if __name__ == "__main__":
    unittest.main()