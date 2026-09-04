"""reporting/dashboard_export.py が docs/index.html の期待する形のJSONを
生成できることを検証する。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import RawItem
from database import db as dbmod
import update as update_mod
from reporting import dashboard_export


class TestDashboardExport(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_db_path = Path(self._tmpdir.name) / "test.db"
        dbmod.DB_PATH = self.tmp_db_path
        dbmod.init_db()

        self._orig_docs_dir = dashboard_export.DOCS_DIR
        self._orig_data_path = dashboard_export.DASHBOARD_DATA_PATH
        tmp_docs = Path(self._tmpdir.name) / "docs"
        dashboard_export.DOCS_DIR = tmp_docs
        dashboard_export.DASHBOARD_DATA_PATH = tmp_docs / "data" / "dashboard_data.json"

    def tearDown(self):
        dashboard_export.DOCS_DIR = self._orig_docs_dir
        dashboard_export.DASHBOARD_DATA_PATH = self._orig_data_path
        self._tmpdir.cleanup()

    def _seed_incident(self, run_id, **overrides):
        defaults = dict(
            source_id="jpcert_alert", source_name="JPCERT/CC", source_trust_level=1,
            title="CVE-2026-7001: 日本の医療機関を狙ったランサムウェア攻撃、実被害を確認",
            url="https://example.test/1", published_at="2026-09-05T00:00:00+00:00",
            summary="複数の病院で患者情報流出等の被害が確認された。",
            raw_text=(
                "CVE-2026-7001: 日本の医療機関を狙ったランサムウェア攻撃、実被害を確認\n"
                "複数の病院で患者情報流出等の被害が確認された。"
            ),
            extra={"cve_ids": ["CVE-2026-7001"], "in_kev": True},
        )
        defaults.update(overrides)
        item = RawItem(**defaults)
        item.source_region = "jp"
        with dbmod.connection() as conn:
            update_mod.process_item(conn, item, run_id=run_id)

    def test_export_produces_valid_json_with_expected_keys(self):
        with dbmod.connection() as conn:
            run_id = dbmod.start_run(conn)
        self._seed_incident(run_id)
        with dbmod.connection() as conn:
            dbmod.finish_run(conn, run_id, 1, 0, 1, 1, 0)

        with dbmod.connection() as conn:
            path = dashboard_export.generate_and_save(conn, run_id=run_id)

        self.assertTrue(path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))

        for key in [
            "generated_at", "last_run", "summary", "diff_since_last_run",
            "top_critical_high", "top_japan_related", "top_kev",
            "sector_counts", "vector_counts", "trend_7d", "all_incidents", "sources",
        ]:
            self.assertIn(key, data)

        self.assertEqual(data["summary"]["total_incidents"], 1)
        self.assertGreaterEqual(data["summary"]["kev_count"], 1)
        self.assertGreaterEqual(data["summary"]["japan_related_count"], 1)
        self.assertEqual(len(data["top_kev"]), 1)
        self.assertTrue(data["diff_since_last_run"]["significant_change"])

    def test_json_is_fully_serializable_and_reparsable(self):
        """dict->json->dict の往復が例外なく行えること(NaN等の混入がないこと)を確認する。"""
        with dbmod.connection() as conn:
            run_id = dbmod.start_run(conn)
        self._seed_incident(run_id)
        with dbmod.connection() as conn:
            dbmod.finish_run(conn, run_id, 1, 0, 1, 1, 0)
            data = dashboard_export.build_dashboard_data(conn, run_id=run_id)

        raw = json.dumps(data, ensure_ascii=False)
        reparsed = json.loads(raw)
        self.assertEqual(reparsed["summary"]["total_incidents"], 1)


if __name__ == "__main__":
    unittest.main()