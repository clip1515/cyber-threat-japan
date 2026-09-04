"""パイプライン全体(process_item)の統合テスト。

外部ネットワーク(feedparser等)には依存せず、collector出力を模した
RawItemを直接 update.process_item に渡し、SQLiteへの保存・重複統合・
ステータス遷移までを検証する。一時DBファイルを使い、実データベースには触れない。
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import RawItem
from database import db as dbmod
import update as update_mod


class TestPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_db_path = Path(self._tmpdir.name) / "test.db"
        dbmod.DB_PATH = self.tmp_db_path
        dbmod.init_db()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _make_item(self, title, summary, source_id="jpcert_alert", source_name="JPCERT/CC",
                    trust_level=1, region="jp", cve_ids=None, in_kev=False):
        item = RawItem(
            source_id=source_id,
            source_name=source_name,
            source_trust_level=trust_level,
            title=title,
            url=f"https://example.test/{hash(title)}",
            published_at="2026-09-01T00:00:00+00:00",
            summary=summary,
            raw_text=f"{title}\n{summary}",
            extra={"cve_ids": cve_ids or [], "in_kev": in_kev},
        )
        item.source_region = region
        return item

    def test_new_incident_is_created_with_new_status(self):
        item = self._make_item(
            title="CVE-2026-0001: FortiGate製品の重大な脆弱性",
            summary="日本国内の複数組織への攻撃が確認された。ランサムウェア被害。",
            cve_ids=["CVE-2026-0001"],
        )
        with dbmod.connection() as conn:
            is_new = update_mod.process_item(conn, item)
        self.assertTrue(is_new)

        with dbmod.connection() as conn:
            rows = dbmod.list_incidents(conn)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "NEW")
        self.assertIn("CVE-2026-0001", rows[0]["cve_ids"])
        self.assertGreater(rows[0]["japan_relevance_score"], 0)

    def test_same_cve_from_second_source_is_merged_not_duplicated(self):
        item1 = self._make_item(
            title="CVE-2026-0002 exploited in the wild",
            summary="Vendor advisory describing the flaw.",
            source_id="cisa_advisories", source_name="CISA", trust_level=1, region="global",
            cve_ids=["CVE-2026-0002"],
        )
        item2 = self._make_item(
            title="国内でもCVE-2026-0002を悪用した攻撃を確認、パッチ適用を",
            summary="国内複数の自治体で被害が報告されている。修正版が公開された。",
            source_id="scan_netsecurity", source_name="ScanNetSecurity", trust_level=3, region="jp",
            cve_ids=["CVE-2026-0002"],
        )
        with dbmod.connection() as conn:
            self.assertTrue(update_mod.process_item(conn, item1))
        with dbmod.connection() as conn:
            self.assertFalse(update_mod.process_item(conn, item2))  # 統合されるので新規ではない

        with dbmod.connection() as conn:
            rows = dbmod.list_incidents(conn)
        self.assertEqual(len(rows), 1)
        # 一次情報(trust_level=1)の本文が優先され、国内報道の追加情報でスコア/ステータスが更新される
        self.assertEqual(rows[0]["source_trust_level"], 1)
        self.assertEqual(rows[0]["status"], "MITIGATED")  # パッチ公開の語句を検出

    def test_status_history_recorded(self):
        item = self._make_item(
            title="CVE-2026-0003",
            summary="initial advisory",
            cve_ids=["CVE-2026-0003"],
        )
        with dbmod.connection() as conn:
            update_mod.process_item(conn, item)
            history = conn.execute("SELECT * FROM status_history").fetchall()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["new_status"], "NEW")


if __name__ == "__main__":
    unittest.main()