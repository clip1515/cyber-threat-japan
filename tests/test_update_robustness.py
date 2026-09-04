"""update.py の障害耐性(1ソース/1アイテムの失敗が全体を止めないこと)を検証する。"""
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.append(str(Path(__file__).resolve().parent.parent))

from database import db as dbmod
import update as update_mod
from collectors.base import RawItem


class TestUpdateRobustness(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        self.tmp_db_path = tmp / "test.db"
        dbmod.DB_PATH = self.tmp_db_path

        self.tmp_sources_yaml = tmp / "sources.yaml"
        self.tmp_sources_yaml.write_text(
            yaml.safe_dump({
                "sources": [
                    {"id": "src_broken", "name": "Broken Source", "type": "rss",
                     "url": "https://broken.test/feed", "trust_level": 2, "lang": "en", "region": "global"},
                    {"id": "src_ok", "name": "OK Source", "type": "rss",
                     "url": "https://ok.test/feed", "trust_level": 1, "lang": "ja", "region": "jp"},
                ]
            }),
            encoding="utf-8",
        )
        update_mod.SOURCES_YAML = self.tmp_sources_yaml
        update_mod.LOG_DIR = tmp / "logs"

        self._orig_build_collector = update_mod.build_collector
        self._orig_process_item = update_mod.process_item
        self._orig_argv = sys.argv

    def tearDown(self):
        update_mod.build_collector = self._orig_build_collector
        update_mod.process_item = self._orig_process_item
        sys.argv = self._orig_argv
        self._tmpdir.cleanup()

    def test_one_broken_source_does_not_stop_others(self):
        def fake_build_collector(source_conf):
            if source_conf["id"] == "src_broken":
                raise RuntimeError("simulated network failure")

            class FakeCollector:
                def safe_collect(self_inner):
                    return [RawItem(
                        source_id="src_ok", source_name="OK Source", source_trust_level=1,
                        title="CVE-2026-1234 test advisory", url="https://ok.test/1",
                        published_at="2026-09-05T00:00:00+00:00", summary="test",
                        raw_text="CVE-2026-1234 test advisory\ntest",
                        extra={"cve_ids": ["CVE-2026-1234"]},
                    )]
            return FakeCollector()

        update_mod.build_collector = fake_build_collector
        dbmod.init_db()

        sys.argv = ["update.py", "--no-report"]
        update_mod.main()  # 例外を投げずに完走すること自体が主な検証ポイント

        with dbmod.connection() as conn:
            rows = dbmod.list_incidents(conn)
            run = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()

        self.assertEqual(len(rows), 1)
        self.assertEqual(run["sources_ok"], 1)
        self.assertEqual(run["sources_failed"], 1)

    def test_one_bad_item_does_not_stop_other_items_in_same_source(self):
        def fake_build_collector(source_conf):
            class FakeCollector:
                def safe_collect(self_inner):
                    good = RawItem(
                        source_id=source_conf["id"], source_name=source_conf["name"], source_trust_level=1,
                        title="CVE-2026-5678 good item", url="https://ok.test/good",
                        published_at="2026-09-05T00:00:00+00:00", summary="ok",
                        raw_text="CVE-2026-5678 good item\nok",
                        extra={"cve_ids": ["CVE-2026-5678"]},
                    )
                    bad = RawItem(
                        source_id=source_conf["id"], source_name=source_conf["name"], source_trust_level=1,
                        title="boom", url="https://ok.test/bad",
                        published_at="2026-09-05T00:00:00+00:00", summary="bad",
                        raw_text="boom", extra={"cve_ids": []},
                    )
                    return [bad, good]
            return FakeCollector()

        update_mod.build_collector = fake_build_collector

        real_process_item = self._orig_process_item

        def fake_process_item(conn, item, run_id=None):
            if item.title == "boom":
                raise RuntimeError("simulated parse failure")
            return real_process_item(conn, item, run_id=run_id)

        update_mod.process_item = fake_process_item
        dbmod.init_db()

        sys.argv = ["update.py", "--source", "src_ok", "--no-report"]
        update_mod.main()

        with dbmod.connection() as conn:
            rows = dbmod.list_incidents(conn)
            run = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "CVE-2026-5678 good item")
        self.assertEqual(run["items_new"], 1)
        self.assertIn("アイテム処理失敗1件", run["notes"])


if __name__ == "__main__":
    unittest.main()