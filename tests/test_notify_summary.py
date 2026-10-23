import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from reporting import notify_summary


class TestNotifySummary(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_path = notify_summary.DATA_PATH
        notify_summary.DATA_PATH = Path(self._tmpdir.name) / "dashboard_data.json"

    def tearDown(self):
        notify_summary.DATA_PATH = self._orig_path
        self._tmpdir.cleanup()

    def test_missing_file_returns_readable_message(self):
        text = notify_summary.build_summary_text()
        self.assertIn("見つかりません", text)

    def test_no_significant_change_message(self):
        notify_summary.DATA_PATH.write_text(json.dumps({
            # 品質情報が完全な(全ソース成功の)回だけ「重要な変化なし」と断定できる。
            "last_run": {"sources_ok": 2, "sources_failed": 0, "notes": '2ソース中 成功2/失敗0 quality={"version": 1, '
                         '"failed_sources": [], "incomplete_sources": [], "items_failed": 0}'},
            "summary": {"total_incidents": 5, "critical_high_count": 0,
                        "japan_related_count": 0, "kev_count": 0},
            # 差分情報が揃っている場合だけ「変化なし」と判断できる。
            "diff_since_last_run": {"significant_change": False, "new_incidents": [], "escalated": [],
                                    "japan_victims": [], "kev_items": []},
        }), encoding="utf-8")
        text = notify_summary.build_summary_text()
        self.assertIn("重要な新規変化はありません", text)

    def test_significant_change_message_includes_counts(self):
        notify_summary.DATA_PATH.write_text(json.dumps({
            "summary": {"total_incidents": 5},
            "diff_since_last_run": {
                "significant_change": True,
                "new_incidents": [{"id": 1}],
                "escalated": [],
                "japan_victims": [{"id": 1}],
                "kev_items": [{"id": 1}],
            },
        }), encoding="utf-8")
        text = notify_summary.build_summary_text()
        self.assertIn("重要な変化を検出しました", text)
        self.assertIn("新規 1件", text)
        self.assertIn("日本組織への実被害 1件", text)


if __name__ == "__main__":
    unittest.main()