"""2026-10-12 監査で発見した、daily_report.md / dashboard の「重要な変化」誤検知の
再現テスト。

実際の daily_report.md / dashboard_data.json では、CISA KEVカタログ全体
(約1700件超)が毎日まるごと再取得され、既存のKEV掲載事案が「touched」として
毎回 upsert されている。これが2つの問題を引き起こしていた:

1. (analyzers/status.py 経由) 同一CVEが複数ソース(KEVカタログ/NVD等)から
   別々に届き、in_kev/cvssがそのitem単体にしか無い情報を元に重要度が
   都度再計算されるため、既に分かっている重要度より一時的に下がった値で
   計算されてしまい、翌日以降「再度上がる」ことでESCALATEDが誤って
   繰り返し発生する(本番DBで28件の既存KEV事案がACTIVE/ESCALATEDを
   連日往復していることを確認済み)。

2. (reporting/daily_report.py 経由) significant_change の判定が
   「このrunでtouchedになった事案にKEV掲載が1件でもあるか」だけを見ており、
   「新規に」KEVに追加されたのか「既存のKEV掲載事案が今日も再取得されただけ」
   なのかを区別していない。カタログ全体を毎日再取得する実装である以上、
   この条件はほぼ恒久的にTrueになる。

このファイルのテストは、修正前は失敗し、修正後に通ることを意図している。
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.base import RawItem
from database import db as dbmod
import update as update_mod
from reporting.daily_report import build_report_data


def _kev_item(cve_id="CVE-2020-9999", run_tag="r"):
    return RawItem(
        source_id="cisa_kev", source_name="CISA KEV", source_trust_level=1,
        title=f"[KEV] {cve_id}: Example old vulnerability",
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published_at="2020-01-01T00:00:00+00:00",
        summary="Old, well-known vulnerability re-listed in the catalog.",
        raw_text=f"[KEV] {cve_id}: Example old vulnerability\nOld, well-known vulnerability re-listed in the catalog.",
        extra={"cve_ids": [cve_id], "in_kev": True, "kev_date_added": "2020-01-01"},
    )


def _other_source_mention(cve_id="CVE-2020-9999"):
    """同じCVEに言及するが、in_kev/cvss情報を自分のextraに持たない別ソース由来のitem
    (例: ニュース記事やブログがCVE番号を本文で言及しているだけのケース)。"""
    return RawItem(
        source_id="scan_netsecurity", source_name="ScanNetSecurity", source_trust_level=3,
        title=f"{cve_id}に関する解説記事",
        url=f"https://example.test/article-{cve_id}",
        published_at="2020-01-02T00:00:00+00:00",
        summary=f"{cve_id} について解説。",
        raw_text=f"{cve_id}に関する解説記事\n{cve_id} について解説。",
        extra={},  # cve_idsはextract_cve_idsでraw_textから抽出される
    )


class TestKevResyncDoesNotFlapSeverity(unittest.TestCase):
    """analyzers/status.py + update.process_item の重要度算出が、
    既知の知識(in_kev/cvss)を後退させないことを確認する。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DB_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.init_db()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _run(self, items):
        with dbmod.connection() as conn:
            run_id = dbmod.start_run(conn)
        for item in items:
            with dbmod.connection() as conn:
                update_mod.process_item(conn, item, run_id=run_id)
        return run_id

    def test_other_source_mention_does_not_demote_kev_severity(self):
        cve = "CVE-2020-9999"
        # Day 1: KEVカタログ経由で新規検出 → severity=High, status=NEW
        self._run([_kev_item(cve)])
        with dbmod.connection() as conn:
            row = dbmod.find_incident_by_dedup_key(
                conn, __import__("parsers.normalizer", fromlist=["make_dedup_key"]).make_dedup_key([cve], "")
            )
        self.assertEqual(row["severity"], "High")

        # Day 2: 同じCVEに言及する別ソース(in_kev情報を持たない)の記事が、
        # KEVカタログの再取得より先に処理される。
        self._run([_other_source_mention(cve), _kev_item(cve)])

        with dbmod.connection() as conn:
            row = dbmod.find_incident_by_dedup_key(
                conn, __import__("parsers.normalizer", fromlist=["make_dedup_key"]).make_dedup_key([cve], "")
            )
        # 既にKEV掲載だと分かっている事案の重要度が、KEV情報を持たない
        # 別ソースの通過によってHighより下に後退してはならない。
        self.assertEqual(row["severity"], "High")
        self.assertEqual(row["in_kev"], 1)

    def test_no_repeated_escalation_once_true_severity_is_known(self):
        cve = "CVE-2020-9999"
        self._run([_kev_item(cve)])  # Day1: NEW, High

        escalated_days = 0
        for _ in range(5):  # Day2-6: 毎日カタログが再取得されるだけで、他に実際の変化は無い
            run_id = self._run([_other_source_mention(cve), _kev_item(cve)])
            with dbmod.connection() as conn:
                history = conn.execute(
                    "SELECT * FROM status_history WHERE run_id=? AND new_status='ESCALATED'",
                    (run_id,),
                ).fetchall()
            escalated_days += len(history)

        # 実際には何も新しい事実が発生していないのに、5日間で何度もESCALATEDが
        # 記録されてしまうのが現在の不具合(修正前はここで失敗する)。
        self.assertEqual(
            escalated_days, 0,
            "同じ事案が実際の変化なしに繰り返しESCALATEDとして記録されている(重要度の後退によるフラッピング)",
        )


class TestKevCatalogResyncIsNotSignificant(unittest.TestCase):
    """reporting/daily_report.py の significant_change が、
    『KEVカタログの日次再同期そのもの』では真にならないことを確認する。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DB_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.init_db()

    def tearDown(self):
        self._tmpdir.cleanup()

    def _run(self, items):
        with dbmod.connection() as conn:
            run_id = dbmod.start_run(conn)
        for item in items:
            with dbmod.connection() as conn:
                update_mod.process_item(conn, item, run_id=run_id)
        return run_id

    def test_first_sighting_is_still_significant(self):
        run_id = self._run([_kev_item("CVE-2020-1111")])
        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id)
        self.assertTrue(data["significant_change"])  # 初回検出は従来通り重要

    def test_unchanged_resync_is_not_significant(self):
        self._run([_kev_item("CVE-2020-2222")])  # Day1: 新規
        run_id2 = self._run([_kev_item("CVE-2020-2222")])  # Day2: 同じ内容の再同期のみ
        with dbmod.connection() as conn:
            data = build_report_data(conn, run_id2)
        self.assertEqual(data["new_incidents"], [])
        self.assertEqual(data["escalated"], [])
        self.assertFalse(
            data["significant_change"],
            "新規事案もESCALATEDも無いのに、KEVカタログの再同期だけでsignificant_change=Trueになっている",
        )


if __name__ == "__main__":
    unittest.main()
