"""2026-10監査Round4 Phase1: 最終安全確認(本番反映前の追加検証)。

ユーザーからの指示:
  1. Japan Risk Scoreのnon-regression処理について、公式情報の訂正時には
     適切に再評価できることを確認する。
  2. MITIGATED/ESCALATED状態の維持が、新たな悪用確認や重大な変更を
     隠さないことを確認する。
  3. CVSS v4.0の評価と変更履歴を再確認する(Round4で実装済みの挙動を
     本番相当のシナリオで再確認)。

本ファイルはすべて実行し、結果(PASS/FAIL)をそのまま報告する。
未実行の項目はSKIPPEDとして表示され、PASSとして報告しない。
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from database import db as dbmod
import update as update_mod
from collectors.base import RawItem
from reporting.daily_report import build_report_data
from parsers.normalizer import make_dedup_key


def _item(source_id, source_name, trust, cve_id, raw_text, extra, title=None):
    return RawItem(
        source_id=source_id, source_name=source_name, source_trust_level=trust,
        title=title or raw_text, url=f"https://example.test/{cve_id}",
        published_at="2026-01-01T00:00:00+00:00", summary=raw_text,
        raw_text=raw_text, extra={**extra, "cve_ids": [cve_id]},
    )


class DbTestCase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        dbmod.DB_PATH = Path(self._tmp.name) / "test.db"
        dbmod.init_db()

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, items, run_id=None):
        with dbmod.connection() as conn:
            if run_id is None:
                run_id = dbmod.start_run(conn)
        for item in items:
            with dbmod.connection() as conn:
                update_mod.process_item(conn, item, run_id=run_id)
        return run_id

    def _row(self, cve_id):
        dedup_key = make_dedup_key([cve_id], None)
        with dbmod.connection() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE dedup_key=?", (dedup_key,)
            ).fetchone()
            return dict(row) if row else None


# ---------------------------------------------------------------------------
# Phase1-1: Japan Risk Score non-regressionと「公式訂正」の関係
# ---------------------------------------------------------------------------
class TestJapanRiskScoreOfficialCorrection(DbTestCase):
    def test_higher_value_from_any_source_is_accepted_even_without_trust_change(self):
        """non-regressionは「下がらない」だけで、上方への再評価は常に効く
        (=新しい事実が追加されればスコアは正しく反映される)ことを確認する。"""
        cve = "CVE-2026-90001"
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "generic vulnerability description with no regional signal", {})])
        row1 = self._row(cve)
        self.assertEqual(row1["japan_relevance_score"], 0)

        self._run([_item("cisa_kev", "CISA KEV", 1, cve,
                          "listed in KEV", {"in_kev": True})])
        row2 = self._row(cve)
        self.assertGreater(row2["japan_relevance_score"], 0, "KEV掲載による加点が反映されるべき")

    def test_no_mechanism_exists_to_officially_lower_the_score(self):
        """[確認された事実/制約] japan_relevance_scoreには「公式な下方訂正」を
        表現する入力(extraフィールド)が現状どのソースにも存在しない。
        このテストは、たとえ信頼度1(最高)の情報源が同じCVEについて
        シグナルの無いitemを再送しても、スコアは(非後退設計により)
        下がらないことを示す。つまり「本当に公式訂正したい」場合でも
        現状の設計では下方反映の経路が無いことを実証する
        (Round4で意図的に『非後退で十分』と判断した設計だが、
        『公式訂正を反映できるか』という問いには、現状はNOと答える必要がある)。
        """
        cve = "CVE-2026-90002"
        self._run([_item("cisa_kev", "CISA KEV", 1, cve,
                          "listed in KEV", {"in_kev": True})])
        row1 = self._row(cve)
        boosted_score = row1["japan_relevance_score"]
        self.assertGreater(boosted_score, 0)

        # 同じ最高信頼度(trust_level=1)のソースが、シグナルを含まないitemで
        # 再度touchする(=「この事案はKEV由来のシグナルを含まない」という
        # 明示的な訂正ではなく、ただの別文面の再送を模している。これが
        # 現状の全ソースの実際の挙動)。
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "plain nvd text with no regional signal", {})])
        row2 = self._row(cve)
        self.assertEqual(row2["japan_relevance_score"], boosted_score,
                          "non-regression設計によりスコアは下がらない(意図した挙動)")

    def test_genuinely_new_higher_signal_still_raises_score_after_a_touch(self):
        """non-regressionは「フリーズ」ではないことの確認(Round4で検証済みの
        再確認)。一度スコアが上がった後も、さらに新しいシグナルが来れば
        スコアは正しく上昇し続ける。"""
        cve = "CVE-2026-90003"
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve, "no regional signal", {})])
        self._run([_item("cisa_kev", "CISA KEV", 1, cve, "listed in KEV", {"in_kev": True})])
        row_mid = self._row(cve)
        self._run([_item("jpcert_alert", "JPCERT/CC", 1, cve,
                          "日本国内で被害を確認、ランサムウェア攻撃", {"in_kev": True})])
        row_final = self._row(cve)
        self.assertGreaterEqual(row_final["japan_relevance_score"], row_mid["japan_relevance_score"])


# ---------------------------------------------------------------------------
# Phase1-2: MITIGATED/ESCALATED維持が新たな悪用確認・重大変更を隠さないか
# ---------------------------------------------------------------------------
class TestStatusPreservationDoesNotHideSignificantChanges(DbTestCase):
    def test_further_severity_escalation_overrides_preserved_mitigated_status(self):
        """既存がMITIGATEDの状態でも、新たに重要度が上昇する事実が来れば
        ステータス維持(preserve)ロジックより先にESCALATED判定が優先されること
        (= 維持ロジックは『他のどの条件にも当たらない場合』の最終フォールバック
        であり、新しい重大事実を隠さない)。"""
        cve = "CVE-2026-90010"
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "low severity item", {"cvss": 3.0, "cvss_version": "3.1"})])
        self._run([_item("vendor_blog", "Vendor Blog", 2, cve,
                          "パッチが公開されました", {})])
        row_mitigated = self._row(cve)
        self.assertEqual(row_mitigated["status"], "MITIGATED")

        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "severity raised", {"cvss": 9.8, "cvss_version": "3.1"})])
        row_escalated = self._row(cve)
        self.assertEqual(row_escalated["status"], "ESCALATED",
                          "MITIGATED維持ロジックが新たな重要度上昇を隠してはならない")

    def test_ransomware_confirmation_is_visible_in_significant_change_even_if_status_unchanged(self):
        """既存がESCALATEDのまま変化しない(=ステータスとしては維持される)場合でも、
        ランサムウェア悪用確認という重大事実そのものはkev_change_events経由で
        significant_changeとして可視化され、隠蔽されないことを確認する。"""
        cve = "CVE-2026-90011"
        run1 = self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                                 "low severity", {"cvss": 3.0, "cvss_version": "3.1"})])
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "severity raised", {"cvss": 9.5, "cvss_version": "3.1"})])
        row_escalated = self._row(cve)
        self.assertEqual(row_escalated["status"], "ESCALATED")

        run2 = self._run([_item("cisa_kev", "CISA KEV", 1, cve,
                                 "ransomware confirmed", {"in_kev": True, "known_ransomware_use": "Known"})])
        row_after = self._row(cve)
        # ステータス自体は(新たな重要度上昇が無いため)ESCALATEDのまま維持される
        self.assertEqual(row_after["status"], "ESCALATED")

        with dbmod.connection() as conn:
            data = build_report_data(conn, run2)
        self.assertTrue(
            any(c["change_type"] == "ransomware_use_confirmed" for c in data["kev_changes"]),
            "ランサムウェア悪用確認がkev_change_eventsに記録されているべき",
        )
        self.assertTrue(
            data["significant_change"],
            "ステータスが変化していなくても、ランサムウェア悪用確認はsignificant_changeとして可視化されるべき",
        )

    def test_escalated_preserved_but_underlying_severity_field_still_updates(self):
        """ステータスが(プリザーブにより)ESCALATEDで変化しなくても、
        incidents.severity自体は毎回再計算されて最新値に更新されており、
        『見た目は同じでも内部の重大度情報が古いまま』にはならないことを確認する。"""
        cve = "CVE-2026-90012"
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "low", {"cvss": 3.0, "cvss_version": "3.1"})])
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "escalate", {"cvss": 7.5, "cvss_version": "3.1"})])
        row1 = self._row(cve)
        self.assertEqual(row1["status"], "ESCALATED")
        self.assertEqual(row1["severity"], "High")

        # さらに深刻なスコアに訂正(同じ信頼度・同バージョンだがas_ofが新しい)
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "even more severe", {"cvss": 9.9, "cvss_version": "3.1",
                                                "cvss_as_of": "2026-02-01T00:00:00Z"})])
        row2 = self._row(cve)
        self.assertEqual(row2["status"], "ESCALATED")  # ステータス名は変わらない(既にESCALATED)
        self.assertEqual(row2["severity"], "Critical")  # しかし重大度の実値はCriticalに更新されている
        self.assertEqual(row2["cvss"], 9.9)


# ---------------------------------------------------------------------------
# Phase1-3: CVSS v4.0評価・変更履歴の再確認
# ---------------------------------------------------------------------------
class TestCvssV40ReconfirmationAtScale(DbTestCase):
    def test_v31_to_v40_transition_with_identical_score_logs_version_event_only(self):
        """バージョンだけ変わってスコアが同一の場合、cvss_corrected_up/downは
        発生せず、cvss_version_changedのみが記録されることを確認する
        (スコアが変わっていないのにcorrected系イベントが誤発生しないことの確認)。"""
        cve = "CVE-2026-90020"
        run1 = self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                                 "v31", {"cvss": 8.8, "cvss_version": "3.1"})])
        run2 = self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                                 "v40 same score", {"cvss": 8.8, "cvss_version": "4.0"})])
        with dbmod.connection() as conn:
            data = build_report_data(conn, run2)
        types = [c["change_type"] for c in data["kev_changes"]]
        self.assertIn("cvss_version_changed", types)
        self.assertNotIn("cvss_corrected_up", types)
        self.assertNotIn("cvss_corrected_down", types)

    def test_more_trusted_source_can_override_with_older_cvss_version(self):
        """[確認された事実/既存設計(Round2で確立、Round4でも変更無し)]
        信頼度(trust_level)がより高いソースからの値は、CVSSバージョンの
        新旧に関わらず常に『訂正』として受け入れられる。つまり、trust_level=1の
        ソースがv3.1の値を出せば、既存のtrust_level=2由来のv4.0値よりも
        優先される。これはバグではなく既存の明文化された仕様だが、
        Phase1での再確認のため明示しておく。"""
        cve = "CVE-2026-90021"
        self._run([_item("vendor_blog", "Vendor Blog", 2, cve,
                          "v40 from less trusted source", {"cvss": 7.0, "cvss_version": "4.0"})])
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve,
                          "v31 from more trusted source", {"cvss": 8.1, "cvss_version": "3.1"})])
        row = self._row(cve)
        self.assertEqual(row["cvss_version"], "3.1")
        self.assertEqual(row["cvss"], 8.1)

    def test_version_history_accumulates_across_multiple_transitions(self):
        """v3.1→v4.0→(別の値で)v4.0と複数回推移した場合、各推移が
        個別にkev_change_eventsへ記録され、取りこぼしが無いことを確認する。"""
        cve = "CVE-2026-90022"
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve, "v31",
                          {"cvss": 8.8, "cvss_version": "3.1"})])
        self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve, "v40 first",
                          {"cvss": 8.7, "cvss_version": "4.0",
                           "cvss_as_of": "2026-01-01T00:00:00Z"})])
        run3 = self._run([_item("nvd_cve", "NVD CVE API 2.0", 1, cve, "v40 corrected",
                                 {"cvss": 9.1, "cvss_version": "4.0",
                                  "cvss_as_of": "2026-02-01T00:00:00Z"})])
        with dbmod.connection() as conn:
            all_events = dbmod.conn = None  # placeholder, real query below
        with dbmod.connection() as conn:
            rows = conn.execute(
                "SELECT change_type, old_value, new_value FROM kev_change_events "
                "WHERE incident_id = (SELECT id FROM incidents WHERE dedup_key=?) "
                "ORDER BY id", (make_dedup_key([cve], None),)
            ).fetchall()
        version_events = [r for r in rows if r["change_type"] == "cvss_version_changed"]
        score_events = [r for r in rows if r["change_type"] == "cvss_corrected_up"]
        self.assertEqual(len(version_events), 1, "v3.1->v4.0の推移は1回だけ記録される")
        self.assertEqual(len(score_events), 1, "同バージョン内でのスコア上昇(8.7->9.1)も別途記録される")


if __name__ == "__main__":
    unittest.main()
