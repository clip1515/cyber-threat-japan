"""2026-10監査 第4ラウンドで追加したテスト。

ユーザーからの追加検証依頼(Round4)に基づき、以下を検証する:
  1. CVSS v4.0対応(収集側の実装バグ修正)と、バージョン移行の訂正履歴が
     kev_change_eventsに保持されること。
  2. source_health/collector_health.jsonの記録・書き出し自体が失敗した場合、
     「監視品質が低下したこと」自体がcollector_health.json / run_log.notesの
     両方から明示的に読み取れること(単に処理が継続するだけでは不十分、という
     Round4の指摘に対応)。
  4. MSRC代替RSSを実際のfeedparserで解析する統合テスト。feedparserがこの
     sandboxに存在しない場合は明示的にSKIP扱いとし、PASSとして報告しない
     (unittest.skipを使い、pytestの結果に"skipped"として残す)。
  5. GitHub Actions心拍監視(monitoring/heartbeat.py)の判定ロジック
     (is_overdue/classify_gap)の純粋関数部分。GitHub API呼び出し自体は
     ローカルsandboxから実行・検証できないため対象外(未確認として報告)。
  6. 本番DBコピーに対する統合リハーサル(process_item()を実データ規模で実行)で
     新たに発見した2件の実バグの再発防止テスト:
     (a) status(ESCALATED/MITIGATED)が、無関係な日次の再取得のたびにACTIVEへ
         格下げされてしまう(analyzers/status.py)。
     (b) japan_relevance_scoreが、KEV由来の加点を持たない別ソースに再度touch
         されるだけで0まで後退してしまう(update.py process_item())。
"""
import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.append(str(Path(__file__).resolve().parent.parent))

from collectors.nvd_collector import _extract_cvss
from database import db as dbmod
import update as update_mod
from reporting.daily_report import build_report_data
from parsers.normalizer import make_dedup_key
from monitoring import heartbeat


def _nvd_item_v(cve_id="CVE-2021-0001", cvss=5.0, version="3.1", as_of=None,
                trust_level=1, source_id="nvd_cve"):
    from collectors.base import RawItem
    extra = {"cve_ids": [cve_id], "cvss": cvss, "cvss_version": version}
    if as_of is not None:
        extra["cvss_as_of"] = as_of
    return RawItem(
        source_id=source_id, source_name="NVD CVE API 2.0", source_trust_level=trust_level,
        title=cve_id, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published_at="2021-01-01T00:00:00+00:00", summary="desc.",
        raw_text=f"{cve_id}\ndesc.", extra=extra,
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

    def _row(self, cve_id):
        with dbmod.connection() as conn:
            return dbmod.find_incident_by_dedup_key(conn, make_dedup_key([cve_id], ""))


# ---------------------------------------------------------------------------
# Round4-① CVSS v4.0対応 + 訂正履歴の保持
# ---------------------------------------------------------------------------

class TestCvssV40Support(unittest.TestCase):
    def test_cvssmetric_v40_is_now_extracted(self):
        """実際のNVD CVE API 2.0レスポンス(2026-10, WebFetchで確認したCVE-2026-19820の
        構造を再現)でcvssMetricV40が正しく抽出されることを確認する。
        Round3時点のコードはcvssMetricV40を一切見ておらず、常にNoneになっていた。
        """
        cve = {
            "metrics": {
                "cvssMetricV40": [
                    {"type": "Primary", "source": "nvd@nist.gov",
                     "cvssData": {"version": "4.0", "baseScore": 7.8}},
                ],
            },
        }
        score, version = _extract_cvss(cve)
        self.assertEqual(score, 7.8)
        self.assertEqual(version, "4.0")

    def test_primary_metric_is_preferred_over_secondary_within_same_version(self):
        """実際に観測された構造(CVE-2026-65643): 同じCVSSバージョンの配列内に
        Primary(NVD自身)とSecondary(第三者, 例: HackerOne経由のCNA)が混在する
        ケースで、配列の先頭[0]を無条件採用するのではなくPrimaryを優先する。
        """
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {"type": "Secondary", "source": "support@hackerone.com",
                     "cvssData": {"version": "3.1", "baseScore": 5.0}},
                    {"type": "Primary", "source": "nvd@nist.gov",
                     "cvssData": {"version": "3.1", "baseScore": 8.8}},
                ],
            },
        }
        score, version = _extract_cvss(cve)
        self.assertEqual(score, 8.8, "Secondaryが配列の先頭でも、Primaryの値を優先すべき")
        self.assertEqual(version, "3.1")

    def test_v40_still_preferred_over_v31_when_both_present(self):
        """実際に観測された構造(CVE-2026-65643相当): 同一CVEにv3.1とv4.0が
        両方存在する場合、CVSS_VERSION_RANK通りv4.0を優先して採用する。"""
        cve = {
            "metrics": {
                "cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov",
                                    "cvssData": {"version": "3.1", "baseScore": 8.8}}],
                "cvssMetricV40": [{"type": "Secondary", "source": "support@hackerone.com",
                                    "cvssData": {"version": "4.0", "baseScore": 8.7}}],
            },
        }
        score, version = _extract_cvss(cve)
        self.assertEqual(version, "4.0")
        self.assertEqual(score, 8.7)

    def test_falls_back_to_first_entry_when_no_primary_exists(self):
        """Primaryが存在しない場合は、拒否せず先頭にフォールバックする
        (Primary不在自体は珍しくないため、完全拒否にはしない)。"""
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {"type": "Secondary", "source": "someone@example.com",
                     "cvssData": {"version": "3.1", "baseScore": 4.4}},
                ],
            },
        }
        score, version = _extract_cvss(cve)
        self.assertEqual(score, 4.4)
        self.assertEqual(version, "3.1")


class TestCvssVersionMigrationHistory(DbTestCase):
    def test_version_migration_is_logged_preserving_old_and_new_value(self):
        """同一trust_levelでv3.1→v4.0へ移行した場合、cvss_version_changed
        イベントとして旧バージョン・旧値と新バージョン・新値の両方が
        kev_change_eventsに残ることを確認する(「訂正履歴を保持できるか」の
        実証)。"""
        self._run([_nvd_item_v("CVE-2026-65643", cvss=8.8, version="3.1")])
        run2 = self._run([_nvd_item_v("CVE-2026-65643", cvss=8.7, version="4.0")])

        with dbmod.connection() as conn:
            data = build_report_data(conn, run2)
        version_changes = data["cvss_version_changed"]
        self.assertEqual(len(version_changes), 1)
        self.assertIn("v3.1", version_changes[0]["old_value"])
        self.assertIn("8.8", version_changes[0]["old_value"])
        self.assertIn("v4.0", version_changes[0]["new_value"])
        self.assertIn("8.7", version_changes[0]["new_value"])

        row = self._row("CVE-2026-65643")
        self.assertEqual(row["cvss"], 8.7)
        self.assertEqual(row["cvss_version"], "4.0")

    def test_version_migration_alone_is_not_treated_as_significant(self):
        """v3.1→v4.0の移行は、スコアがほぼ同じ現実の例(8.8→8.7)のように
        「深刻度が実際に変わった」とは限らないため、これ単体ではsignificant_
        changeのトリガーにしない(日次でNVDがv4.0を遡及付与するたびに
        誤検知が増えるのを防ぐための設計判断。本報告の[1]で詳細を議論)。"""
        self._run([_nvd_item_v("CVE-2026-99001", cvss=8.8, version="3.1")])
        run2 = self._run([_nvd_item_v("CVE-2026-99001", cvss=8.7, version="4.0")])
        with dbmod.connection() as conn:
            data = build_report_data(conn, run2)
        # cvss_corrected_down(8.8→8.7は数値上は下降)としては記録されるが、
        # 下降は元々significantに含めない設計(Round2)。version_changedイベントも
        # significant判定には使っていないことを確認する。
        self.assertEqual(len(data["cvss_version_changed"]), 1)
        self.assertFalse(data["significant_change"])


# ---------------------------------------------------------------------------
# Round4-② 診断台帳の保存失敗時に「監視品質の低下」を明示する
# ---------------------------------------------------------------------------

class TestDiagnosticsDegradationIsExplicit(DbTestCase):
    def test_collector_health_json_marks_degraded_sources_explicitly(self):
        with dbmod.connection() as conn:
            dbmod.record_source_health(conn, "src_ok", success=True, item_count=3)

        tmp = Path(tempfile.mkdtemp())
        with mock.patch("config.settings.DATA_DIR", tmp):
            path = update_mod._write_collector_health_json(degraded_sources=["src_broken"])

        written = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(written["diagnostics_degraded"], "degraded_sourcesを渡したらdiagnostics_degraded=Trueになるべき")
        self.assertEqual(written["diagnostics_degraded_sources"], ["src_broken"])
        self.assertIn("src_broken", written["diagnostics_note"])

    def test_collector_health_json_not_degraded_when_no_failures(self):
        tmp = Path(tempfile.mkdtemp())
        with mock.patch("config.settings.DATA_DIR", tmp):
            path = update_mod._write_collector_health_json(degraded_sources=[])
        written = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(written["diagnostics_degraded"])
        self.assertNotIn("diagnostics_note", written)

    def test_run_log_notes_mentions_health_record_failure(self):
        """main()実行中にrecord_source_health呼び出しが失敗した場合、
        run_log.notesにそのsource_idが残ることを確認する(Round3では
        処理続行のみ保証していたが、「見える」ことまでは保証していなかった)。"""
        import yaml
        from collectors.base import BaseCollector

        tmp = Path(tempfile.mkdtemp())
        sources_yaml = tmp / "sources.yaml"
        sources_yaml.write_text(
            yaml.safe_dump({"sources": [
                {"id": "src_a", "name": "A", "type": "rss", "url": "https://a.test/feed",
                 "trust_level": 2, "lang": "en", "region": "global"},
            ]}),
            encoding="utf-8",
        )
        update_mod.SOURCES_YAML = sources_yaml
        update_mod.LOG_DIR = tmp / "logs"

        class EmptyOkCollector(BaseCollector):
            def collect(self):
                return []

        orig_build_collector = update_mod.build_collector
        orig_record = dbmod.record_source_health
        update_mod.build_collector = lambda conf: EmptyOkCollector(conf)
        dbmod.record_source_health = mock.Mock(side_effect=sqlite3.OperationalError("simulated"))
        try:
            sys.argv = ["update.py", "--no-report"]
            update_mod.main()
            with dbmod.connection() as conn:
                run = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
            self.assertIn("src_a", run["notes"], "診断記録の失敗がrun_log.notesから見えるべき")
        finally:
            update_mod.build_collector = orig_build_collector
            dbmod.record_source_health = orig_record

    def test_run_log_notes_mentions_json_write_failure(self):
        import yaml
        tmp = Path(tempfile.mkdtemp())
        sources_yaml = tmp / "sources.yaml"
        sources_yaml.write_text(yaml.safe_dump({"sources": []}), encoding="utf-8")
        update_mod.SOURCES_YAML = sources_yaml
        update_mod.LOG_DIR = tmp / "logs"

        with mock.patch.object(update_mod, "_write_collector_health_json", side_effect=OSError("disk full (simulated)")):
            sys.argv = ["update.py", "--no-report"]
            update_mod.main()
        with dbmod.connection() as conn:
            run = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIn("書き出し失敗", run["notes"])


# ---------------------------------------------------------------------------
# Round4-④ MSRC代替RSSの実feedparser統合テスト(未実行ならSKIP、PASSと report しない)
# ---------------------------------------------------------------------------

_FEEDPARSER_AVAILABLE = importlib.util.find_spec("feedparser") is not None

# WebFetchで確認した実際のMSRCフィード(https://api.msrc.microsoft.com/update-guide/rss)
# の構造を再現した合成サンプル(Round3のSAMPLE_MSRC_RSSと同一のもの)。
SAMPLE_MSRC_RSS = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
<channel>
  <title>MSRC Security Update Guide</title>
  <link>https://msrc.microsoft.com/update-guide/</link>
  <description>Microsoft Security Update Guide</description>
  <item>
    <title>Chromium: CVE-2025-12727 Inappropriate implementation in V8</title>
    <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-12727</link>
    <guid isPermaLink="false">CVE-2025-12727</guid>
    <Revision>3.0</Revision>
    <pubDate>Mon, 12 Oct 2026 02:24:36 -0700</pubDate>
    <description>Information published.</description>
  </item>
  <item>
    <title>CVE-2025-0611 Remote Code Execution Vulnerability</title>
    <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-0612</link>
    <guid isPermaLink="false">CVE-2025-0612</guid>
    <Revision>2.0</Revision>
    <pubDate>Tue, 13 Oct 2026 09:00:00 -0700</pubDate>
    <description>Information published.</description>
  </item>
</channel>
</rss>
"""


@unittest.skipUnless(
    _FEEDPARSER_AVAILABLE,
    "feedparserがこのsandboxにインストールできない(pypi.orgへのDNS解決不可、"
    "Round1〜3で確認済みの環境制約)ため実行不可。CI(GitHub Actions)等、"
    "feedparserが利用可能な環境で実行すること。このテストはSKIPされており、"
    "PASSとして報告してはならない。",
)
class TestMsrcFeedparserIntegration(unittest.TestCase):
    """実際のfeedparser.parse()を使った統合テスト。このsandboxでは
    ModuleNotFoundErrorにより常にSKIPされる。feedparserが使える環境
    (GitHub Actions runner等)で実行された場合のみ意味のある結果になる。
    """

    def test_feedparser_parses_sample_msrc_feed_without_crashing(self):
        import feedparser
        parsed = feedparser.parse(SAMPLE_MSRC_RSS)
        self.assertEqual(len(parsed.entries), 2)

    def test_rsscollector_pipeline_extracts_correct_cve_from_real_feedparser(self):
        import feedparser
        from parsers.cve_extractor import extract_cve_ids

        parsed = feedparser.parse(SAMPLE_MSRC_RSS)
        titles = [e.get("title", "") for e in parsed.entries]
        self.assertIn("Chromium: CVE-2025-12727 Inappropriate implementation in V8", titles)
        mismatched_title = titles[1]
        self.assertEqual(extract_cve_ids(mismatched_title), ["CVE-2025-0611"])


class TestFeedparserAvailabilityIsHonestlyReported(unittest.TestCase):
    def test_feedparser_unavailability_is_recorded_not_hidden(self):
        """この環境でfeedparserが使えないこと自体を明示的に記録する
        (前ラウンドまでの対応を引き続き維持)。"""
        self.assertFalse(_FEEDPARSER_AVAILABLE, "この行がFalseを期待する限り、上の統合テストはSKIPされ続ける")


# ---------------------------------------------------------------------------
# Round4-⑤ GitHub Actions心拍監視の判定ロジック(純粋関数のみ、ローカルで実行可)
# ---------------------------------------------------------------------------

class TestHeartbeatMonitorLogic(unittest.TestCase):
    def test_is_overdue_true_when_gap_exceeds_threshold(self):
        now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        last_success = now - timedelta(hours=50)
        self.assertTrue(heartbeat.is_overdue(last_success, now, timedelta(hours=48)))

    def test_is_overdue_false_when_within_threshold(self):
        now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        last_success = now - timedelta(hours=30)
        self.assertFalse(heartbeat.is_overdue(last_success, now, timedelta(hours=48)))

    def test_is_overdue_true_when_never_succeeded(self):
        now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        self.assertTrue(heartbeat.is_overdue(None, now, timedelta(hours=48)), "確認不能自体も過剰超過として扱うべき(安全側)")

    def test_classify_gap_ok_within_normal_cron_delay(self):
        """cronのbest-effort遅延(本監査で確認済み: 最大4時間程度)は正常範囲として
        okを返すこと(過剰な警告を出さない)。"""
        now = datetime(2026, 10, 13, 6, 0, tzinfo=timezone.utc)
        last_success = now - timedelta(hours=28)  # 24時間周期+4時間遅延
        status = heartbeat.classify_gap(last_success, now, timedelta(hours=24))
        self.assertEqual(status, "ok")

    def test_classify_gap_warn_when_one_run_is_entirely_missed(self):
        now = datetime(2026, 10, 13, 6, 0, tzinfo=timezone.utc)
        last_success = now - timedelta(hours=50)  # 24時間x2超
        status = heartbeat.classify_gap(last_success, now, timedelta(hours=24))
        self.assertEqual(status, "warn")

    def test_classify_gap_critical_when_several_runs_missed(self):
        now = datetime(2026, 10, 13, 6, 0, tzinfo=timezone.utc)
        last_success = now - timedelta(hours=100)  # 24時間x4超
        status = heartbeat.classify_gap(last_success, now, timedelta(hours=24))
        self.assertEqual(status, "critical")

    def test_classify_gap_critical_when_last_success_unknown(self):
        now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        self.assertEqual(heartbeat.classify_gap(None, now, timedelta(hours=24)), "critical")

    def test_build_alert_message_empty_when_ok(self):
        self.assertEqual(heartbeat.build_alert_message("ok", datetime.now(timezone.utc), datetime.now(timezone.utc)), "")

    def test_build_alert_message_nonempty_when_warn_or_critical(self):
        now = datetime.now(timezone.utc)
        msg = heartbeat.build_alert_message("critical", None, now)
        self.assertIn("重大", msg)
        self.assertIn("不明", msg)


# ---------------------------------------------------------------------------
# Round4-⑥ 統合リハーサルで発見した実バグの再発防止テスト
# ---------------------------------------------------------------------------

class TestStatusDoesNotRegressToActiveOnNoOpTouch(DbTestCase):
    def test_escalated_status_survives_unrelated_kev_resync(self):
        """severityが上昇してESCALATEDになった事案が、その後severityもmitigation
        情報も変化しない無関係な再取得(KEVカタログの日次全件再同期を模す)だけで
        ACTIVEに戻ってしまわないこと(本番DBコピーでの統合リハーサルで実際に
        40件超の退行を確認した実バグの再発防止)。"""
        from collectors.base import RawItem
        low = RawItem(
            source_id="nvd_cve", source_name="NVD CVE API 2.0", source_trust_level=1,
            title="CVE-2024-7001", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7001",
            published_at="2024-01-01T00:00:00+00:00", summary="desc",
            raw_text="CVE-2024-7001\ndesc", extra={"cve_ids": ["CVE-2024-7001"], "cvss": 4.0},
        )
        self._run([low])
        high = RawItem(
            source_id="nvd_cve", source_name="NVD CVE API 2.0", source_trust_level=1,
            title="CVE-2024-7001", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7001",
            published_at="2024-01-01T00:00:00+00:00", summary="desc",
            raw_text="CVE-2024-7001\ndesc", extra={"cve_ids": ["CVE-2024-7001"], "cvss": 9.8},
        )
        self._run([high])  # severity上昇 → ESCALATED
        row = self._row("CVE-2024-7001")
        self.assertEqual(row["status"], "ESCALATED")

        # 無関係な日次再取得(同じseverity、mitigation情報なし)。
        resync = RawItem(
            source_id="cisa_kev", source_name="CISA KEV", source_trust_level=1,
            title="[KEV] CVE-2024-7001: resync", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7001",
            published_at="2024-01-01T00:00:00+00:00", summary="resync",
            raw_text="[KEV] CVE-2024-7001: resync", extra={"cve_ids": ["CVE-2024-7001"], "in_kev": True},
        )
        self._run([resync])
        row = self._row("CVE-2024-7001")
        self.assertEqual(row["status"], "ESCALATED", "無関係な再取得だけでESCALATEDがACTIVEへ後退してはならない")

    def test_mitigated_status_survives_unrelated_resync(self):
        from collectors.base import RawItem
        mitigated_item = RawItem(
            source_id="nvd_cve", source_name="NVD CVE API 2.0", source_trust_level=1,
            title="CVE-2024-7002", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7002",
            published_at="2024-01-01T00:00:00+00:00", summary="パッチが公開されました",
            raw_text="CVE-2024-7002\nパッチが公開されました", extra={"cve_ids": ["CVE-2024-7002"], "cvss": 7.0},
        )
        self._run([mitigated_item])
        self._run([mitigated_item])  # 2回目でMITIGATED確定(1回目はNEW)
        row = self._row("CVE-2024-7002")
        self.assertEqual(row["status"], "MITIGATED")

        resync = RawItem(
            source_id="cisa_kev", source_name="CISA KEV", source_trust_level=1,
            title="[KEV] CVE-2024-7002: resync", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7002",
            published_at="2024-01-01T00:00:00+00:00", summary="resync",
            raw_text="[KEV] CVE-2024-7002: resync", extra={"cve_ids": ["CVE-2024-7002"], "in_kev": True},
        )
        self._run([resync])
        row = self._row("CVE-2024-7002")
        self.assertEqual(row["status"], "MITIGATED", "無関係な再取得だけでMITIGATEDがACTIVEへ後退してはならない")


class TestJapanRelevanceScoreDoesNotRegress(DbTestCase):
    def test_kev_boosted_score_survives_later_touch_by_source_without_jp_signal(self):
        """本番DB上で実際に確認した状態(in_kev=1だがjapan_relevance_score=0)の
        再現と修正確認。KEV経由でスコアが付いた後、JPシグナルを持たない別ソース
        (NVD)に再度touchされても、スコアが0まで後退しないこと。"""
        from collectors.base import RawItem
        kev_item = RawItem(
            source_id="cisa_kev", source_name="CISA KEV", source_trust_level=1,
            title="[KEV] CVE-2024-7003: example", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7003",
            published_at="2024-01-01T00:00:00+00:00", summary="example",
            raw_text="[KEV] CVE-2024-7003: example", extra={"cve_ids": ["CVE-2024-7003"], "in_kev": True},
        )
        self._run([kev_item])
        row = self._row("CVE-2024-7003")
        boosted_score = row["japan_relevance_score"]
        self.assertGreater(boosted_score, 0, "KEV掲載はjapan_relevance_scoreに加点されるはず(前提確認)")

        nvd_item = RawItem(
            source_id="nvd_cve", source_name="NVD CVE API 2.0", source_trust_level=1,
            title="CVE-2024-7003", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7003",
            published_at="2024-01-01T00:00:00+00:00", summary="desc(日本関連キーワード無し)",
            raw_text="CVE-2024-7003\ndesc", extra={"cve_ids": ["CVE-2024-7003"], "cvss": 6.0},
        )
        self._run([nvd_item])
        row = self._row("CVE-2024-7003")
        self.assertEqual(
            row["japan_relevance_score"], boosted_score,
            "KEV由来の加点を持たない別ソースに再度touchされただけでスコアが後退してはならない",
        )
        self.assertEqual(row["in_kev"], 1)

    def test_genuinely_higher_score_from_new_source_is_still_accepted(self):
        """非後退ロジックが「上昇」を妨げないことも確認する(maxであることの確認)。"""
        from collectors.base import RawItem
        low = RawItem(
            source_id="nvd_cve", source_name="NVD CVE API 2.0", source_trust_level=1,
            title="CVE-2024-7004", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7004",
            published_at="2024-01-01T00:00:00+00:00", summary="desc",
            raw_text="CVE-2024-7004\ndesc", extra={"cve_ids": ["CVE-2024-7004"], "cvss": 6.0},
        )
        self._run([low])
        row = self._row("CVE-2024-7004")
        before = row["japan_relevance_score"]

        kev_item = RawItem(
            source_id="cisa_kev", source_name="CISA KEV", source_trust_level=1,
            title="[KEV] CVE-2024-7004: example", url="https://nvd.nist.gov/vuln/detail/CVE-2024-7004",
            published_at="2024-01-01T00:00:00+00:00", summary="example",
            raw_text="[KEV] CVE-2024-7004: example", extra={"cve_ids": ["CVE-2024-7004"], "in_kev": True},
        )
        self._run([kev_item])
        row = self._row("CVE-2024-7004")
        self.assertGreater(row["japan_relevance_score"], before, "新しいソースによるスコアの上昇は妨げられてはならない")


if __name__ == "__main__":
    unittest.main()
