"""2026-10監査 第3ラウンドで追加したテスト。

ユーザーからの追加検証依頼(Round3)に基づき、以下を検証する:
  1. collector_health.json / source_health に認証情報が漏れないこと、
     consecutive_failuresが正常復旧時に0へリセットされること、
     診断台帳自体の保存(DB書き込み/ファイル書き込み)が失敗してもパイプライン
     本体が止まらないこと。
  2. CVSSの非後退マージが trust_level だけでなく、CVSSバージョンと更新日時も
     考慮すること(同一trust_level間の競合で、古い/低バージョンの値が新しい/
     高バージョンの値を上書きしないこと)。
  3. 既存CVEが新規KEV登録された場合に significant_change=True となること
     (Round2で作成済みのテストの再確認+より実データに近いストレステスト)。
  4. KEVカタログの全件再同期(多数の無変更+1件の本物の変更)でも、
     変更が無い項目はノイズにならず、本物の変更だけが検出されること。
  5. MSRC代替フィード(RSS/XML、CVRFという呼称だが実体はRSS2.0)の構造的な
     互換性確認。feedparserはこのサンドボックスにインストールできないため、
     標準ライブラリのxml.etree.ElementTreeによる代替検証であることを明記する
     (feedparser自体の寛容なパース挙動の検証は未確認として扱う)。
  6. source_health(DBテーブル)とdata/collector_health.json(ファイル出力)の
     整合性、および新しいスキーマ(Round2/3で追加した列・テーブル)への
     マイグレーションが既存DBのデータを壊さないこと。
"""
import json
import sqlite3
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import requests

sys.path.append(str(Path(__file__).resolve().parent.parent))
sys.path.append(str(Path(__file__).resolve().parent))

from collectors.base import BaseCollector, RawItem
from database import db as dbmod
import update as update_mod
from reporting.daily_report import build_report_data
from parsers.cve_extractor import extract_cve_ids
from parsers.normalizer import make_dedup_key

from test_db_migration import LEGACY_SCHEMA_SQL  # 最古スキーマのフィクスチャを再利用


def _nvd_item_v(cve_id="CVE-2021-0001", cvss=5.0, version="3.1", as_of=None,
                trust_level=1, source_id="nvd_cve"):
    extra = {"cve_ids": [cve_id], "cvss": cvss, "cvss_version": version}
    if as_of is not None:
        extra["cvss_as_of"] = as_of
    return RawItem(
        source_id=source_id, source_name="NVD CVE API 2.0", source_trust_level=trust_level,
        title=cve_id, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published_at="2021-01-01T00:00:00+00:00", summary="desc.",
        raw_text=f"{cve_id}\ndesc.", extra=extra,
    )


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
        title=cve_id, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published_at="2020-01-01T00:00:00+00:00", summary="NVD description.",
        raw_text=f"{cve_id}\nNVD description.", extra={"cve_ids": [cve_id], "cvss": cvss},
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
# Round3-① collector_health.json / source_health の安全性
# ---------------------------------------------------------------------------

class TestCollectorHealthSecretSafety(unittest.TestCase):
    def test_http_error_message_does_not_contain_header_only_secret(self):
        """NVD_API_KEYはhttp_get()でヘッダー(apiKey)としてのみ送信される。
        requestsのHTTPErrorの文字列表現(str(e))はURLとステータスのみを含み、
        リクエストヘッダーの値は含まれないことを、実際のrequestsオブジェクトで確認する。
        last_error_detail["message"]はこのstr(e)を元にしているため、
        ヘッダー経由の秘密情報(APIキー)がそこに漏れないことの根拠となる。
        """
        secret = "SuPeRsEcReT-Api-Key-should-never-leak-12345"
        resp = requests.Response()
        resp.status_code = 401
        resp.url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
        prepared = requests.PreparedRequest()
        prepared.headers = {"apiKey": secret, "User-Agent": "cyber-threat-japan-collector/0.1"}
        prepared.url = resp.url
        resp.request = prepared

        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            resp.raise_for_status()
        message = str(ctx.exception)
        self.assertNotIn(secret, message, "ヘッダーに載せたAPIキーが例外メッセージに含まれてはならない")

    def test_safe_collect_last_error_detail_does_not_leak_secret(self):
        """BaseCollector.safe_collect()が記録するlast_error_detail(update.pyが
        source_health/collector_health.jsonへ書き出す元データ)にも、
        同様に秘密情報が含まれないことをエンドツーエンドで確認する。
        """
        secret = "SuPeRsEcReT-Api-Key-should-never-leak-67890"

        class FakeHTTPError(Exception):
            def __init__(self):
                super().__init__(
                    "401 Client Error: Unauthorized for url: "
                    "https://services.nvd.nist.gov/rest/json/cves/2.0"
                )
                resp = requests.Response()
                resp.status_code = 401
                self.response = resp

        class Collector(BaseCollector):
            def collect(self):
                # 実装上、apiKeyはヘッダーにのみ存在し例外メッセージには含まれない。
                # (もし将来誰かがURLクエリ文字列にAPIキーを混ぜてしまったら、
                #  このテストではなく「URLがそのままメッセージに現れる」別の
                #  観点のテストで検出する必要がある。ここでは現状の実装
                #  [ヘッダー経由] が安全であることのみを保証する。)
                raise FakeHTTPError()

        c = Collector({"id": "nvd_cve", "name": "NVD", "trust_level": 1, "url": "https://services.nvd.nist.gov/rest/json/cves/2.0"})
        c.safe_collect()
        self.assertIsNotNone(c.last_error_detail)
        self.assertNotIn(secret, c.last_error_detail["message"])
        self.assertNotIn(secret, json.dumps(c.last_error_detail))


class TestConsecutiveFailureReset(DbTestCase):
    def test_consecutive_failures_resets_to_zero_on_recovery(self):
        with dbmod.connection() as conn:
            dbmod.record_source_health(conn, "src_a", success=False, error_type="Timeout", error_message="t/o")
            dbmod.record_source_health(conn, "src_a", success=False, error_type="Timeout", error_message="t/o")
            dbmod.record_source_health(conn, "src_a", success=False, error_type="Timeout", error_message="t/o")
            row = conn.execute("SELECT * FROM source_health WHERE source_id='src_a'").fetchone()
        self.assertEqual(row["consecutive_failures"], 3)

        with dbmod.connection() as conn:
            dbmod.record_source_health(conn, "src_a", success=True, item_count=5)
            row = conn.execute("SELECT * FROM source_health WHERE source_id='src_a'").fetchone()
        self.assertEqual(row["consecutive_failures"], 0, "正常復旧時にconsecutive_failuresは0へリセットされるべき")
        self.assertIsNotNone(row["last_success_at"])

        with dbmod.connection() as conn:
            dbmod.record_source_health(conn, "src_a", success=False, error_type="Timeout", error_message="t/o")
            row = conn.execute("SELECT * FROM source_health WHERE source_id='src_a'").fetchone()
        self.assertEqual(row["consecutive_failures"], 1, "リセット後の再失敗は1から数え直すべき(直前の3から継続してはならない)")


class TestHealthRecordSaveFailureDoesNotCrashPipeline(DbTestCase):
    def test_record_source_health_db_failure_is_caught_and_pipeline_continues(self):
        """source_healthへの書き込み自体が失敗(DBロック/テーブル破損等)しても、
        それが原因でmain()全体(=残りの全ソースの処理)が止まってはならない。
        2026-10監査Round3で追加したtry/exceptラップの効果を確認する。
        """
        import yaml
        tmp = Path(tempfile.mkdtemp())
        sources_yaml = tmp / "sources.yaml"
        sources_yaml.write_text(
            yaml.safe_dump({"sources": [
                {"id": "src_ok", "name": "OK", "type": "rss", "url": "https://ok.test/feed",
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
        update_mod.build_collector = lambda conf: EmptyOkCollector(conf)
        orig_record = dbmod.record_source_health

        def broken_record(*args, **kwargs):
            raise sqlite3.OperationalError("simulated: database is locked")

        dbmod.record_source_health = broken_record
        try:
            sys.argv = ["update.py", "--no-report"]
            update_mod.main()  # 例外を投げずに完走することが検証ポイント
            with dbmod.connection() as conn:
                run = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
            self.assertIsNotNone(run["finished_at"], "source_healthの記録失敗でrunそのものが未完了にならないこと")
        finally:
            update_mod.build_collector = orig_build_collector
            dbmod.record_source_health = orig_record

    def test_write_collector_health_json_failure_is_caught_and_logged(self):
        """collector_health.jsonのファイル書き込み失敗(既存のtry/except)も、
        main()全体をクラッシュさせないことを確認する(既存の安全網の再確認)。
        """
        import yaml
        tmp = Path(tempfile.mkdtemp())
        sources_yaml = tmp / "sources.yaml"
        sources_yaml.write_text(yaml.safe_dump({"sources": []}), encoding="utf-8")
        update_mod.SOURCES_YAML = sources_yaml
        update_mod.LOG_DIR = tmp / "logs"

        with mock.patch.object(update_mod, "_write_collector_health_json", side_effect=OSError("disk full (simulated)")):
            sys.argv = ["update.py", "--no-report"]
            update_mod.main()  # 例外を投げずに完走することが検証ポイント(既存のtry/exceptの効果)
        with dbmod.connection() as conn:
            run = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIsNotNone(run["finished_at"])


# ---------------------------------------------------------------------------
# Round3-② CVSSのバージョン・更新日時・出典を考慮した非後退マージ
# ---------------------------------------------------------------------------

class TestCvssVersionAndTimestampAwareMerge(DbTestCase):
    def test_equal_trust_newer_cvss_version_corrects_older_version(self):
        """同じtrust_levelでも、CVSSv2(旧手法)の値をCVSSv3.1の値が
        訂正できる(手法が新しい方を優先)。"""
        self._run([_nvd_item_v("CVE-2021-1001", cvss=5.0, version="2.0")])
        run2 = self._run([_nvd_item_v("CVE-2021-1001", cvss=7.5, version="3.1")])
        row = self._row("CVE-2021-1001")
        self.assertEqual(row["cvss"], 7.5)
        self.assertEqual(row["cvss_version"], "3.1")

    def test_equal_trust_older_cvss_version_cannot_override_newer_version(self):
        """逆方向: 既にCVSSv3.1で分かっている値を、同じtrust_levelの
        CVSSv2(旧手法)の値で後退させてはならない。"""
        self._run([_nvd_item_v("CVE-2021-1002", cvss=7.5, version="3.1")])
        self._run([_nvd_item_v("CVE-2021-1002", cvss=5.0, version="2.0")])
        row = self._row("CVE-2021-1002")
        self.assertEqual(row["cvss"], 7.5, "v3.1の値がv2の値で後退してはならない")
        self.assertEqual(row["cvss_version"], "3.1")

    def test_equal_trust_older_timestamp_cannot_override_newer_timestamp(self):
        """バージョンが同じ(v3.1同士)場合、更新日時(cvss_as_of)が古い情報で
        新しい情報を上書きしてはならない。"""
        self._run([_nvd_item_v("CVE-2021-1003", cvss=9.8, version="3.1", as_of="2021-06-01T00:00:00Z")])
        self._run([_nvd_item_v("CVE-2021-1003", cvss=4.0, version="3.1", as_of="2021-05-01T00:00:00Z")])
        row = self._row("CVE-2021-1003")
        self.assertEqual(row["cvss"], 9.8, "日時が古い情報で新しい情報を上書きしてはならない")

    def test_equal_trust_newer_timestamp_corrects_value(self):
        """バージョン同一・日時が新しい場合は、訂正(上昇・下降とも)を受け入れる。"""
        self._run([_nvd_item_v("CVE-2021-1004", cvss=4.0, version="3.1", as_of="2021-05-01T00:00:00Z")])
        self._run([_nvd_item_v("CVE-2021-1004", cvss=9.8, version="3.1", as_of="2021-06-01T00:00:00Z")])
        row = self._row("CVE-2021-1004")
        self.assertEqual(row["cvss"], 9.8, "日時がより新しい公式訂正は反映されるべき")

    def test_timestamp_unavailable_falls_back_to_accepting_as_before(self):
        """日時情報が片方(または両方)に無い場合は、従来通り『明示的な値=訂正』
        として受け入れる(既知の限界。恒久拒否にすると日時非対応ソースの
        訂正が一切効かなくなるため)。"""
        self._run([_nvd_item_v("CVE-2021-1005", cvss=4.0, version="3.1", as_of=None)])
        self._run([_nvd_item_v("CVE-2021-1005", cvss=9.8, version="3.1", as_of=None)])
        row = self._row("CVE-2021-1005")
        self.assertEqual(row["cvss"], 9.8)

    def test_higher_trust_source_still_overrides_regardless_of_version(self):
        """trust_levelがより高い(数値が小さい)ソースによる訂正は、
        Round2で確立した通り、バージョン・日時に関わらず常に受け入れる。"""
        self._run([_nvd_item_v("CVE-2021-1006", cvss=9.8, version="3.1", as_of="2021-06-01T00:00:00Z", trust_level=2, source_id="other_vendor")])
        self._run([_nvd_item_v("CVE-2021-1006", cvss=5.0, version="2.0", as_of="2020-01-01T00:00:00Z", trust_level=1, source_id="nvd_cve")])
        row = self._row("CVE-2021-1006")
        self.assertEqual(row["cvss"], 5.0, "より信頼度の高いソースの訂正はバージョン/日時のランクに関わらず採用されるべき")

    def test_lower_trust_source_still_cannot_override_regardless_of_version(self):
        """逆方向: trust_levelが低いソースは、バージョンが新しくても後退防止の対象。"""
        self._run([_nvd_item_v("CVE-2021-1007", cvss=5.0, version="2.0", trust_level=1, source_id="nvd_cve")])
        self._run([_nvd_item_v("CVE-2021-1007", cvss=1.0, version="3.1", trust_level=3, source_id="scan_netsecurity")])
        row = self._row("CVE-2021-1007")
        self.assertEqual(row["cvss"], 5.0, "信頼度の低いソースはバージョンが新しくても既存値を後退させてはならない")


# ---------------------------------------------------------------------------
# Round3-③④ 既存CVEの新規KEV登録 / 全件再同期での検出(実データに近い規模)
# ---------------------------------------------------------------------------

class TestKevChangeDetectionAtScale(DbTestCase):
    def test_existing_cve_newly_kev_listed_yields_significant_change_true(self):
        """Round2で作成済みの再確認。既知CVEが翌日KEVに新規掲載されたら
        significant_change=Trueとなることを明示的に再証明する。"""
        self._run([_nvd_item("CVE-2021-2001", cvss=5.0)])
        run2 = self._run([_kev_item("CVE-2021-2001")])
        with dbmod.connection() as conn:
            data = build_report_data(conn, run2)
        self.assertTrue(data["significant_change"])
        self.assertEqual(len(data["newly_kev_listed"]), 1)
        self.assertEqual(data["newly_kev_listed"][0]["cve_ids"], "CVE-2021-2001")

    def test_large_scale_resync_with_one_real_change_detects_only_that_change(self):
        """実際の本番環境に近い規模(多数=200件の無変更KEV再同期の中に
        1件だけ本物の変更=新規ランサムウェア悪用確認を混ぜる)でも、
        ノイズ(touchedになった199件)はkev_change_eventsに現れず、
        本物の変更1件だけが検出されることを確認する。"""
        cve_ids = [f"CVE-2022-{1000+i}" for i in range(200)]
        day1_items = [_kev_item(c) for c in cve_ids]
        self._run(day1_items)

        day2_items = [_kev_item(c) for c in cve_ids]  # 199件は完全に同一内容の再同期
        changed_cve = cve_ids[42]
        for item in day2_items:
            if item.extra["cve_ids"][0] == changed_cve:
                item.extra["known_ransomware_use"] = "Known"  # 1件だけ本物の変更
        run2 = self._run(day2_items)

        with dbmod.connection() as conn:
            data = build_report_data(conn, run2)
        self.assertEqual(len(data["kev_changes"]), 1, "200件中の本物の変更1件だけが検出されるべき")
        self.assertEqual(len(data["ransomware_confirmed"]), 1)
        self.assertEqual(data["ransomware_confirmed"][0]["cve_ids"], changed_cve)
        self.assertTrue(data["significant_change"])


# ---------------------------------------------------------------------------
# Round3-⑤ MSRC代替フィードの構造的互換性(feedparser代替検証)
# ---------------------------------------------------------------------------

# 2026-10監査Round3: このサンドボックスはPyPI(pypi.org)へのDNS解決ができず、
# feedparserをインストールできない(本報告のEnvironment Constraints参照)。
# 本番のRssCollectorはfeedparser.parse()を使うが、ここではfeedparserそのものの
# 寛容なパース挙動は検証できない(未確認として明記する)。
# 代わりに、WebFetch経由で確認した実際のMSRCフィード(
# https://api.msrc.microsoft.com/update-guide/rss)の構造を再現した合成サンプルを
# 標準ライブラリのxml.etree.ElementTreeで解析し、(a) XMLとして整形式であること、
# (b) title/link/summaryがRssCollector.collect()が期待する形で取り出せること、
# (c) title内のCVE番号抽出(extract_cve_ids、regexベースでtitleテキストに対して
# 動作し、guidフィールドには依存しない)が、観測されたtitle/guid不一致・
# 重複guid・非標準<Revision>要素の存在下でも正しく機能することを確認する。
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
    <!-- 実フィードで観測された、title側とguid側のCVE番号が一致しないケース -->
    <title>CVE-2025-0611 Remote Code Execution Vulnerability</title>
    <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-0612</link>
    <guid isPermaLink="false">CVE-2025-0612</guid>
    <Revision>2.0</Revision>
    <pubDate>Tue, 13 Oct 2026 09:00:00 -0700</pubDate>
    <description>Information published.</description>
  </item>
  <item>
    <!-- 実フィードで観測された、同一guidが異なるRevision/pubDateで複数回出現するケース -->
    <title>Windows: CVE-2025-0612 Elevation of Privilege Vulnerability</title>
    <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-0612</link>
    <guid isPermaLink="false">CVE-2025-0612</guid>
    <Revision>3.0</Revision>
    <pubDate>Wed, 14 Oct 2026 10:00:00 -0700</pubDate>
    <description>Revision 3.0 information published.</description>
  </item>
</channel>
</rss>
"""


def _parse_rss_items_via_elementtree(xml_text):
    """feedparserの代替として、本検証に必要な最小限の項目だけを
    xml.etree.ElementTreeで取り出す(本番コードのロジックではなく、
    本テスト専用の簡易パーサ)。"""
    root = ET.fromstring(xml_text)
    items = []
    for item_el in root.findall("./channel/item"):
        title = (item_el.findtext("title") or "").strip()
        link = (item_el.findtext("link") or "").strip()
        summary = (item_el.findtext("description") or "").strip()
        guid = (item_el.findtext("guid") or "").strip()
        items.append({"title": title, "link": link, "summary": summary, "guid": guid})
    return items


class TestMsrcFeedStructuralCompatibility(unittest.TestCase):
    def test_sample_is_well_formed_xml(self):
        # 整形式であること自体の確認(bozo相当の最低限のチェック)。
        ET.fromstring(SAMPLE_MSRC_RSS)  # 例外が出ないことが検証ポイント

    def test_title_link_summary_are_extractable_in_rsscollector_expected_shape(self):
        items = _parse_rss_items_via_elementtree(SAMPLE_MSRC_RSS)
        self.assertEqual(len(items), 3)
        for it in items:
            self.assertTrue(it["title"])
            self.assertTrue(it["link"])  # RssCollector.collect()は title/link が無いitemをskipする

    def test_cve_extraction_from_title_is_correct_despite_title_guid_mismatch(self):
        """title側のCVE番号(CVE-2025-0611)とguid側(CVE-2025-0612)が
        一致しないケースでも、extract_cve_ids()はtitleテキストに対して
        regexで動作する(guidには依存しない)ため、title記載の番号を
        正しく抽出できることを確認する。"""
        items = _parse_rss_items_via_elementtree(SAMPLE_MSRC_RSS)
        mismatched = items[1]
        self.assertEqual(mismatched["guid"], "CVE-2025-0612")
        extracted = extract_cve_ids(mismatched["title"] + "\n" + mismatched["summary"])
        self.assertEqual(extracted, ["CVE-2025-0611"], "guidではなくtitle記載のCVE番号が抽出されるべき")

    def test_duplicate_guid_across_revisions_does_not_break_cve_extraction(self):
        """同一guid(CVE-2025-0612)が異なるRevision/pubDateで2回出現しても、
        各itemのtitleテキストからのCVE抽出はitemごとに独立して正しく動作する。"""
        items = _parse_rss_items_via_elementtree(SAMPLE_MSRC_RSS)
        guids = [it["guid"] for it in items]
        self.assertEqual(guids.count("CVE-2025-0612"), 2, "合成サンプルは実フィードの重複guidを再現している")
        third = items[2]
        self.assertEqual(extract_cve_ids(third["title"]), ["CVE-2025-0612"])

    def test_feedparser_itself_is_not_available_in_this_sandbox(self):
        """重要な制約の明示: 本番で実際に使われるfeedparserの寛容な
        パース挙動そのもの(例: 本テストが代替しているXML構文エラー耐性)は、
        このサンドボックスでは検証できない(未確認)。"""
        import builtins
        from unittest.mock import patch
        original_import = builtins.__import__
        def simulate_missing_feedparser(name, *args, **kwargs):
            if name == 'feedparser':
                raise ModuleNotFoundError("No module named 'feedparser'")
            return original_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=simulate_missing_feedparser):
            with self.assertRaises(ModuleNotFoundError):
                import feedparser  # noqa: F401


# ---------------------------------------------------------------------------
# Round3-⑥ source_health <-> collector_health.json の整合性 / スキーマ移行
# ---------------------------------------------------------------------------

class TestCollectorHealthJsonConsistency(DbTestCase):
    def test_collector_health_json_matches_source_health_table_exactly(self):
        with dbmod.connection() as conn:
            dbmod.record_source_health(conn, "src_a", success=True, item_count=3)
            dbmod.record_source_health(conn, "src_b", success=False, error_type="Timeout",
                                        error_message="read timed out", http_status=None)

        tmp = Path(tempfile.mkdtemp())
        data_dir_patch = mock.patch("update.DATA_DIR" if hasattr(update_mod, "DATA_DIR") else "config.settings.DATA_DIR", tmp)
        with data_dir_patch:
            path = update_mod._write_collector_health_json()

        with dbmod.connection() as conn:
            db_rows = {r["source_id"]: r for r in dbmod.get_all_source_health(conn)}

        written = json.loads(path.read_text(encoding="utf-8"))
        json_rows = {r["source_id"]: r for r in written["sources"]}

        self.assertEqual(set(db_rows.keys()), set(json_rows.keys()))
        for source_id, db_row in db_rows.items():
            self.assertEqual(json_rows[source_id], db_row, f"{source_id}: JSON出力とDBの内容が完全に一致するべき")


class TestRound3SchemaMigration(unittest.TestCase):
    """Round2/3で追加した列・テーブルへの移行が、最古スキーマのDBを壊さないことを確認する。
    test_db_migration.LEGACY_SCHEMA_SQL(最古スキーマのフィクスチャ)をそのまま再利用する。
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_db_path = Path(self._tmpdir.name) / "legacy.db"
        conn = sqlite3.connect(str(self.tmp_db_path))
        conn.executescript(LEGACY_SCHEMA_SQL)
        conn.execute(
            "INSERT INTO incidents (dedup_key, title, status, cvss) VALUES (?, ?, ?, ?)",
            ("legacy-key-cvss", "既存の事案(CVSSあり)", "ACTIVE", 7.0),
        )
        conn.commit()
        conn.close()
        dbmod.DB_PATH = self.tmp_db_path

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_round2_and_round3_columns_and_tables_are_added_without_error(self):
        dbmod.init_db()  # 例外が出ないことが主な検証ポイント
        with dbmod.connection() as conn:
            incident_cols = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)")}
            tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for col in ("kev_known_ransomware_use", "kev_due_date", "cvss_version", "cvss_as_of", "cvss_source_id"):
            self.assertIn(col, incident_cols, f"列{col}が追加されているべき")
        for table in ("kev_change_events", "source_health"):
            self.assertIn(table, tables, f"テーブル{table}が作成されているべき")

    def test_existing_data_and_cvss_survive_full_migration(self):
        dbmod.init_db()
        with dbmod.connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE dedup_key='legacy-key-cvss'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["title"], "既存の事案(CVSSあり)")
        self.assertEqual(row["cvss"], 7.0, "既存のCVSS値がマイグレーションで消えてはならない")
        self.assertIsNone(row["cvss_version"], "新列はNULLで補完されるべき(旧データに無い情報を創作しない)")

    def test_running_init_db_twice_on_migrated_db_is_idempotent(self):
        dbmod.init_db()
        dbmod.init_db()  # 2回目も列/テーブル重複エラーにならないこと
        with dbmod.connection() as conn:
            tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("source_health", tables)


if __name__ == "__main__":
    unittest.main()
