"""Browser regression against the real docs/index.html; synthetic data, no network."""
import json
from pathlib import Path
import unittest
from playwright.sync_api import sync_playwright

HTML = (Path(__file__).resolve().parents[1] / "docs" / "index.html").read_text(encoding="utf-8")
PROBE = '<span data-probe="inert">TEST</span>'

def incident(**overrides):
    row = dict(title="Normal title", severity="High", japan_relevance_score=75,
               published_at="2026-10-20T01:00:00Z", source_name="Test",
               source_url="https://example.invalid/test", sector="IT", country="JP",
               status="ACTIVE", cve_ids="CVE-TEST", confirmed_facts="Normal",
               target_org="", threat_actor="")
    row.update(overrides)
    return row

def payload(**overrides):
    base = dict(generated_at="2026-10-20T01:00:00Z", last_run=None,
                diff_since_last_run=None,
                summary=dict(total_incidents=2, new_count=1, critical_high_count=1,
                             japan_related_count=1, kev_count=0, ransomware_count=0,
                             apt_count=0, active_count=1),
                top_critical_high=[incident()], top_japan_related=[],
                top_kev=[], all_incidents=[incident()],
                sector_counts={"IT":2}, vector_counts={"Email":1},
                trend_7d={"2026-10-20":2}, sources=[])
    base.update(overrides)
    return base

class DashboardBrowserRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def show(self, data):
        page = self.browser.new_page()
        errors = []
        page.on("pageerror", lambda err: errors.append(str(err)))
        def serve(route):
            if route.request.url.endswith("/data/dashboard_data.json"):
                route.fulfill(status=200, content_type="application/json", body=json.dumps(data))
            elif route.request.url.endswith("/index.html"):
                route.fulfill(status=200, content_type="text/html", body=HTML)
            else:
                route.abort()
        page.route("**/*", serve)
        page.goto("http://dashboard.invalid/index.html")
        page.locator("#content").wait_for(state="visible", timeout=5000)
        self.assertEqual(errors, [], errors)
        return page

    def test_html_injection_and_valid_display(self):
        data = payload(
            summary=dict(total_incidents=PROBE, new_count=2),
            top_critical_high=[incident(title=PROBE, japan_relevance_score=PROBE,
                                        published_at=PROBE, confirmed_facts=PROBE)],
            all_incidents=[incident(title=PROBE, japan_relevance_score=PROBE)],
            sector_counts={PROBE: PROBE}, vector_counts={PROBE: PROBE},
            trend_7d={PROBE: PROBE},
        )
        page = self.show(data)
        try:
            self.assertEqual(page.locator('[data-probe="inert"]').count(), 0)
            self.assertIn("不明", page.locator("#criticalHighList").inner_text())
            self.assertIn("0", page.locator("#kpiGrid").inner_text())
            self.assertEqual(page.locator("#sectorChart .bar-fill").count(), 1)
            self.assertEqual(page.locator("#trendChart svg").count(), 1)
        finally:
            page.close()

    def test_object_number_does_not_crash(self):
        data = payload(summary={"total_incidents":{"toString":"probe"}},
                       sector_counts={"IT":{"toString":"probe"}},
                       trend_7d={"2026-10-20":{"toString":"probe"}})
        page = self.show(data)
        try:
            self.assertIn("0", page.locator("#kpiGrid").inner_text())
            self.assertEqual(page.locator('[data-probe="inert"]').count(), 0)
        finally:
            page.close()

    def test_score_range_and_missing(self):
        for value in (-1, 101, PROBE, None, 0, 100):
            with self.subTest(value=value):
                page = self.show(payload(top_critical_high=[incident(japan_relevance_score=value)]))
                try:
                    label = page.locator("#criticalHighList .tag").filter(has_text="JP Score").inner_text()
                    self.assertEqual(label, "JP Score " + (str(value) if value in (0, 100) else "不明"))
                finally:
                    page.close()

    def test_invalid_calendar_and_leap_day(self):
        for date, expected in [
            ("2026-02-30T12:00:00Z", "不明"),
            ("2025-02-29T12:00:00Z", "不明"),
            ("2024-02-29T12:00:00Z", "2024/02/29"),
            ("2026-13-01T12:00:00Z", "不明"),
            ("2026-10-20T25:00:00Z", "不明"),
        ]:
            with self.subTest(date=date):
                page = self.show(payload(top_critical_high=[incident(published_at=date)]))
                try:
                    self.assertIn(expected, page.locator("#criticalHighList .sub").inner_text())
                finally:
                    page.close()

    def test_search_and_severity_filters(self):
        page = self.show(payload(all_incidents=[incident(title="FindMe", severity="High"),
                                                    incident(title="Other", severity="Low")]))
        try:
            page.locator("#searchBox").fill("FindMe")
            self.assertEqual(page.locator("#allIncidentsList .incident").count(), 1)
            page.locator("#searchBox").fill("")
            page.locator('#severityChips [data-sev="Low"]').click()
            self.assertEqual(page.locator("#allIncidentsList .incident").count(), 1)
            self.assertIn("Other", page.locator("#allIncidentsList").inner_text())
        finally:
            page.close()

    def test_normal_charts_and_kpis(self):
        page = self.show(payload())
        try:
            self.assertIn("2", page.locator("#kpiGrid").inner_text())
            self.assertEqual(page.locator("#sectorChart .bar-fill").count(), 1)
            self.assertEqual(page.locator("#trendChart svg circle").count(), 1)
            self.assertIn("2026", page.locator("#criticalHighList .sub").inner_text())
        finally:
            page.close()

if __name__ == "__main__":
    unittest.main()
