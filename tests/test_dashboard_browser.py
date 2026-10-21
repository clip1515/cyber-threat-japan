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

    def test_repository_dashboard_json_in_real_html(self):
        """Read-only integration: render checked-in dashboard JSON in actual HTML."""
        path = Path(__file__).resolve().parents[1] / "docs" / "data" / "dashboard_data.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(data["all_incidents"], list)
        self.assertGreater(len(data["all_incidents"]), 0)
        page = self.show(data)
        try:
            self.assertEqual(page.locator("#errorBox:visible").count(), 0)
            self.assertEqual(page.locator("#allIncidentsList .incident").count(),
                             len(data["all_incidents"]))
            self.assertEqual(page.locator("#criticalHighList .incident").count(),
                             len(data["top_critical_high"]))
            self.assertEqual(page.locator("#japanList .incident").count(),
                             len(data["top_japan_related"]))
            self.assertEqual(page.locator("#kevList .incident").count(),
                             len(data["top_kev"]))
            self.assertEqual(page.locator("#sectorChart .bar-row").count(),
                             len(data["sector_counts"]))
            self.assertEqual(page.locator("#vectorChart .bar-row").count(),
                             len(data["vector_counts"]))
            self.assertEqual(page.locator("#trendChart svg circle").count(),
                             len(data["trend_7d"]))
            self.assertEqual(page.locator("#kpiGrid .kpi").count(), 8)
            self.assertIn(str(data["summary"]["total_incidents"]),
                          page.locator("#kpiGrid").inner_text())
            page.locator("#searchBox").fill("__no_matching_incident__")
            self.assertEqual(page.locator("#allIncidentsList .incident").count(), 0)
            page.locator("#searchBox").fill("")
            self.assertEqual(page.locator("#allIncidentsList .incident").count(),
                             len(data["all_incidents"]))
        finally:
            page.close()

    def test_real_data_firefox_and_webkit(self):
        """Cross-engine smoke test using repository data; no external requests."""
        path = Path(__file__).resolve().parents[1] / "docs" / "data" / "dashboard_data.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        chromium = self.browser
        try:
            for engine in ("firefox", "webkit"):
                with self.subTest(engine=engine):
                    browser = getattr(self.playwright, engine).launch(headless=True)
                    self.browser = browser
                    try:
                        page = self.show(data)
                        try:
                            self.assertEqual(page.locator("#errorBox:visible").count(), 0)
                            self.assertEqual(page.locator("#allIncidentsList .incident").count(),
                                             len(data["all_incidents"]))
                            self.assertEqual(page.locator("#criticalHighList .incident").count(),
                                             len(data["top_critical_high"]))
                            self.assertEqual(page.locator("#kpiGrid .kpi").count(), 8)
                            page.locator("#searchBox").fill("__no_matching_incident__")
                            self.assertEqual(page.locator("#allIncidentsList .incident").count(), 0)
                        finally:
                            page.close()
                    finally:
                        browser.close()
        finally:
            self.browser = chromium

    def test_source_url_scheme_allowlist(self):
        """F11: rejected schemes never become anchors; safe HTTPS remains escaped."""
        blocked = [
            "javascript:alert(1)", "JaVaScRiPt:alert(1)",
            "  javascript:alert(1)  ", "data:text/html,<svg onload=alert(1)>",
            "//evil.example/path", "file:///etc/passwd", "vbscript:msgbox(1)",
        ]
        for url in blocked:
            with self.subTest(url=url):
                page = self.show(payload(top_critical_high=[incident(source_url=url)]))
                try:
                    self.assertEqual(page.locator("#criticalHighList .src a").count(), 0)
                finally:
                    page.close()
        page = self.show(payload(top_critical_high=[
            incident(source_url='  https://example.invalid/?a=1&b="quoted"  ')
        ]))
        try:
            link = page.locator("#criticalHighList .src a")
            self.assertEqual(link.count(), 1)
            self.assertEqual(link.get_attribute("href"),
                             'https://example.invalid/?a=1&b="quoted"')
            self.assertEqual(link.get_attribute("rel"), "noopener noreferrer")
        finally:
            page.close()

    def test_injected_markup_stays_visible_as_literal_text(self):
        """F12/F15: do not confuse safe escaping with silent field removal."""
        injection = '<span data-probe="inert" onclick="alert(1)">TEST</span>'
        row = incident(title=injection, confirmed_facts=injection,
                       source_name=injection, cve_ids=injection)
        page = self.show(payload(top_critical_high=[row], all_incidents=[row]))
        try:
            self.assertEqual(page.locator('[data-probe="inert"]').count(), 0)
            card = page.locator("#criticalHighList .incident")
            self.assertIn(injection, card.inner_text())
            self.assertIn(injection, card.locator(".title").inner_text())
            self.assertIn(injection, card.locator(".src").inner_text())
            card.locator("details summary").click()
            self.assertIn(injection, card.locator("details").inner_text())
            self.assertIn("&lt;span", card.locator(".title").inner_html())
            self.assertEqual(card.locator("[onclick]").count(), 0)
        finally:
            page.close()

    def test_list_fields_are_escaped_not_interpreted(self):
        """F13: list-like source fields render as inert text."""
        injection = '<span data-probe="inert">TEST</span>'
        row = incident(cve_ids=["CVE-2026-00001", injection],
                       confirmed_facts="Known facts",
                       recommended_actions=["Check vendor guidance", injection])
        page = self.show(payload(top_critical_high=[row]))
        try:
            card = page.locator("#criticalHighList .incident")
            self.assertEqual(card.locator('[data-probe="inert"]').count(), 0)
            self.assertIn("CVE-2026-00001", card.inner_text())
            card.locator("details summary").click()
            self.assertIn("Check vendor guidance", card.locator("details").inner_text())
            self.assertIn(injection, card.inner_text())
        finally:
            page.close()

    def test_extreme_counts_fall_back_without_markup(self):
        """F14: non-finite numbers and injected text cannot reach HTML/CSS."""
        for invalid in ("1e400", "Infinity", "-Infinity",
                        '<span data-probe="inert">TEST</span>', {}, []):
            with self.subTest(value=str(invalid)):
                page = self.show(payload(
                    summary=dict(total_incidents=invalid),
                    sector_counts={"IT": invalid},
                    vector_counts={"Email": invalid},
                    trend_7d={"2026-10-20": invalid},
                ))
                try:
                    self.assertEqual(page.locator('[data-probe="inert"]').count(), 0)
                    self.assertIn("0", page.locator("#kpiGrid").inner_text())
                    self.assertEqual(page.locator("#sectorChart .bar-fill").count(), 1)
                    self.assertEqual(page.locator("#trendChart svg").count(), 1)
                finally:
                    page.close()

    def test_search_handles_array_and_object_fields(self):
        """List-valued CVEs remain searchable; malformed objects cannot crash search."""
        data = payload(all_incidents=[
            incident(title="Array example", cve_ids=["CVE-2026-00001", "CVE-2026-00002"]),
            incident(title="Object example", cve_ids={"toString": "inert"},
                     target_org={"toString": "inert"}, sector={"toString": "inert"},
                     threat_actor={"toString": "inert"}),
        ])
        page = self.show(data)
        try:
            page.locator("#searchBox").fill("CVE-2026-00002")
            self.assertEqual(page.locator("#allIncidentsList .incident").count(), 1)
            self.assertIn("Array example", page.locator("#allIncidentsList").inner_text())
            page.locator("#searchBox").fill("Object example")
            self.assertEqual(page.locator("#allIncidentsList .incident").count(), 1)
            page.locator("#searchBox").fill("")
            self.assertEqual(page.locator("#allIncidentsList .incident").count(), 2)
        finally:
            page.close()

    def test_object_text_and_url_fields_fail_closed(self):
        """Untrusted toString-shaped JSON cannot throw or become a clickable URL."""
        malicious = {"toString": "inert"}
        data = payload(top_critical_high=[
            incident(title=malicious, source_url=malicious, source_name=malicious,
                     confirmed_facts=malicious, cve_ids=malicious),
        ])
        page = self.show(data)
        try:
            card = page.locator("#criticalHighList .incident")
            self.assertEqual(card.count(), 1)
            self.assertEqual(card.locator(".src a").count(), 0)
            self.assertNotIn("[object Object]", card.inner_text())
            self.assertNotIn("inert", card.inner_text())
        finally:
            page.close()

    def test_svg_edge_labels_within_viewbox(self):
        """First and last trend label centers must have adequate horizontal margins."""
        page = self.show(payload(trend_7d={
            "2026-10-15": 1, "2026-10-16": 2, "2026-10-17": 3,
            "2026-10-18": 4, "2026-10-19": 5, "2026-10-20": 6,
        }))
        try:
            svg = page.locator("#trendChart svg")
            width = float(svg.get_attribute("viewBox").split()[2])
            labels = svg.locator("text")
            self.assertEqual(labels.count(), 6)
            first = float(labels.first.get_attribute("x"))
            last = float(labels.last.get_attribute("x"))
            self.assertGreaterEqual(first, 26)
            self.assertLessEqual(last, width - 26)
            self.assertEqual(labels.first.inner_text(), "10-15")
            self.assertEqual(labels.last.inner_text(), "10-20")
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
