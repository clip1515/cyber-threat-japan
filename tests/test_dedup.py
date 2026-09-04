import sys
import sqlite3
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from parsers.normalizer import normalize_title, make_dedup_key
from analyzers.dedup import title_similarity, find_fuzzy_duplicate


class TestNormalizer(unittest.TestCase):
    def test_normalize_strips_symbols_and_case(self):
        self.assertEqual(normalize_title("Fortinet VPN Bug!!"), normalize_title("fortinet vpn bug"))
        self.assertEqual(normalize_title("Fortinet VPN Bug!!"), "fortinetvpnbug")

    def test_dedup_key_uses_cve_when_present(self):
        k1 = make_dedup_key(["CVE-2024-1"], "Title A")
        k2 = make_dedup_key(["CVE-2024-1"], "Completely Different Title")
        self.assertEqual(k1, k2)

    def test_dedup_key_differs_without_cve_for_different_titles(self):
        k1 = make_dedup_key([], "Ransomware hits hospital in Osaka")
        k2 = make_dedup_key([], "Totally unrelated separate news article")
        self.assertNotEqual(k1, k2)


class TestFuzzyDedup(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE incidents (id INTEGER PRIMARY KEY, title TEXT, dedup_key TEXT, published_at TEXT)"
        )
        self.conn.execute(
            "INSERT INTO incidents (title, dedup_key, published_at) VALUES (?, ?, ?)",
            ("Ransomware attack hits major Japanese logistics firm",
             "title:hash1", "2026-09-01T00:00:00+00:00"),
        )
        self.conn.commit()

    def test_similar_title_within_window_matches(self):
        key = find_fuzzy_duplicate(
            self.conn,
            "Ransomware attack hits a major Japanese logistics firm!",
            "2026-09-02T00:00:00+00:00",
        )
        self.assertEqual(key, "title:hash1")

    def test_dissimilar_title_does_not_match(self):
        key = find_fuzzy_duplicate(
            self.conn,
            "New phishing campaign targets European banks",
            "2026-09-02T00:00:00+00:00",
        )
        self.assertIsNone(key)

    def test_similar_title_outside_date_window_does_not_match(self):
        key = find_fuzzy_duplicate(
            self.conn,
            "Ransomware attack hits a major Japanese logistics firm!",
            "2026-10-15T00:00:00+00:00",
        )
        self.assertIsNone(key)


if __name__ == "__main__":
    unittest.main()