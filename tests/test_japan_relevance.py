import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from analyzers.japan_relevance import analyze_japan_relevance


class TestJapanRelevance(unittest.TestCase):
    def test_domestic_source_with_victim_language_scores_high(self):
        text = "日本のある自治体で個人情報が流出する被害が確認された。ランサムウェア攻撃とみられる。"
        score, reasons = analyze_japan_relevance(text, source_region="jp", source_trust_level=1, extra={})
        self.assertGreaterEqual(score, 70)
        self.assertTrue(any("被害" in r or "日本" in r for r in reasons))

    def test_generic_foreign_advisory_scores_low(self):
        text = "A vulnerability was found in an internal enterprise tool used mostly in Europe."
        score, reasons = analyze_japan_relevance(text, source_region="global", source_trust_level=2, extra={})
        self.assertLessEqual(score, 20)

    def test_kev_listed_adds_points(self):
        text = "Widely exploited vulnerability affecting FortiGate devices."
        score, _ = analyze_japan_relevance(
            text, source_region="global", source_trust_level=1,
            extra={"in_kev": True},
        )
        self.assertGreaterEqual(score, 20 + 15 + 20)  # widely_used + kev + exploited

    def test_score_is_clipped_to_100(self):
        text = "日本 japan 日本語フィッシング ransomware apt 被害 流出"
        score, _ = analyze_japan_relevance(
            text, source_region="jp", source_trust_level=1,
            extra={"in_kev": True, "known_ransomware_use": "Known"},
        )
        self.assertLessEqual(score, 100)

    def test_low_trust_source_no_signal_is_penalized(self):
        text = "Some unrelated general IT news with no security content."
        score, reasons = analyze_japan_relevance(text, source_region="global", source_trust_level=3, extra={})
        self.assertEqual(score, 0)  # clipped at min


if __name__ == "__main__":
    unittest.main()