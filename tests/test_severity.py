import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from analyzers.severity import determine_severity


class TestSeverity(unittest.TestCase):
    def test_high_cvss_is_critical(self):
        self.assertEqual(determine_severity(cvss=9.8), "Critical")

    def test_mid_cvss_is_medium(self):
        self.assertEqual(determine_severity(cvss=5.0), "Medium")

    def test_low_cvss_is_low(self):
        self.assertEqual(determine_severity(cvss=2.0), "Low")

    def test_kev_forces_at_least_high(self):
        self.assertEqual(determine_severity(cvss=None, in_kev=True), "High")

    def test_kev_with_critical_cvss_stays_critical(self):
        self.assertEqual(determine_severity(cvss=9.9, in_kev=True), "Critical")

    def test_ransomware_forces_at_least_high(self):
        self.assertEqual(determine_severity(cvss=3.0, is_ransomware_or_apt=True), "High")

    def test_no_data_defaults_to_low(self):
        self.assertEqual(determine_severity(), "Low")


if __name__ == "__main__":
    unittest.main()