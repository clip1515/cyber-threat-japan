import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from parsers.cve_extractor import extract_cve_ids, extract_iocs


class TestCveExtractor(unittest.TestCase):
    def test_extracts_single_cve(self):
        text = "This advisory covers CVE-2024-12345 affecting the product."
        self.assertEqual(extract_cve_ids(text), ["CVE-2024-12345"])

    def test_extracts_multiple_and_dedupes(self):
        text = "cve-2023-0001 and CVE-2023-0001 and CVE-2022-99999"
        self.assertEqual(extract_cve_ids(text), ["CVE-2022-99999", "CVE-2023-0001"])

    def test_no_cve_returns_empty(self):
        self.assertEqual(extract_cve_ids("no vulnerabilities mentioned here"), [])

    def test_extract_iocs_ip_and_hash(self):
        text = "C2 server at 203.0.113.5 dropped a payload with sha256 " \
               "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        iocs = extract_iocs(text)
        types = {t for t, _ in iocs}
        self.assertIn("ip", types)
        self.assertIn("hash_sha256", types)


if __name__ == "__main__":
    unittest.main()