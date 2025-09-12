import unittest
import json
from datetime import datetime
from unittest.mock import patch, mock_open

from consolidator import (
    load_scan_results,
    compare_scans,
    _extract_vulnerabilities,
    _get_quick_wins,
    _count_critical_vulnerabilities,
)

# Sample scan data that can be used across multiple tests
SAMPLE_SCAN_DATA = {
    "score_final": 55,
    "security_headers": {
        "hsts": {"statut": "ERROR", "criticite": "HIGH", "remediation_id": "HSTS_MISSING"}
    },
    "cookie_security": [
        {
            "nom": "sessionid",
            "secure": {"present": False, "criticite": "HIGH", "remediation_id": "COOKIE_NO_SECURE"},
            "httponly": {"present": True, "criticite": "INFO", "remediation_id": "COOKIE_NO_HTTPONLY"},
            "samesite": {"present": False, "criticite": "MEDIUM", "remediation_id": "COOKIE_NO_SAMESITE"}
        }
    ],
    "js_libraries": [
        {"bibliotheque": "jquery", "version_detectee": "1.12.4", "statut": "WARNING", "criticite": "CRITICAL", "remediation_id": "JS_LIB_OBSOLETE"}
    ],
    "a_successful_check": {
        "statut": "SUCCESS",
        "criticite": "INFO"
    }
}

class TestConsolidatorHelpers(unittest.TestCase):

    def test_extract_vulnerabilities(self):
        vulnerabilities = _extract_vulnerabilities(SAMPLE_SCAN_DATA)
        expected_vulns = {
            'security_headers.hsts.HSTS_MISSING',
            'cookie_security[0].secure.COOKIE_NO_SECURE',
            'cookie_security[0].samesite.COOKIE_NO_SAMESITE',
            'js_libraries[0].JS_LIB_OBSOLETE'
        }
        self.assertEqual(vulnerabilities, expected_vulns)

    def test_get_quick_wins(self):
        quick_wins = _get_quick_wins(SAMPLE_SCAN_DATA)
        expected_wins = {
            'security_headers.hsts.HSTS_MISSING',
            'cookie_security[0].secure.COOKIE_NO_SECURE',
            'cookie_security[0].samesite.COOKIE_NO_SAMESITE'
        }
        self.assertEqual(quick_wins, expected_wins)

    def test_count_critical_vulnerabilities(self):
        count = _count_critical_vulnerabilities(SAMPLE_SCAN_DATA)
        self.assertEqual(count, 3)

    def test_empty_scan_data(self):
        empty_data = {"score_final": 0, "note": "A+"}
        self.assertEqual(_extract_vulnerabilities(empty_data), set())
        self.assertEqual(_get_quick_wins(empty_data), set())
        self.assertEqual(_count_critical_vulnerabilities(empty_data), 0)


class TestConsolidatorMainLogic(unittest.TestCase):

    @patch("consolidator.os.listdir")
    @patch("builtins.open", new_callable=mock_open)
    def test_load_scan_results(self, mock_file, mock_listdir):
        mock_listdir.return_value = ["site2_020123.json", "site1_010123.json", "invalid.txt"]

        file_content_map = {
            "scans/site1_010123.json": '{"hostname": "site1", "score_final": 10}',
            "scans/site2_020123.json": '{"hostname": "site2", "score_final": 20}',
        }
        mock_file.side_effect = lambda filepath, *args, **kwargs: mock_open(read_data=file_content_map.get(filepath, "")).return_value

        results = load_scan_results()

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["domain"], "site2") # Sorted reverse
        self.assertEqual(results[1]["domain"], "site1")

    def test_compare_scans_improvement(self):
        scan1_data = {"score_final": 20, "security_headers": {"hsts": {"remediation_id": "HSTS_MISSING"}}}
        scan2_data = {"score_final": 10, "security_headers": {"hsts": {"statut": "SUCCESS"}}}

        all_scans = [
            {"domain": "example.com", "date": datetime(2023, 1, 1), "data": scan1_data},
            {"domain": "example.com", "date": datetime(2023, 1, 2), "data": scan2_data},
        ]

        from io import StringIO
        with patch('sys.stdout', new=StringIO()) as fake_out:
            compare_scans(all_scans, "example.com", "2023-01-01", "2023-01-02")
            output = fake_out.getvalue()

            self.assertIn("Amélioration du score", output)
            self.assertIn("[✅ VULNÉRABILITÉS CORRIGÉES]", output)

if __name__ == '__main__':
    unittest.main()
