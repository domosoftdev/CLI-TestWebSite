import unittest
import os
import json
import sys
from unittest.mock import patch
from datetime import datetime

from src.reporters import generate_html_report

class TestHtmlReportGeneration(unittest.TestCase):
    """
    Test case for the HTML report generation functionality.
    """
    def setUp(self):
        """Set up test data and environment."""
        self.hostname = "test-site.com"
        self.output_dir = "test_reports"
        os.makedirs(self.output_dir, exist_ok=True)
        # Use a subset of the data from debug_reporter.py to keep the test focused
        self.results = {
            "score_final": 42,
            "note": "D",
            "hostname": self.hostname,
            "ssl_certificate": { "statut": "ERROR", "message": "Test SSL Error" },
            "tls_protocols": [ { "protocole": "TLS 1.3", "statut": "SUCCESS", "message": "Supporté" } ],
            "dns_records": { "dmarc": { "statut": "SUCCESS", "valeur": "v=DMARC1;" } },
            "whois_info": { "Registrar": "Test Registrar" }
        }

    def tearDown(self):
        """Clean up generated files and directories."""
        if os.path.exists(self.output_dir):
            for f in os.listdir(self.output_dir):
                os.remove(os.path.join(self.output_dir, f))
            os.rmdir(self.output_dir)

    @patch('src.reporters.datetime')
    def test_report_generation_and_grouping(self, mock_datetime):
        """Test the generation of the HTML report and its group structure."""
        mock_datetime.now.return_value = datetime(2023, 10, 27)

        generate_html_report(self.results, self.hostname, self.output_dir)

        date_str = "271023"
        expected_filename = os.path.join(self.output_dir, f"{self.hostname}_{date_str}.html")

        self.assertTrue(os.path.exists(expected_filename))

        with open(expected_filename, 'r', encoding='utf-8') as f:
            content = f.read()

            # Check for new card titles
            self.assertIn("<h3>Sécurité SSL/TLS</h3>", content)
            self.assertIn("<h3>Protocoles TLS</h3>", content)
            self.assertIn("<h3>DNS & Informations WHOIS</h3>", content)

            # Check that SSL certificate content is rendered
            self.assertIn("Test SSL Error", content)

            # Check that DNS content is rendered
            self.assertIn("v=DMARC1;", content)

if __name__ == '__main__':
    unittest.main()
