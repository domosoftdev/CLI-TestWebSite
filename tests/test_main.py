import unittest
import os
from unittest.mock import patch
from datetime import datetime
from src.reporters import generate_html_report

class TestHtmlReportGeneration(unittest.TestCase):
    def setUp(self):
        self.hostname = "test-site.com"
        self.output_dir = "test_reports"
        os.makedirs(self.output_dir, exist_ok=True)
        self.results = {
            "score_final": 42, "note": "D", "hostname": self.hostname,
            "ssl_certificate": { "statut": "ERROR", "message": "Test SSL Error" },
            "tls_protocols": [ { "protocole": "TLS 1.3", "statut": "SUCCESS", "message": "Supporté" } ],
            "dns_records": { "dmarc": { "statut": "SUCCESS", "valeur": "v=DMARC1;" } }
        }

    def tearDown(self):
        if os.path.exists(self.output_dir):
            for f in os.listdir(self.output_dir):
                os.remove(os.path.join(self.output_dir, f))
            os.rmdir(self.output_dir)

    @patch('src.reporters.datetime')
    def test_report_generation_and_grouping(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2023, 10, 27)
        generate_html_report(self.results, self.hostname, self.output_dir)
        date_str = "271023"
        expected_filename = os.path.join(self.output_dir, f"{self.hostname}_{date_str}.html")
        self.assertTrue(os.path.exists(expected_filename))
        with open(expected_filename, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("1. Configuration du protocole et du transport", content)
            self.assertIn("<h3>Certificat SSL/TLS</h3>", content)
            self.assertIn("<h3>Protocoles TLS</h3>", content)
            self.assertIn("3. Infrastructure DNS et identité du domaine", content)
            self.assertIn("<h3>Enregistrements DNS</h3>", content)

if __name__ == '__main__':
    unittest.main()
