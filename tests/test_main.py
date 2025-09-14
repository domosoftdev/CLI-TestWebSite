import unittest
import os
import json
import sys
from unittest.mock import patch
from datetime import datetime

# Add the src directory to the Python path to allow for absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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
        self.results = {
            "score_final": 80,
            "note": "B",
            "hostname": self.hostname,
            "ssl_certificate": {
                "statut": "SUCCESS",
                "message": "Le certificat SSL est valide.",
                "criticite": "INFO",
                "points_a_corriger": [],
                "details": {
                    "jours_restants": 365,
                    "force_cle_publique": "2048 bits",
                    "algorithme_signature": "SHA-256 with RSA Encryption",
                    "noms_alternatifs_sujet (SAN)": ["test-site.com", "www.test-site.com"],
                    "chaine_de_certificats": ["Cert CA", "Root CA"]
                }
            },
            "headers": [
                {
                    "nom": "Content-Security-Policy",
                    "statut": "WARNING",
                    "criticite": "MEDIUM",
                    "message": "CSP non configuré"
                }
            ]
        }

    def tearDown(self):
        """Clean up generated files and directories."""
        if os.path.exists(self.output_dir):
            for f in os.listdir(self.output_dir):
                os.remove(os.path.join(self.output_dir, f))
            os.rmdir(self.output_dir)

    @patch('src.reporters.datetime')
    def test_report_generation(self, mock_datetime):
        """Test the generation of the HTML report."""
        # Mock datetime.now() to return a fixed date
        mock_datetime.now.return_value = datetime(2023, 10, 27)
        date_str = "271023"

        generate_html_report(self.results, self.hostname, self.output_dir)

        expected_filename = os.path.join(self.output_dir, f"{self.hostname}_{date_str}.html")

        # 1. Check if the file was created
        self.assertTrue(os.path.exists(expected_filename), f"Le fichier de rapport {expected_filename} n'a pas été créé.")

        # 2. Check if the file is not empty
        self.assertTrue(os.path.getsize(expected_filename) > 0, "Le fichier de rapport est vide.")

        # 3. Check for specific content
        with open(expected_filename, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn(f"<title>Rapport de Sécurité - {self.hostname}</title>", content, "Le titre HTML est incorrect.")
            self.assertIn(f"Score de Dangerosité : {self.results['score_final']}", content, "Le score n'a pas été trouvé dans le rapport.")
            self.assertIn(f"Note: {self.results['note']}", content, "La note n'a pas été trouvée dans le rapport.")
            self.assertIn("Ssl Certificate", content, "La section du certificat SSL est manquante.")
            self.assertIn("Expire dans", content, "Les détails du certificat SSL sont manquants.")

if __name__ == '__main__':
    unittest.main()
