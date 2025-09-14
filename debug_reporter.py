# -*- coding: utf-8 -*-

"""
This is a standalone script for debugging and evolving the generate_html_report function.

It calls the function with a sample dataset and saves the output to a 'debug_outputs'
directory without cleaning it up, allowing for easy inspection of the generated HTML.

To run this script:
python debug_reporter.py
"""

import os
import sys
from datetime import datetime

# Add the src directory to the Python path to allow for absolute imports from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

try:
    from reporters import generate_html_report
except ImportError:
    print("Error: Could not import 'generate_html_report' from 'src.reporters'.")
    print("Please ensure the file 'src/reporters.py' exists and the main refactoring has been applied.")
    sys.exit(1)

def main():
    """Main function to generate the debug report."""
    print("--- Running HTML Report Generation for Debugging ---")

    hostname = "debug-test.com"
    output_dir = "debug_outputs"

    # Sample data for the report
    results = {
        "score_final": 75,
        "note": "C",
        "hostname": hostname,
        "ssl_certificate": {
            "statut": "WARNING",
            "message": "Le certificat SSL expire bientôt.",
            "criticite": "MEDIUM",
            "points_a_corriger": [
                {"criticite": "MEDIUM", "message": "Le certificat expire dans moins de 30 jours."}
            ],
            "details": {
                "jours_restants": 25,
                "force_cle_publique": "4096 bits",
                "algorithme_signature": "SHA-256 with RSA Encryption",
                "noms_alternatifs_sujet (SAN)": ["debug-test.com", "www.debug-test.com"],
                "chaine_de_certificats": ["Intermediate CA", "Root CA"]
            }
        },
        "headers": [
            {
                "nom": "Strict-Transport-Security",
                "statut": "SUCCESS",
                "criticite": "INFO",
                "message": "HSTS est bien configuré."
            },
            {
                "nom": "X-Frame-Options",
                "statut": "ERROR",
                "criticite": "HIGH",
                "message": "L'en-tête X-Frame-Options est manquant."
            }
        ],
        "some_other_category": {
            "statut": "INFO",
            "message": "Ceci est une catégorie de test."
        }
    }

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Call the report generation function
    generate_html_report(results, hostname, output_dir)

    print("\nDebug report generation process finished.")
    print(f"Check the '{output_dir}' directory for the HTML report.")
    print("The file will not be deleted automatically.")

if __name__ == "__main__":
    main()
