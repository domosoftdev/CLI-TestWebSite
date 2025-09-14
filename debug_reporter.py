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
        "score_final": 42,
        "note": "D",
        "hostname": hostname,
        "ssl_certificate": {
          "statut": "ERROR",
          "message": "La vérification du certificat a échoué (CERTIFICATE_VERIFY_FAILED).",
          "criticite": "HIGH",
          "remediation_id": "CERT_VERIFY_FAILED"
        },
        "tls_protocols": [
          { "protocole": "SSL 2.0", "statut": "SUCCESS", "message": "Non supporté", "criticite": "INFO" },
          { "protocole": "SSL 3.0", "statut": "SUCCESS", "message": "Non supporté", "criticite": "INFO" },
          { "protocole": "TLS 1.0", "statut": "SUCCESS", "message": "Non supporté", "criticite": "INFO" },
          { "protocole": "TLS 1.1", "statut": "SUCCESS", "message": "Non supporté", "criticite": "INFO" },
          { "protocole": "TLS 1.2", "statut": "SUCCESS", "message": "Supporté", "criticite": "INFO" },
          { "protocole": "TLS 1.3", "statut": "SUCCESS", "message": "Supporté", "criticite": "INFO" }
        ],
        "http_redirect": {
          "statut": "SUCCESS",
          "message": "Redirection correcte vers HTTPS.",
          "criticite": "INFO"
        },
        "security_headers": {
          "statut": "ERROR",
          "message": "Erreur lors de la récupération des en-têtes: HTTPSConnectionPool(host='robonic.fi', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1032)')))",
          "criticite": "HIGH"
        },
        "cookie_security": [
          {
            "statut": "ERROR",
            "message": "Erreur lors de la récupération des cookies: HTTPSConnectionPool(host='robonic.fi', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1032)')))",
            "criticite": "HIGH"
          }
        ],
        "cms_footprint_meta": {
          "statut": "ERROR",
          "message": "Erreur lors de l'analyse CMS: HTTPSConnectionPool(host='robonic.fi', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1032)')))",
          "criticite": "HIGH"
        },
        "cms_footprint_paths": [],
        "dns_records": {
          "ns": { "statut": "SUCCESS", "valeurs": ["ns4.printcom.fi.", "ns3.printcom.fi.", "ns.pcom.fi.", "ns1.pcom.fi."], "criticite": "INFO" },
          "a": { "statut": "SUCCESS", "valeurs": ["185.55.85.15"], "criticite": "INFO" },
          "mx": { "statut": "SUCCESS", "valeurs": ["Prio 0: robonic-fi.mail.protection.outlook.com."], "criticite": "INFO" },
          "dmarc": { "statut": "SUCCESS", "valeur": "v=DMARC1; p=quarantine; rua=mailto:dmarc_agg@vali.email", "criticite": "INFO" },
          "spf": { "statut": "ERROR", "message": "Aucun enregistrement TXT trouvé.", "criticite": "HIGH" }
        },
        "js_libraries": [
          {
            "statut": "ERROR",
            "message": "Erreur lors de l'analyse des bibliothèques JS: HTTPSConnectionPool(host='robonic.fi', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1032)')))",
            "criticite": "HIGH"
          }
        ],
        "whois_info": {
          "statut": "SUCCESS", "criticite": "INFO", "registrar": "Printcom Center Oy", "creation_date": "1999-07-19T00:00:00",
          "expiration_date": "2026-08-31T00:00:00", "updated_date": "2020-12-08T00:00:00", "domain_status": "Registered",
          "name_servers": "ns4.printcom.fi, ns1.pcom.fi, ns3.printcom.fi, ns.pcom.fi", "dnssec": "Activé",
          "registrant_name": "ROBONIC LTD OY", "registrant_org": "N/A", "registrant_address": "Pinninkatu 53 C"
        },
        "parking_score": 20
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
