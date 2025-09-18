# -*- coding: utf-8 -*-
import os
import sys
from src.reporters import generate_html_report

def main():
    """Main function to generate the debug report."""
    print("--- Running HTML Report Generation for Debugging ---")
    hostname = "debug-test.com"
    output_dir = "debug_outputs"
    results = {
        "score_final": 42, "note": "D", "hostname": hostname,
        "ssl_certificate": {"statut": "ERROR", "message": "La vérification du certificat a échoué (CERTIFICATE_VERIFY_FAILED).", "criticite": "HIGH", "remediation_id": "CERT_VERIFY_FAILED"},
        "tls_protocols": [{"protocole": "SSL 2.0", "statut": "SUCCESS", "message": "Non supporté"}, {"protocole": "TLS 1.3", "statut": "SUCCESS", "message": "Supporté"}],
        "http_redirect": {"statut": "SUCCESS", "message": "Redirection correcte vers HTTPS."},
        "security_headers": {"statut": "ERROR", "message": "En-tête X-Frame-Options manquant.", "criticite": "HIGH", "remediation_id": "XFO_MISSING"},
        "cookie_security": [{"statut": "WARNING", "message": "Cookie 'test' sans l'attribut Secure.", "criticite": "MEDIUM", "remediation_id": "COOKIE_NO_SECURE"}],
        "cms_footprint_meta": {"statut": "INFO", "message": "Aucun CMS détecté via les métadonnées."},
        "cms_footprint_paths": [],
        "js_libraries": [{"nom": "jQuery", "version_detectee": "1.12.4", "derniere_version": "3.7.1", "statut": "ERROR", "criticite": "HIGH", "remediation_id": "JS_LIB_OBSOLETE"}],
        "dns_records": {"spf": {"statut": "ERROR", "message": "Aucun enregistrement TXT trouvé.", "criticite": "HIGH", "remediation_id": "SPF_MISSING"}},
        "whois_info": {"registrar": "Gandi SAS", "expiration_date": "2025-12-25T00:00:00"},
        "parking_score": {"score": 20}
    }
    os.makedirs(output_dir, exist_ok=True)
    generate_html_report(results, hostname, output_dir)
    print(f"Report generated in '{output_dir}' directory.")

if __name__ == "__main__":
    main()
