# -*- coding: utf-8 -*-
import sys
from .analyzers.security import SecurityAnalyzer
from .reporters import generate_json_report, generate_csv_report, generate_html_report
from .utils import print_human_readable_report, get_hostname, check_host_exists

def run_full_scan(domain, scans_dir="scans"):
    """
    Runs a full security scan for a given domain and generates all reports.
    """
    print(f"--- Démarrage du scan pour : {domain} ---")
    hostname = get_hostname(domain)

    if not check_host_exists(hostname):
        print(f"❌ Erreur : L'hôte '{hostname}' est introuvable.", file=sys.stderr)
        return

    try:
        # For CLI, verbose can be true, but for web app, it should be false.
        # This can be made a parameter later.
        analyzer = SecurityAnalyzer(verbose=False)
        results = analyzer.analyze(hostname, perform_gdpr_check=True)

        print_human_readable_report(results)

        print(f"--- Génération des rapports pour {hostname} ---")
        generate_json_report(results, hostname, scans_dir)
        generate_csv_report(results, hostname, scans_dir)
        generate_html_report(results, hostname, scans_dir)
        print(f"--- Scan et rapports terminés pour {hostname} ---")
    except Exception as e:
        print(f"❌ Une erreur majeure est survenue durant le scan de {hostname}: {e}", file=sys.stderr)

if __name__ == '__main__':
    # This allows running the scanner directly for debugging
    # e.g., python -m src.scanner example.com
    if len(sys.argv) > 1:
        domain_to_scan = sys.argv[1]
        run_full_scan(domain_to_scan)
    else:
        print("Usage: python -m src.scanner <domain_to_scan>")
