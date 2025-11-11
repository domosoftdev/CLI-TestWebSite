# -*- coding: utf-8 -*-
import sys
from .analyzers.security import SecurityAnalyzer
from .reporters import generate_json_report, generate_csv_report, generate_html_report
from .utils import print_human_readable_report, get_hostname, check_host_exists

def run_full_scan(domain, scans_dir="scans", verbose=False, formats="html,json,csv"):
    """
    Runs a full security scan for a given domain and generates reports in the specified formats.
    """
    print(f"--- Démarrage du scan pour : {domain} ---")
    hostname = get_hostname(domain)

    if not check_host_exists(hostname):
        print(f"❌ Erreur : L'hôte '{hostname}' est introuvable.", file=sys.stderr)
        return

    try:
        analyzer = SecurityAnalyzer(verbose=verbose)
        results = analyzer.analyze(hostname, perform_gdpr_check=True)

        print_human_readable_report(results)

        print(f"--- Génération des rapports pour {hostname} dans les formats : {formats} ---")
        format_list = [f.strip() for f in formats.lower().split(',')]

        if 'json' in format_list:
            generate_json_report(results, hostname, scans_dir)
        if 'csv' in format_list:
            generate_csv_report(results, hostname, scans_dir)
        if 'html' in format_list:
            generate_html_report(results, hostname, scans_dir)

        print(f"--- Scan et rapports terminés pour {hostname} ---")
    except Exception as e:
        import traceback
        print(f"❌ Une erreur majeure est survenue durant le scan de {hostname}: {e}", file=sys.stderr)
        traceback.print_exc()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        domain_to_scan = sys.argv[1]
        run_full_scan(domain_to_scan)
    else:
        print("Usage: python -m src.scanner <domain_to_scan>")
