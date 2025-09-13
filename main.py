# -*- coding: utf-8 -*-

"""
Main entry point for the web security analysis application.
This script handles command-line arguments, orchestrates the analysis,
and generates reports.
"""

import argparse
import sys
import json
import csv
from datetime import datetime

# Import the core logic and analyzer classes from the new structure
from src.analyzers.security import SecurityAnalyzer
from src.core.consolidator import Consolidator
from src.config import REMEDIATION_ADVICE

# --- Utility Functions ---

def check_host_exists(hostname):
    """Checks if a hostname can be resolved."""
    import socket
    try:
        socket.gethostbyname_ex(hostname)
        return True
    except socket.gaierror:
        return False

def get_hostname(url):
    """Extracts the hostname from a URL."""
    if url.startswith('https://'): url = url[8:]
    if url.startswith('http://'): url = url[7:]
    if '/' in url: url = url.split('/')[0]
    return url

# --- Reporting Functions ---

def generate_json_report(results, hostname):
    """Generates a JSON report from the analysis results."""
    date_str = datetime.now().strftime('%d%m%y')
    filename = f"{hostname}_{date_str}.json"
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n✅ Rapport JSON généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport JSON : {e}")

def generate_csv_report(results, hostname):
    """Generates a CSV report from the analysis results."""
    date_str = datetime.now().strftime('%d%m%y')
    filename = f"{hostname}_{date_str}.csv"
    header = ['Catégorie', 'Sous-catégorie', 'Statut', 'Criticité', 'Description', 'Vulnérabilités']
    rows = []

    # Helper to flatten the nested result dictionaries
    def flatten_data(category, sub_category, data):
        if isinstance(data, list):
            for item in data:
                flatten_data(category, sub_category, item)
        elif isinstance(data, dict):
            if 'statut' in data and data['statut'] in ['ERROR', 'WARNING']:
                vuln_ids = ", ".join([v['id'] for v in data.get('vulnerabilities', [])])
                rows.append({
                    'Catégorie': category,
                    'Sous-catégorie': data.get('protocole') or data.get('nom') or data.get('bibliotheque') or sub_category,
                    'Statut': data.get('statut'),
                    'Criticité': data.get('criticite'),
                    'Description': data.get('message') or f"Version: {data.get('version_detectee')} (Dernière: {data.get('derniere_version')})",
                    'Vulnérabilités': vuln_ids
                })
            # Add more specific flattening logic as needed

    for key, res in results.items():
        if key in ['hostname', 'score_final', 'note']:
            continue
        flatten_data(key.replace('_', ' ').title(), key, res)

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n✅ Rapport CSV généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport CSV : {e}")

def generate_html_report(results, hostname):
    """Generates an HTML report from the analysis results."""
    date_str = datetime.now().strftime('%d%m%y')
    filename = f"{hostname}_{date_str}.html"
    score = results.get('score_final', 0)
    grade = results.get('note', 'N/A')

    # Basic HTML structure, can be enhanced with CSS from the original file
    html_content = f"<!DOCTYPE html><html><head><title>Rapport de Sécurité - {hostname}</title></head><body>"
    html_content += f"<h1>Rapport d'Analyse de Sécurité pour {hostname}</h1>"
    html_content += f"<h2>Score de Dangerosité : {score} (Note: {grade})</h2>"

    for category, data in results.items():
        if category in ['hostname', 'score_final', 'note']:
            continue
        html_content += f"<div><h2>{category.replace('_', ' ').title()}</h2>"
        # This is a simplified version; a full implementation would need the detailed logic
        # from the original security_analyzer to render findings correctly.
        html_content += f"<pre>{json.dumps(data, indent=2)}</pre>"
        html_content += "</div>"

    html_content += "</body></html>"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"\n✅ Rapport HTML généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport HTML : {e}")


def print_human_readable_report(results):
    """Prints a human-readable summary of the analysis to the console."""
    STATUS_ICONS = {"SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}
    score = results.get('score_final', 'N/A')
    grade = results.get('note', 'N/A')
    hostname = results.get('hostname', 'N/A')

    print("\n" + "="*50)
    print(f" RAPPORT D'ANALYSE DE SÉCURITÉ POUR : {hostname}")
    print(f" SCORE DE DANGEROSITÉ : {score} (Note : {grade})")
    print("="*50)

    # Simplified printing logic
    for category, data in results.items():
        if category in ['hostname', 'score_final', 'note']:
            continue
        print(f"\n--- {category.replace('_', ' ').title()} ---")
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'statut' in item:
                    icon = STATUS_ICONS.get(item.get('statut'), '❓')
                    print(f"  {icon} [{item.get('criticite', 'INFO')}] {item.get('message', 'Détail non disponible.')}")
        elif isinstance(data, dict) and 'statut' in data:
             icon = STATUS_ICONS.get(data.get('statut'), '❓')
             print(f"  {icon} [{data.get('criticite', 'INFO')}] {data.get('message', 'Détail non disponible.')}")


# --- Main Application Logic ---

def main():
    """
    Main function to parse arguments and run the application.
    """
    parser = argparse.ArgumentParser(description="Analyseur de sécurité de site web et outil de reporting.")

    # Primary action: running a new scan
    parser.add_argument("--domain", help="Le nom de domaine du site web à analyser (ex: google.com).")
    parser.add_argument("--formats", type=str, default="", help="Génère des rapports dans les formats spécifiés, séparés par des virgules (ex: json,html,csv).")
    parser.add_argument("--gdpr", action="store_true", help="Inclut une analyse de conformité RGPD (expérimental).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Affiche des informations détaillées pendant l'exécution.")

    # Reporting actions (from consolidator)
    reporting_group = parser.add_argument_group('Reporting', 'Actions pour analyser les scans existants')
    reporting_group.add_argument("--list-scans", metavar="DOMAIN", help="Liste tous les scans disponibles pour un domaine.")
    reporting_group.add_argument("--compare", nargs=3, metavar=("DOMAIN", "DATE1", "DATE2"), help="Compare les scans d'un domaine entre deux dates (format YYYY-MM-DD).")
    reporting_group.add_argument("--status", action="store_true", help="Affiche l'état des scans par rapport à la liste des cibles.")
    reporting_group.add_argument("--graph", metavar="DOMAIN", help="Génère un graphique d'évolution du score pour un domaine.")

    args = parser.parse_args()

    # If a domain is provided, run a new scan
    if args.domain:
        hostname = get_hostname(args.domain)
        if not check_host_exists(hostname):
            print(f"Erreur : L'hôte '{hostname}' est introuvable.", file=sys.stderr)
            sys.exit(1)

        analyzer = SecurityAnalyzer(verbose=args.verbose)
        results = analyzer.analyze(hostname, perform_gdpr_check=args.gdpr)

        print_human_readable_report(results)

        formats = [f.strip() for f in args.formats.lower().split(',') if f.strip()]
        if 'json' in formats:
            generate_json_report(results, hostname)
        if 'csv' in formats:
            generate_csv_report(results, hostname)
        if 'html' in formats:
            generate_html_report(results, hostname)

    # Handle reporting actions
    elif args.list_scans or args.compare or args.status or args.graph:
        consolidator = Consolidator(verbose=args.verbose)
        if not consolidator.all_scans:
             print("Aucun rapport de scan trouvé. Exécutez une analyse avec --domain d'abord.")
             sys.exit(1)

        if args.list_scans:
            consolidator.display_scans_for_domain(args.list_scans)
        if args.compare:
            consolidator.compare_scans(args.compare[0], args.compare[1], args.compare[2])
        if args.status:
            consolidator.display_scan_status()
        if args.graph:
            consolidator.generate_evolution_graph(args.graph)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
