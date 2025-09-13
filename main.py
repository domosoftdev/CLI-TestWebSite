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
import os
import warnings
from datetime import datetime

# Suppress the specific CryptographyDeprecationWarning
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass  # If cryptography is not installed, we don't need to do anything

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

def generate_json_report(results, hostname, output_dir="."):
    """Generates a JSON report from the analysis results."""
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.json")
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n✅ Rapport JSON généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport JSON : {e}")

def generate_csv_report(results, hostname, output_dir="."):
    """Generates a CSV report from the analysis results."""
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.csv")
    header = ['Catégorie', 'Sous-catégorie', 'Statut', 'Criticité', 'Description', 'Chaine de Certificat', 'Vulnérabilités']
    rows = []

    # Special handling for SSL certificate
    ssl_res = results.get('ssl_certificate')
    if ssl_res:
        chain_str = ""
        if ssl_res.get('certificate_chain'):
            chain_str = " -> ".join(ssl_res['certificate_chain'])

        rows.append({
            'Catégorie': 'Ssl Certificate',
            'Sous-catégorie': ssl_res.get('sujet', 'N/A'),
            'Statut': ssl_res.get('statut'),
            'Criticité': ssl_res.get('criticite'),
            'Description': ssl_res.get('message'),
            'Chaine de Certificat': chain_str,
            'Vulnérabilités': "" # Not applicable for the main cert check
        })

    # Helper to flatten other nested result dictionaries
    def flatten_data(category, sub_category, data):
        if isinstance(data, list):
            for item in data:
                flatten_data(category, sub_category, item)
        elif isinstance(data, dict):
            if 'statut' in data and data['statut'] in ['ERROR', 'WARNING']:
                vuln_ids = ", ".join([v.get('id', '') for v in data.get('vulnerabilities', [])])
                rows.append({
                    'Catégorie': category,
                    'Sous-catégorie': data.get('protocole') or data.get('nom') or data.get('bibliotheque') or sub_category,
                    'Statut': data.get('statut'),
                    'Criticité': data.get('criticite'),
                    'Description': data.get('message') or f"Version: {data.get('version_detectee')} (Dernière: {data.get('derniere_version')})",
                    'Chaine de Certificat': '', # Not applicable for other checks
                    'Vulnérabilités': vuln_ids
                })

    for key, res in results.items():
        # Skip keys already handled or not for reporting
        if key in ['hostname', 'score_final', 'note', 'ssl_certificate']:
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

def generate_html_report(results, hostname, output_dir="."):
    """Generates an HTML report from the analysis results."""
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.html")
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

        # Special handling for SSL Certificate to show details
        if category == 'ssl_certificate' and isinstance(data, dict):
            status_class = data.get('statut', 'INFO').lower()
            html_content += f"<p class='{status_class}'><strong>Status:</strong> {data.get('statut', 'N/A')}</p>"
            html_content += f"<p><strong>Message:</strong> {data.get('message', 'N/A')}</p>"
            if 'jours_restants' in data:
                html_content += f"<p><strong>Jours Restants:</strong> {data['jours_restants']}</p>"
            if 'certificate_chain' in data:
                html_content += "<strong>Chaîne de confiance:</strong><ul>"
                for cert_subject in data['certificate_chain']:
                    html_content += f"<li>{cert_subject}</li>"
                html_content += "</ul>"
        else:
            # Fallback to JSON for other categories
            html_content += f"<pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>"

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

        # Special handling for SSL Certificate to show details
        if category == 'ssl_certificate' and isinstance(data, dict):
            icon = STATUS_ICONS.get(data.get('statut'), '❓')
            print(f"  {icon} [{data.get('criticite', 'INFO')}] {data.get('message', 'Détail non disponible.')}")
            if 'jours_restants' in data:
                print(f"    - Expire dans : {data['jours_restants']} jours")
            if 'certificate_chain' in data:
                print("    - Chaîne de confiance :")
                for i, cert_subject in enumerate(data['certificate_chain']):
                    print(f"      {i}: {cert_subject}")

        elif isinstance(data, list):
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
    parser.add_argument("--scans-dir", default="scans", help="Le répertoire pour lire et sauvegarder les rapports de scan.")
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
            generate_json_report(results, hostname, args.scans_dir)
        if 'csv' in formats:
            generate_csv_report(results, hostname, args.scans_dir)
        if 'html' in formats:
            generate_html_report(results, hostname, args.scans_dir)

    # Handle reporting actions
    elif args.list_scans or args.compare or args.status or args.graph:
        consolidator = Consolidator(scans_dir=args.scans_dir, verbose=args.verbose)
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
            consolidator.generate_evolution_graph(args.graph, output_dir=args.scans_dir)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
