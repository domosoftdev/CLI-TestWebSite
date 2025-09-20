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

from src.reporters import generate_json_report, generate_csv_report, generate_html_report

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
            # Main status
            icon = STATUS_ICONS.get(data.get('statut'), '❓')
            print(f"  {icon} [{data.get('criticite', 'INFO')}] {data.get('message')}")

            # Points to correct
            if data.get('points_a_corriger'):
                print("    - Points à corriger :")
                for point in data['points_a_corriger']:
                    icon = STATUS_ICONS.get(point.get('statut', '❓'), '❓')
                    print(f"      {icon} [{point.get('criticite')}] {point.get('message')}")

            # Details section
            if data.get('details'):
                print("    - Détails techniques :")
                details = data['details']
                detail_items = {
                    "Expire dans": f"{details.get('jours_restants')} jours",
                    "Force de la clé": details.get('force_cle_publique'),
                    "Algorithme de signature": details.get('algorithme_signature'),
                }
                for label, value in detail_items.items():
                    if value: print(f"      - {label} : {value}")

                if 'noms_alternatifs_sujet (SAN)' in details:
                    print("      - Noms alternatifs (SAN) :")
                    for name in details['noms_alternatifs_sujet (SAN)']:
                        print(f"        - {name}")

                if 'chaine_de_certificats' in details:
                    print("      - Chaîne de confiance :")
                    for i, cert_subject in enumerate(details['chaine_de_certificats']):
                        print(f"        {i}: {cert_subject}")

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
