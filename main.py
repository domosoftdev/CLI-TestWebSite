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
from src.utils import get_hostname, check_host_exists, print_human_readable_report


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
        print("Lancement de scan depuis la ligne de commande est temporairement désactivé. Veuillez utiliser l'application web.")
        # The core scan logic has been moved into the web app (app.py)
        # to handle complexities with multiprocessing.
        # A future refactoring could make it available to both.

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
