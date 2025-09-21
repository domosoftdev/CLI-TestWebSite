# -*- coding: utf-8 -*-
import argparse
import sys
from src.core.consolidator import Consolidator
from src.scanner import run_full_scan

def main():
    """
    Main function to parse arguments and run the application.
    """
    parser = argparse.ArgumentParser(description="Analyseur de sécurité de site web et outil de reporting.")
    parser.add_argument("--domain", help="Le nom de domaine du site web à analyser (ex: google.com).")
    parser.add_argument("--formats", type=str, default="html,json,csv", help="Formats de rapport, séparés par des virgules (défaut: html,json,csv).")
    parser.add_argument("--scans-dir", default="scans", help="Le répertoire pour lire et sauvegarder les rapports de scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Affiche des informations détaillées pendant l'exécution.")

    reporting_group = parser.add_argument_group('Reporting', 'Actions pour analyser les scans existants')
    reporting_group.add_argument("--list-scans", metavar="DOMAIN", help="Liste tous les scans disponibles pour un domaine.")
    reporting_group.add_argument("--compare", nargs=3, metavar=("DOMAIN", "DATE1", "DATE2"), help="Compare les scans d'un domaine entre deux dates (format YYYY-MM-DD).")
    reporting_group.add_argument("--status", action="store_true", help="Affiche l'état des scans par rapport à la liste des cibles.")
    reporting_group.add_argument("--graph", metavar="DOMAIN", help="Génère un graphique d'évolution du score pour un domaine.")

    args = parser.parse_args()

    if args.domain:
        run_full_scan(args.domain, args.scans_dir, args.verbose, args.formats)
    elif args.list_scans or args.compare or args.status or args.graph:
        consolidator = Consolidator(scans_dir=args.scans_dir, verbose=False)
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
