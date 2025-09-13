# -*- coding: utf-8 -*-

"""
Outil de consolidation et d'analyse pour les rapports de sécurité JSON.
"""

import json
import os
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt

from src.config import (
    SCAN_REPORTS_DIR,
    REMEDIATION_ADVICE,
    SUPPORTED_REPORTS,
    QUICK_WIN_REMEDIATION_IDS,
    TARGETS_FILE,
    SUMMARY_REPORT_HTML_FILE,
    EVOLUTION_GRAPH_FILE_FORMAT
)

class Consolidator:
    """
    Gère le chargement, l'analyse et la présentation des résultats de scan.
    """
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.all_scans = self._load_scan_results()
        if self.verbose:
            print(f"Consolidator initialisé, {len(self.all_scans)} rapport(s) chargé(s).")

    def _load_scan_results(self):
        """
        Charge tous les rapports de scan JSON depuis le répertoire configuré.
        """
        if not os.path.exists(SCAN_REPORTS_DIR):
            if self.verbose:
                print(f"Le répertoire des scans '{SCAN_REPORTS_DIR}' n'existe pas.")
            return []

        scan_files = [f for f in os.listdir(SCAN_REPORTS_DIR) if f.endswith('.json')]
        results = []
        for filename in scan_files:
            try:
                parts = filename.replace('.json', '').split('_')
                domain = "_".join(parts[:-1])
                date_str = parts[-1]
                scan_date = datetime.strptime(date_str, '%d%m%y')
                filepath = os.path.join(SCAN_REPORTS_DIR, filename)
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                results.append({"domain": domain, "date": scan_date, "data": data})
            except (IndexError, ValueError, json.JSONDecodeError) as e:
                print(f"Avertissement : Impossible de parser le fichier '{filename}'. Erreur: {e}")
                continue

        results.sort(key=lambda x: (x['domain'], x['date']), reverse=True)
        return results

    def _extract_vulnerabilities(self, scan_data):
        """Helper pour extraire un set de vulnérabilités identifiables d'un rapport."""
        vulnerabilities = set()
        def find_issues(data, path=""):
            if isinstance(data, dict):
                if 'remediation_id' in data:
                    is_successful_case = data.get('present') is True or data.get('statut') == 'SUCCESS'
                    if not is_successful_case:
                        vuln_id = f"{path}.{data['remediation_id']}"
                        vulnerabilities.add(vuln_id)
                for key, value in data.items():
                    find_issues(value, f"{path}.{key}" if path else key)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    find_issues(item, f"{path}[{i}]")
        find_issues(scan_data)
        return vulnerabilities

    def display_scans_for_domain(self, domain):
        """Affiche tous les scans disponibles pour un domaine spécifique."""
        scans_for_domain = [s for s in self.all_scans if s['domain'] == domain]
        if not scans_for_domain:
            print(f"Aucun scan trouvé pour le domaine '{domain}'.")
            return

        print(f"🔎 Scans disponibles pour '{domain}':")
        for scan in scans_for_domain:
            date_str = scan['date'].strftime('%Y-%m-%d')
            score = scan['data'].get('score_final', 'N/A')
            grade = scan['data'].get('note', 'N/A')
            print(f"  - Date: {date_str}, Score: {score}, Note: {grade}")

    def display_scan_status(self):
        """Affiche l'état des scans par rapport à la liste des cibles."""
        try:
            with open(TARGETS_FILE, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Le fichier '{TARGETS_FILE}' est introuvable. Veuillez le créer.")
            return

        scanned_domains = {s['domain'] for s in self.all_scans}
        print("📊 État des scans cibles :")
        scanned_count = 0
        for target in targets:
            if target in scanned_domains:
                print(f"  [✅] {target}")
                scanned_count += 1
            else:
                print(f"  [❌] {target}")
        print(f"\nTotal: {scanned_count} / {len(targets)} cibles scannées.")

    def compare_scans(self, domain, date1_str, date2_str):
        """Compare deux scans pour un domaine donné."""
        try:
            d1 = datetime.strptime(date1_str, '%Y-%m-%d').date()
            d2 = datetime.strptime(date2_str, '%Y-%m-%d').date()
        except ValueError:
            print("Erreur: Le format de la date doit être YYYY-MM-DD.")
            return

        if d1 > d2: d1, d2 = d2, d1
        scan1 = next((s for s in self.all_scans if s['domain'] == domain and s['date'].date() == d1), None)
        scan2 = next((s for s in self.all_scans if s['domain'] == domain and s['date'].date() == d2), None)

        if not scan1 or not scan2:
            print(f"Impossible de trouver les deux scans pour '{domain}' aux dates {d1} et {d2}.")
            self.display_scans_for_domain(domain)
            return

        print(f"🔄 Comparaison des scans pour '{domain}' entre {d1} et {d2}\n")
        score1 = scan1['data'].get('score_final', 0)
        score2 = scan2['data'].get('score_final', 0)
        print(f"Score: {score1} (à {d1}) -> {score2} (à {d2})")
        if score2 < score1: print(f"  -> ✅ Amélioration du score de {score1 - score2} points.")
        elif score2 > score1: print(f"  -> ⚠️ Dégradation du score de {score2 - score1} points.")
        else: print("  -> 😐 Score inchangé.")

        vulns1 = self._extract_vulnerabilities(scan1['data'])
        vulns2 = self._extract_vulnerabilities(scan2['data'])
        fixed_vulns = vulns1 - vulns2
        new_vulns = vulns2 - vulns1

        print("\n--- Changements des vulnérabilités ---")
        if fixed_vulns:
            print("\n[✅ VULNÉRABILITÉS CORRIGÉES]")
            for v in sorted(list(fixed_vulns)): print(f"  - {v}")
        if new_vulns:
            print("\n[❌ NOUVELLES VULNÉRABILITÉS]")
            for v in sorted(list(new_vulns)): print(f"  - {v}")
        if not fixed_vulns and not new_vulns:
            print("\n[😐] Aucune nouvelle vulnérabilité détectée et aucune n'a été corrigée.")

    def generate_evolution_graph(self, domain):
        """Génère un graphique d'évolution du score pour un domaine spécifique."""
        scans_for_domain = sorted([s for s in self.all_scans if s['domain'] == domain], key=lambda x: x['date'])
        if len(scans_for_domain) < 2:
            print(f"Moins de deux scans trouvés pour '{domain}'. Impossible de générer un graphique.")
            return

        dates = [s['date'] for s in scans_for_domain]
        scores = [s['data'].get('score_final', 0) for s in scans_for_domain]
        plt.figure(figsize=(10, 6))
        plt.plot(dates, scores, marker='o', linestyle='-', color='b')
        plt.title(f"Évolution du Score de Sécurité pour {domain}")
        plt.xlabel("Date du Scan")
        plt.ylabel("Score de Dangerosité (plus bas = mieux)")
        plt.grid(True, which='both', linestyle='--', linewidth=0.5)
        plt.ylim(bottom=0, top=max(scores) + 10)
        plt.gcf().autofmt_xdate()

        filename = EVOLUTION_GRAPH_FILE_FORMAT.format(domain=domain)
        try:
            plt.savefig(filename, bbox_inches='tight')
            print(f"✅ Graphique d'évolution '{filename}' généré avec succès.")
        except IOError as e:
            print(f"❌ Erreur lors de la sauvegarde du graphique : {e}")
        plt.close()
