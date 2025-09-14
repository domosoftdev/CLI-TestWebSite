# -*- coding: utf-8 -*-

"""
This module contains functions for generating reports in various formats.
"""

import os
import json
import csv
from datetime import datetime

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
    header = ['Catégorie', 'Sous-catégorie', 'Statut', 'Criticité', 'Description', 'Vulnérabilités']
    rows = []

    # Helper to flatten the nested result dictionaries
    def flatten_data(category, sub_category, data):
        # Special handling for the new SSL structure
        if category.lower() == 'ssl certificate':
            if data.get('points_a_corriger'):
                for point in data['points_a_corriger']:
                    rows.append({
                        'Catégorie': category,
                        'Sous-catégorie': 'Certificat SSL/TLS',
                        'Statut': 'WARNING' if point.get('criticite') == 'MEDIUM' else 'ERROR',
                        'Criticité': point.get('criticite'),
                        'Description': point.get('message'),
                        'Vulnérabilités': ''
                    })
            return # Stop processing this category further

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
                    'Vulnérabilités': vuln_ids
                })

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

def generate_html_report(results, hostname, output_dir="."):
    """Generates an HTML report from the analysis results."""
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.html")
    score = results.get('score_final', 0)
    grade = results.get('note', 'N/A')

    html_content = f"<!DOCTYPE html><html><head><title>Rapport de Sécurité - {hostname}</title></head><body>"
    html_content += f"<h1>Rapport d'Analyse de Sécurité pour {hostname}</h1>"
    html_content += f"<h2>Score de Dangerosité : {score} (Note: {grade})</h2>"

    for category, data in results.items():
        if category in ['hostname', 'score_final', 'note']:
            continue
        html_content += f"<div><h2>{category.replace('_', ' ').title()}</h2>"

        if category == 'ssl_certificate' and isinstance(data, dict):
            status_class = data.get('statut', 'INFO').lower()
            html_content += f"<p class='{status_class}'><strong>Statut global :</strong> {data.get('statut', 'N/A')} ({data.get('message', 'N/A')})</p>"

            if data.get('points_a_corriger'):
                html_content += "<strong>Points à corriger :</strong><ul>"
                for point in data['points_a_corriger']:
                    html_content += f"<li><strong>[{point.get('criticite')}]</strong>: {point.get('message')}</li>"
                html_content += "</ul>"

            if data.get('details'):
                details = data['details']
                html_content += "<strong>Détails techniques :</strong><ul>"
                detail_items = {
                    "Expire dans": f"{details.get('jours_restants')} jours",
                    "Force de la clé": details.get('force_cle_publique'),
                    "Algorithme de signature": details.get('algorithme_signature'),
                }
                for label, value in detail_items.items():
                    if value: html_content += f"<li><strong>{label}:</strong> {value}</li>"

                if 'noms_alternatifs_sujet (SAN)' in details:
                    html_content += "<li><strong>Noms alternatifs (SAN):</strong><ul>"
                    for name in details['noms_alternatifs_sujet (SAN)']:
                        html_content += f"<li>{name}</li>"
                    html_content += "</ul></li>"

                if 'chaine_de_certificats' in details:
                    html_content += "<li><strong>Chaîne de confiance:</strong><ul>"
                    for cert_subject in details['chaine_de_certificats']:
                        html_content += f"<li>{cert_subject}</li>"
                    html_content += "</ul></li>"
                html_content += "</ul>"
        else:
            html_content += f"<pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>"

        html_content += "</div>"

    html_content += "</body></html>"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"\n✅ Rapport HTML généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport HTML : {e}")
