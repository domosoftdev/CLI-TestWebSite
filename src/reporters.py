# -*- coding: utf-8 -*-

"""
This module contains functions for generating reports in various formats.
"""

import os
import json
import csv
import copy
from datetime import datetime

def generate_json_report(results, hostname, output_dir="."):
    """Generates a JSON report from the analysis results."""
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.json")

    # Deep copy to avoid modifying the original results dictionary in memory
    results_to_report = copy.deepcopy(results)

    # Transform tls_protocols into a more compact, "horizontal" format
    if 'tls_protocols' in results_to_report and isinstance(results_to_report['tls_protocols'], list):
        transformed_protocols = {
            item.get('protocole', 'N/A'): item.get('message', 'N/A')
            for item in results_to_report['tls_protocols']
        }
        results_to_report['tls_protocols'] = transformed_protocols

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_to_report, f, indent=4, ensure_ascii=False)
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

    # Helper to get status color
    def get_status_color(status):
        return {"ERROR": "red", "WARNING": "orange", "SUCCESS": "green", "INFO": "blue"}.get(status, "black")

    # --- Start of HTML content ---
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport de Sécurité - {hostname}</title>
        <style>
            body {{ font-family: sans-serif; margin: 2em; }}
            h1, h2, h3 {{ color: #333; }}
            .report-section {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .status-ERROR {{ color: red; font-weight: bold; }}
            .status-WARNING {{ color: orange; font-weight: bold; }}
            .status-SUCCESS {{ color: green; }}
            .status-INFO {{ color: blue; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            ul {{ list-style-type: square; padding-left: 20px; }}
        </style>
    </head>
    <body>
        <h1>Rapport d'Analyse de Sécurité pour {hostname}</h1>
        <h2>Score de Dangerosité : {score} (Note: {grade})</h2>
    """

    # --- Loop through results ---
    for category, data in results.items():
        if category in ['hostname', 'score_final', 'note']:
            continue

        html_content += f"<div class='report-section'><h2>{category.replace('_', ' ').title()}</h2>"

        # --- Specific Handlers for each category ---

        if category == 'ssl_certificate' and isinstance(data, dict):
            status_class = data.get('statut', 'INFO')
            html_content += f"<p class='status-{status_class}'><strong>Statut global :</strong> {data.get('message', 'N/A')}</p>"
            if data.get('points_a_corriger'):
                html_content += "<strong>Points à corriger :</strong><ul>"
                for point in data['points_a_corriger']:
                    html_content += f"<li><strong class='status-{point.get('criticite')}'>[{point.get('criticite')}]</strong>: {point.get('message')}</li>"
                html_content += "</ul>"
            if data.get('details'):
                html_content += "<strong>Détails techniques :</strong><ul>"
                for key, value in data['details'].items():
                    html_content += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
                html_content += "</ul>"

        elif category == 'tls_protocols' and isinstance(data, list):
            html_content += "<table><tr><th>Protocole</th><th>Statut</th><th>Message</th></tr>"
            for item in data:
                status_class = item.get('statut', 'INFO')
                html_content += f"<tr><td>{item.get('protocole')}</td><td class='status-{status_class}'>{item.get('statut')}</td><td>{item.get('message')}</td></tr>"
            html_content += "</table>"

        elif category == 'dns_records' and isinstance(data, dict):
            html_content += "<ul>"
            for record_type, record_data in data.items():
                status_class = record_data.get('statut', 'INFO')
                valeurs = record_data.get('valeurs') or [record_data.get('valeur')]
                message = record_data.get('message', ', '.join(filter(None, valeurs)))
                html_content += f"<li><strong>{record_type.upper()}:</strong> <span class='status-{status_class}'>[{record_data.get('criticite', 'N/A')}]</span> {message}</li>"
            html_content += "</ul>"

        elif category == 'whois_info' and isinstance(data, dict):
            html_content += "<ul>"
            for key, value in data.items():
                 if key not in ['statut', 'criticite']:
                    html_content += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
            html_content += "</ul>"

        elif isinstance(data, dict) and 'statut' in data:
            status_class = data.get('statut', 'INFO')
            html_content += f"<p class='status-{status_class}'><strong>[{data.get('criticite')}]</strong> {data.get('message')}</p>"

        elif isinstance(data, list) and data and isinstance(data[0], dict) and 'statut' in data[0]:
             for item in data:
                status_class = item.get('statut', 'INFO')
                html_content += f"<p class='status-{status_class}'><strong>[{item.get('criticite')}]</strong> {item.get('message')}</p>"

        else:
            # Fallback for any other structure
            html_content += f"<pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>"

        html_content += "</div>"

    html_content += "</body></html>"

    # --- Write to file ---
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"\n✅ Rapport HTML généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport HTML : {e}")
