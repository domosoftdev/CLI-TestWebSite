# -*- coding: utf-8 -*-
import os
import json
import csv
import copy
from datetime import datetime

def generate_json_report(results, hostname, output_dir="."):
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
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.csv")
    header = ['Catégorie', 'Sous-catégorie', 'Statut', 'Criticité', 'Description', 'Vulnérabilités']
    rows = []
    def flatten_data(category, sub_category, data):
        if category.lower() == 'ssl certificate':
            if data.get('points_a_corriger'):
                for point in data['points_a_corriger']:
                    rows.append({'Catégorie': category, 'Sous-catégorie': 'Certificat SSL/TLS', 'Statut': 'WARNING' if point.get('criticite') == 'MEDIUM' else 'ERROR', 'Criticité': point.get('criticite'), 'Description': point.get('message'), 'Vulnérabilités': ''})
            return
        if isinstance(data, list):
            for item in data:
                flatten_data(category, sub_category, item)
        elif isinstance(data, dict):
            if 'statut' in data and data['statut'] in ['ERROR', 'WARNING']:
                vuln_ids = ", ".join([v.get('id', '') for v in data.get('vulnerabilities', [])])
                rows.append({'Catégorie': category, 'Sous-catégorie': data.get('protocole') or data.get('nom') or data.get('bibliotheque') or sub_category, 'Statut': data.get('statut'), 'Criticité': data.get('criticite'), 'Description': data.get('message') or f"Version: {data.get('version_detectee')} (Dernière: {data.get('derniere_version')})", 'Vulnérabilités': vuln_ids})
    for key, res in results.items():
        if key in ['hostname', 'score_final', 'note']: continue
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
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.html")
    score = results.get('score_final', 0)
    grade = results.get('note', 'N/A')
    report_structure = {
        "1. Configuration du protocole et du transport": {"description": "Cette section vérifie la sécurité de la couche réseau et du chiffrement. 📌 Objectif : garantir que la communication est sécurisée et que les protections de base sont en place.", "categories": ["ssl_certificate", "tls_protocols", "http_redirect", "security_headers", "cookie_security"]},
        "🧠 2. Empreinte applicative et exposition CMS": {"description": "Cette section analyse les traces laissées par les technologies côté serveur. 📌 Objectif : identifier les technologies exposées et les risques liés à des versions vulnérables.", "categories": ["cms_footprint_meta", "cms_footprint_paths", "js_libraries"]},
        "🌐 3. Infrastructure DNS et identité du domaine": {"description": "Cette section couvre la configuration DNS et les informations WHOIS. 📌 Objectif : vérifier la légitimité du domaine, la protection contre l’usurpation, et la configuration des serveurs.", "categories": ["dns_records", "whois_info"]},
        "📈 4. Score et indicateurs complémentaires": {"description": "Cette section regroupe les métriques globales ou spécifiques. 📌 Objectif : fournir une synthèse ou un indicateur complémentaire.", "categories": ["parking_score"]}
    }
    html_content = f'''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Rapport de Sécurité - {hostname}</title><style>
            body {{ font-family: sans-serif; margin: 2em; }} h1, h2, h3 {{ color: #333; }}
            .report-header {{ display: flex; align-items: center; gap: 2em; border-bottom: 2px solid #ccc; padding-bottom: 1em; margin-bottom: 2em; }}
            .header-main {{ flex: 3; }} .header-sidebar {{ flex: 1; }} .grading-table table {{ font-size: 0.9em; width: 100%; }} .grading-table h3 {{ margin-top: 0; }}
            .report-group {{ border: 2px solid #007bff; padding: 20px; margin-bottom: 25px; border-radius: 8px; background-color: #f8f9fa; }}
            .report-section {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; background-color: #fff;}}
            .group-description {{ font-style: italic; color: #555; margin-bottom: 20px; }}
            .status-ERROR {{ color: red; font-weight: bold; }} .status-WARNING {{ color: orange; font-weight: bold; }} .status-SUCCESS {{ color: green; }} .status-INFO {{ color: blue; }}
            table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }} th {{ background-color: #f2f2f2; }}
            ul {{ list-style-type: square; padding-left: 20px; }}
            .horizontal-list {{ list-style-type: none; padding: 0; display: flex; flex-wrap: wrap; gap: 1em; }}
            .horizontal-list li {{ background-color: #f0f0f0; padding: 5px 10px; border-radius: 5px; }}
        </style></head><body>
        <header class="report-header"><div class="header-main"><h1>Rapport d'Analyse de Sécurité pour {hostname}</h1><h2>Score de Dangerosité : {score} (Note: {grade})</h2></div>
            <div class="header-sidebar"><div class='grading-table'><h3>Légende des Notes</h3>
                <table><tr><th>Note</th><th>Score</th><th>Niveau</th></tr>
                    <tr><td>A</td><td>90-100</td><td style="color:green;">Excellent</td></tr><tr><td>B</td><td>80-89</td><td style="color:blue;">Bon</td></tr>
                    <tr><td>C</td><td>70-79</td><td style="color:orange;">Moyen</td></tr><tr><td>D</td><td>60-69</td><td style="color:darkorange;">Passable</td></tr>
                    <tr><td>F</td><td>0-59</td><td style="color:red;">Insuffisant</td></tr></table></div></div></header>'''
    rendered_categories = set()
    def render_category(category, data):
        title_map = {"ssl_certificate": "Certificat SSL/TLS", "tls_protocols": "Protocoles TLS", "http_redirect": "Redirection HTTP", "security_headers": "En-têtes de sécurité", "cookie_security": "Sécurité des cookies", "dns_records": "Enregistrements DNS", "whois_info": "Informations Whois", "cms_footprint_meta": "Détection de CMS (Méta)", "cms_footprint_paths": "Détection de CMS (Chemins)", "js_libraries": "Bibliothèques JavaScript", "parking_score": "Score de Parking"}
        title = title_map.get(category, category.replace('_', ' ').title())
        content = f"<div class='report-section'><h3>{title}</h3>"
        if category == 'ssl_certificate' and isinstance(data, dict):
            status_class = data.get('statut', 'INFO')
            content += f"<p class='status-{status_class}'><strong>Statut global :</strong> {data.get('message', 'N/A')}</p>"
            if data.get('points_a_corriger'):
                content += "<strong>Points à corriger :</strong><ul>"; [content := content + f"<li><strong class='status-{point.get('criticite')}'>[{point.get('criticite')}]</strong>: {point.get('message')}</li>" for point in data['points_a_corriger']]; content += "</ul>"
            if data.get('details'):
                content += "<strong>Détails techniques :</strong><ul>"; [content := content + f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>" for key, value in data['details'].items()]; content += "</ul>"
        elif category == 'tls_protocols' and isinstance(data, list):
            content += "<ul class='horizontal-list'>"; [content := content + f"<li><strong>{item.get('protocole')}:</strong> <span class='status-{item.get('statut', 'INFO')}'>{item.get('message')}</span></li>" for item in data]; content += "</ul>"
        elif category == 'dns_records' and isinstance(data, dict):
            content += "<ul>"; [content := content + f"<li><strong>{rt.upper()}:</strong> <span class='status-{rd.get('statut', 'INFO')}'>[{rd.get('criticite', 'N/A')}]</span> {rd.get('message', ', '.join(filter(None, rd.get('valeurs') or [rd.get('valeur')])))}</li>" for rt, rd in data.items()]; content += "</ul>"
        elif category == 'whois_info' and isinstance(data, dict):
            content += "<ul>"; [content := content + f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>" for key, value in data.items() if key not in ['statut', 'criticite']]; content += "</ul>"
        elif isinstance(data, dict) and 'statut' in data:
            content += f"<p class='status-{data.get('statut', 'INFO')}'><strong>[{data.get('criticite')}]</strong> {data.get('message')}</p>"
        elif isinstance(data, list) and data and isinstance(data[0], dict) and 'statut' in data[0]:
            for item in data: content += f"<p class='status-{item.get('statut', 'INFO')}'><strong>[{item.get('criticite')}]</strong> {item.get('message')}</p>"
        else: content += f"<pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>"
        content += "</div>"; return content
    main_report_content = ""
    for group_title, group_data in report_structure.items():
        main_report_content += f"<div class='report-group'><h2>{group_title}</h2><p class='group-description'>{group_data['description']}</p>"
        for category in group_data['categories']:
            if category in results: main_report_content += render_category(category, results[category]); rendered_categories.add(category)
        main_report_content += "</div>"
    other_categories_content = ""
    for category, data in results.items():
        if category not in rendered_categories and category not in ['hostname', 'score_final', 'note']: other_categories_content += render_category(category, data)
    if other_categories_content: main_report_content += f"<div class='report-group'><h2>Autres Analyses</h2>{other_categories_content}</div>"
    html_content += main_report_content + "</body></html>"
    try:
        with open(filename, 'w', encoding='utf-8') as f: f.write(html_content)
        print(f"\n✅ Rapport HTML généré avec succès : {filename}")
    except IOError as e: print(f"\n❌ Erreur lors de l'écriture du rapport HTML : {e}")
