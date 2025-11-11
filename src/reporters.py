# -*- coding: utf-8 -*-
import os
import json
import csv
import copy
from datetime import datetime
from .config import REMEDIATION_ADVICE

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

    def get_remediation_html(item_data):
        remediation_id = item_data.get('remediation_id')
        if remediation_id and remediation_id in REMEDIATION_ADVICE:
            advice = REMEDIATION_ADVICE[remediation_id].get('default', 'Aucun conseil disponible.')
            return f"<div class='remediation-advice'><strong>Conseil:</strong> {advice}</div>"
        return ""

    def render_ssl_certificate(data):
        rows = ""
        for point in data.get('points_a_corriger', []):
            rows += f"<tr><td>{point.get('criticite')}</td><td>{point.get('message')}</td><td>{get_remediation_html(point)}</td></tr>"

        details_html = "<h4>Détails techniques:</h4><ul>"
        if 'details' in data:
            for key, value in data['details'].items():
                if key == 'chaine_de_certificats':
                    details_html += "<li><strong>Chaîne de certificats:</strong><ul>"
                    for cert in value:
                        style = "style='background-color: #f8d7da;'" if cert.get('is_problematic') else ""
                        details_html += f"<li {style}>Sujet: {cert.get('sujet')}<br><br>Émetteur: {cert.get('emetteur')}</li>"
                    details_html += "</ul></li>"
                else:
                    details_html += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
        details_html += "</ul>"

        return rows + f"<tr><td colspan='3'>{details_html}</td></tr>"

    def render_tls_protocols(data):
        rows = ""
        for item in data:
            rows += f"<tr><td>{item.get('protocole')}</td><td>{item.get('statut')}</td><td>{item.get('message')}</td></tr>"
        return rows

    def render_dns_records(data):
        rows = ""
        for record_type, record_data in data.items():
            valeurs = record_data.get('valeurs') or [record_data.get('valeur')]
            message = record_data.get('message', ', '.join(filter(None, valeurs)))
            rows += f"<tr><td>{record_type.upper()}</td><td>{record_data.get('statut')}</td><td>{message}{get_remediation_html(record_data)}</td></tr>"
        return rows

    def render_security_headers(data):
        rows = ""
        for header, header_data in data.get('en-tetes_securite', {}).items():
            rows += f"<tr><td>{header}</td><td>{header_data.get('statut')}</td><td>{get_remediation_html(header_data)}</td></tr>"
        return rows

    def render_generic(data):
        if isinstance(data, dict) and 'statut' in data:
            return f"<tr><td>-</td><td>{data.get('statut')}</td><td>{data.get('message')}{get_remediation_html(data)}</td></tr>"
        elif isinstance(data, list):
            rows = ""
            for item in data:
                rows += f"<tr><td>-</td><td>{item.get('statut')}</td><td>{item.get('message')}{get_remediation_html(item)}</td></tr>"
            return rows
        return f"<tr><td colspan='3'>{json.dumps(data, indent=2)}</td></tr>"

    def render_category(category, data):
        title_map = {
            "ssl_certificate": "Certificat SSL/TLS",
            "tls_protocols": "Protocoles TLS",
            "http_redirect": "Redirection HTTP",
            "security_headers": "En-têtes de sécurité",
            "dns_records": "Enregistrements DNS",
        }
        title = title_map.get(category, category.replace('_', ' ').title())

        content = f"<div class='report-group'><h3>{title}</h3><table class='grading-table'><thead><tr><th>Critère</th><th>Statut</th><th>Détails</th></tr></thead><tbody>"

        if category == 'ssl_certificate':
            content += render_ssl_certificate(data)
        elif category == 'tls_protocols':
            content += render_tls_protocols(data)
        elif category == 'dns_records':
            content += render_dns_records(data)
        elif category == 'security_headers':
            content += render_security_headers(data)
        else:
            content += render_generic(data)

        content += "</tbody></table></div>"
        return content

    def render_all_categories(results):
        content = ""
        # Define the order of categories
        ordered_categories = [
            "ssl_certificate", "tls_protocols", "http_redirect", "security_headers",
            "dns_records", "cookie_security", "cms_footprint_meta", "cms_footprint_paths",
            "js_libraries", "whois_info", "parking_score", "gdpr_compliance"
        ]
        for category in ordered_categories:
            if category in results:
                content += render_category(category, results[category])
        return content

    html_content = f'''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport de Sécurité - {hostname}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            color: #333;
            line-height: 1.6;
            background-color: #f4f4f9;
        }}
        .container {{
            width: 90%;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px 0;
            text-align: center;
            margin-bottom: 30px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .report-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }}
        .report-group {{
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 20px;
            margin-bottom: 20px;
        }}
        .grading-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        .grading-table th, .grading-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        .grading-table th {{
            background-color: #f8f9fa;
        }}
        .grading-table tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .summary {{
            background-color: #e8f4fc;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .score {{
            font-size: 1.2em;
            font-weight: bold;
            color: #007bff;
        }}
        .remediation-advice {{
            background-color: #fff3cd;
            border-left: 4px solid #ffeeba;
            padding: 10px;
            margin-top: 10px;
        }}
        footer {{
            background-color: #2c3e50;
            color: white;
            text-align: center;
            padding: 10px 0;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <header>
        <h1>Rapport de Sécurité - {hostname}</h1>
    </header>
    <div class="container">
        <div class="report-header">
            <div class="header-main">
                <h2>Résumé de l'analyse</h2>
                <p>Date de l'analyse: {datetime.now().strftime('%d/%m/%Y')}</p>
            </div>
            <div class="header-sidebar">
                <div class="score">Score de sécurité : {grade}</div>
            </div>
        </div>

        {render_all_categories(results)}

    </div>
    <footer>
        <p>© {datetime.now().year} Rapport de Sécurité. Tous droits réservés.</p>
    </footer>
</body>
</html>'''

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"\n✅ Rapport HTML généré avec succès : {filename}")
        return filename
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport HTML : {e}")
        return None
