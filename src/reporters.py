# -*- coding: utf-8 -*-
import os
import json
import csv
import copy
from datetime import datetime, timezone
import matplotlib.pyplot as plt
import io
import base64
from .config import REMEDIATION_ADVICE

def generate_score_pie_chart(score, grade):
    """Génère un graphique en camembert pour le score et retourne une image encodée en Base64."""
    colors = {
        'A': '#28a745', 'B': '#fd7e14', 'C': '#ffc107',
        'D': '#dc3545', 'E': '#dc3545', 'F': '#dc3545'
    }
    grade_color = colors.get(grade, '#6c757d')

    fig, ax = plt.subplots(figsize=(1, 1), dpi=100)
    ax.set_aspect('equal')

    values = [score, 100 - score]
    ax.pie(values, colors=[grade_color, '#e9ecef'], startangle=90, wedgeprops=dict(width=0.3))

    ax.text(0, 0, grade, ha='center', va='center', fontsize=20, fontweight='bold', color=grade_color)

    buf = io.BytesIO()
    fig.savefig(buf, format='png', transparent=True)
    buf.seek(0)
    plt.close(fig)

    return base64.b64encode(buf.getvalue()).decode('utf-8')

def get_critical_issues_summary(results):
    """Extrait les deux premiers problèmes critiques (statut ERROR) pour le résumé."""
    critical_issues = []

    def find_errors(data):
        if len(critical_issues) >= 2:
            return

        if isinstance(data, dict):
            if 'points_a_corriger' in data:
                for point in data['points_a_corriger']:
                    if point.get('criticite') in ['HIGH', 'CRITICAL']:
                         critical_issues.append(point.get('message'))
                         if len(critical_issues) >= 2: return
            elif data.get('statut') == 'ERROR':
                message = data.get('message')
                if message and message not in critical_issues:
                    critical_issues.append(message)

            for key, value in data.items():
                if len(critical_issues) < 2:
                    find_errors(value)

        elif isinstance(data, list):
            for item in data:
                if len(critical_issues) < 2:
                    find_errors(item)

    find_errors(results)
    return "; ".join(critical_issues)

def generate_json_report(results, hostname, output_dir="."):
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime('%d%m%y')
    filename = os.path.join(output_dir, f"{hostname}_{date_str}.json")
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n✅ Rapport JSON généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport JSON : {e}")

def generate_csv_report(results, hostname, output_dir="."):
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime('%d%m%y')
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
    date_str = datetime.now(timezone.utc).strftime('%d%m%y')
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
        # If data is not the expected dict, it's likely an error message from the scan.
        if not isinstance(data, dict) or 'details' not in data:
            return render_generic(data)

        rows = ""
        for point in data.get('points_a_corriger', []):
            rows += f"<tr><td>{point.get('criticite')}</td><td>{point.get('message')}</td><td>{get_remediation_html(point)}</td></tr>"

        details = data.get('details', {})
        crypto_details_html = "<ul>"
        if 'force_cle_publique' in details:
            crypto_details_html += f"<li><strong>Force Clé Publique:</strong> {details['force_cle_publique']}</li>"
        if 'algorithme_signature' in details:
            crypto_details_html += f"<li><strong>Algorithme Signature:</strong> {details['algorithme_signature']}</li>"
        crypto_details_html += "</ul>"

        chain_html = ""
        certs = details.get('chaine_de_certificats', [])
        if certs:
            chain_html += "<h4>Chaîne de certificats:</h4><div class='certificate-chain-container'>"
            for i, cert in enumerate(certs):
                is_problematic = cert.get('is_problematic', False)
                problem_style = "style='border-left: 4px solid #c62828;'" if is_problematic else ""
                chain_html += f"<div class='certificate-card' {problem_style}>"
                chain_html += f"<h5>Certificat #{i+1}</h5>"
                chain_html += f"<strong>Sujet:</strong> {cert.get('subject_cn', 'N/A')}<br>"
                chain_html += f"<strong>Émetteur:</strong> {cert.get('issuer_cn', 'N/A')}<br>"
                chain_html += f"<strong>Délivré le:</strong> {cert.get('issued', 'N/A')}<br>"
                chain_html += f"<strong>Expire le:</strong> {cert.get('expires', 'N/A')}<br>"
                if is_problematic:
                    chain_html += f"<div class='cert-explanation'><strong>Statut:</strong> {cert.get('explanation', '')}</div>"
                chain_html += "</div>"
            chain_html += "</div>"

        details_html = f"{crypto_details_html}{chain_html}"

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
        # If data is not the expected dict, it's likely an error message.
        if not isinstance(data, dict) or 'en-tetes_securite' not in data:
            return render_generic(data)

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

    css_content = ""
    try:
        # Build a robust path to the CSS file relative to this script's location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        css_path = os.path.join(script_dir, '..', 'static', 'style.css')
        with open(css_path, 'r', encoding='utf-8') as f:
            css_content = f.read()
    except FileNotFoundError:
        print(f"⚠️ Avertissement : Le fichier CSS n'a pas été trouvé. Le rapport ne sera pas stylisé.")

    html_content = f'''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport de Sécurité - {hostname}</title>
    <style>
        {css_content}
    </style>
</head>
<body>
    <header>
        <h1>Rapport de Sécurité - {hostname}</h1>
    </header>
    <div class="container">
        <div class="score-summary-card">
            <div class="chart">
                <img src="data:image/png;base64,{generate_score_pie_chart(score, grade)}" alt="Score: {grade}" />
            </div>
            <div class="details">
                <h2>Score global</h2>
                <div class="score-display">{grade} — {int(score)}%</div>
                <div class="issues">{get_critical_issues_summary(results)}</div>
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
