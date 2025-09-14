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

    # --- Report Structure Definition ---
    report_structure = {
        "1. Configuration du protocole et du transport": {
            "description": "Cette section vérifie la sécurité de la couche réseau et du chiffrement. 📌 Objectif : garantir que la communication est sécurisée et que les protections de base sont en place.",
            "categories": ["ssl_certificate", "tls_protocols", "http_redirect", "security_headers", "cookie_security"]
        },
        "🧠 2. Empreinte applicative et exposition CMS": {
            "description": "Cette section analyse les traces laissées par les technologies côté serveur. 📌 Objectif : identifier les technologies exposées et les risques liés à des versions vulnérables.",
            "categories": ["cms_footprint_meta", "cms_footprint_paths", "js_libraries"]
        },
        "🌐 3. Infrastructure DNS et identité du domaine": {
            "description": "Cette section couvre la configuration DNS et les informations WHOIS. 📌 Objectif : vérifier la légitimité du domaine, la protection contre l’usurpation, et la configuration des serveurs.",
            "categories": ["dns_records", "whois_info"]
        },
        "📈 4. Score et indicateurs complémentaires": {
            "description": "Cette section regroupe les métriques globales ou spécifiques. 📌 Objectif : fournir une synthèse ou un indicateur complémentaire.",
            "categories": ["parking_score"]
        }
    }

    # --- Start of HTML content ---
    # Using a standard string and .format() to avoid f-string parsing issues with CSS
    html_head = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport de Sécurité - {hostname}</title>
        <style>
            :root {{
                --color-primary: #00A8C6;
                --color-secondary: #40C0CB;
                --color-background: #f0f4f8;
                --color-card: #ffffff;
                --color-text: #333333;
                --color-text-light: #777777;
                --color-success: #28a745;
                --color-warning: #ffc107;
                --color-error: #dc3545;
                --color-medium: #fd7e14;
                --color-border: #e0e0e0;
            }}
            @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');
            body {{
                font-family: 'Roboto', sans-serif;
                margin: 0;
                padding: 2em;
                background-color: var(--color-background);
                color: var(--color-text);
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            .report-header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 2em;
                padding-bottom: 1.5em;
                margin-bottom: 2em;
                border-bottom: 3px solid var(--color-primary);
            }}
            .header-main {{ flex: 2; }}
            .header-main h1 {{
                margin: 0 0 0.2em 0;
                font-size: 2.5em;
                color: var(--color-primary);
            }}
            .score-card {{
                background: var(--color-card);
                border-radius: 12px;
                padding: 1.5em;
                text-align: center;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                border-left: 8px solid var(--color-secondary);
            }}
            .score-card h2 {{
                margin: 0;
                font-size: 2.2em;
                color: var(--color-text);
            }}
            .score-card .grade {{
                font-size: 1.5em;
                font-weight: 500;
                color: var(--color-text-light);
            }}
            .header-sidebar {{
                flex: 1;
                max-width: 300px;
            }}
            .grading-table table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 0.9em;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            }}
            .grading-table th, .grading-table td {{
                border: 1px solid var(--color-border);
                padding: 0.6em;
                text-align: center;
            }}
            .grading-table th {{
                background-color: var(--color-secondary);
                color: white;
                font-weight: 500;
            }}
            .grading-table h3 {{
                margin-top: 0;
                text-align: center;
                color: var(--color-primary);
            }}
            .report-grid {{
                display: flex;
                flex-direction: column;
                gap: 1.5em;
            }}
            .card {{
                background: var(--color-card);
                border-radius: 8px;
                padding: 1.5em;
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                display: flex;
                flex-direction: column;
            }}
            .group-description {{
                font-style: italic;
                color: var(--color-text-light);
                margin-bottom: 1.5em;
                padding-bottom: 1em;
                border-bottom: 1px solid var(--color-border);
            }}
            .category-subsection {{
                padding: 1em;
                margin-top: 1em;
                border-radius: 6px;
                border: 1px solid #f0f0f0;
                background-color: #fcfcfc;
            }}
            .category-subsection h4 {{
                margin: 0 0 0.8em 0;
                color: var(--color-primary);
                font-size: 1.1em;
                border-bottom: 2px solid var(--color-secondary);
                padding-bottom: 0.4em;
            }}
            .card-header {{
                display: flex;
                align-items: center;
                gap: 0.8em;
                margin-bottom: 1em;
                border-bottom: 1px solid var(--color-border);
                padding-bottom: 0.8em;
            }}
            .card-header .icon {{
                width: 32px;
                height: 32px;
                fill: var(--color-primary);
            }}
            .card-header h3 {{
                margin: 0;
                font-size: 1.4em;
                color: var(--color-text);
            }}
            .card-content p {{
                margin: 0 0 1em 0;
                color: var(--color-text-light);
                line-height: 1.6;
            }}
            .card-content ul {{
                list-style: none;
                padding: 0;
                margin: 0;
            }}
            .card-content li {{
                display: flex;
                align-items: flex-start;
                gap: 0.7em;
                margin-bottom: 0.8em;
            }}
            .status-icon {{
                width: 20px;
                height: 20px;
                flex-shrink: 0;
                margin-top: 2px;
            }}
            .status-icon.success {{ fill: var(--color-success); }}
            .status-icon.warning {{ fill: var(--color-warning); }}
            .status-icon.error {{ fill: var(--color-error); }}
            .status-icon.medium {{ fill: var(--color-medium); }}
            .status-SUCCESS {{ color: var(--color-success); font-weight: 500; }}
            .status-WARNING {{ color: var(--color-warning); font-weight: 500; }}
            .status-ERROR {{ color: var(--color-error); font-weight: 500; }}
            .status-MEDIUM {{ color: var(--color-medium); font-weight: 500; }}
            .tls-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 1em;
                font-size: 0.95em;
            }}
            .tls-table th, .tls-table td {{
                padding: 0.5em;
                text-align: left;
                border-bottom: 1px solid var(--color-border);
            }}
            .tls-table th {{ font-weight: 500; }}
            .dns-list strong {{ color: var(--color-primary); }}
        </style>
    </head>
    <body>
        <div id="svg-defs" style="display: none;">
            <svg id="icon-lock" viewBox="0 0 24 24"><path d="M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V9c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6z"/></svg>
            <svg id="icon-code" viewBox="0 0 24 24"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>
            <svg id="icon-dns" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1h-2v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 3.88-2.62 7.16-6.1 7.92z"/></svg>
            <svg id="icon-chart" viewBox="0 0 24 24"><path d="M3.5 18.49l6-6.01 4 4L22 6.92l-1.41-1.41-7.09 7.97-4-4L2 16.99z"/></svg>
            <svg id="icon-success" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
            <svg id="icon-error" viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
            <svg id="icon-warning" viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
        </div>
        <div class="container">
    """

    html_header = f"""
            <header class="report-header">
                <div class="header-main">
                    <h1>Analyse de Sécurité</h1>
                    <div class="score-card">
                        <h2>Score de Dangerosité : {score} <span class="grade">(Note: {grade})</span></h2>
                    </div>
                </div>
                <div class="header-sidebar">
                    <div class='grading-table'>
                        <h3>Légende des Notes</h3>
                        <table>
                            <tr><th>Note</th><th>Score</th><th>Niveau</th></tr>
                            <tr><td>A</td><td>90-100</td><td style="color:var(--color-success);">Excellent</td></tr>
                            <tr><td>B</td><td>80-89</td><td style="color:#007bff;">Bon</td></tr>
                            <tr><td>C</td><td>70-79</td><td style="color:var(--color-warning);">Moyen</td></tr>
                            <tr><td>D</td><td>60-69</td><td style="color:var(--color-medium);">Passable</td></tr>
                            <tr><td>F</td><td>0-59</td><td style="color:var(--color-error);">Insuffisant</td></tr>
                        </table>
                    </div>
                </div>
            </header>
    """
    html_content = html_head.format(hostname=hostname) + html_header

    rendered_categories = set()

    title_map = {
        "ssl_certificate": "Certificat SSL/TLS",
        "tls_protocols": "Protocoles TLS",
        "http_redirect": "Redirection HTTP",
        "security_headers": "En-têtes de sécurité",
        "cookie_security": "Sécurité des Cookies",
        "cms_footprint_meta": "Empreinte CMS (Meta)",
        "cms_footprint_paths": "Empreinte CMS (Chemins)",
        "js_libraries": "Librairies Javascript",
        "dns_records": "Enregistrements DNS",
        "whois_info": "Informations Whois",
        "parking_score": "Score de Parking"
    }

    icon_map = {
        "ssl_certificate": "icon-lock", "tls_protocols": "icon-lock", "http_redirect": "icon-lock",
        "security_headers": "icon-lock", "cookie_security": "icon-lock",
        "cms_footprint_meta": "icon-code", "cms_footprint_paths": "icon-code", "js_libraries": "icon-code",
        "dns_records": "icon-dns", "whois_info": "icon-dns",
        "parking_score": "icon-chart"
    }

    def get_status_icon(status, criticite=None):
        if criticite == 'MEDIUM':
            return '<svg class="status-icon medium"><use href="#icon-warning"></use></svg>'
        if status == 'SUCCESS':
            return '<svg class="status-icon success"><use href="#icon-success"></use></svg>'
        if status == 'ERROR':
            return '<svg class="status-icon error"><use href="#icon-error"></use></svg>'
        if status == 'WARNING':
            return '<svg class="status-icon warning"><use href="#icon-warning"></use></svg>'
        return ''

    def render_category_content(category, data):
        content = "<ul>"
        if category == 'ssl_certificate' and isinstance(data, dict):
            status_icon = get_status_icon(data.get('statut'))
            content += f"<li>{status_icon}<div><strong>Statut global :</strong> <span class='status-{data.get('statut')}'>{data.get('message', 'N/A')}</span></div></li>"
            if data.get('points_a_corriger'):
                for point in data['points_a_corriger']:
                    point_icon = get_status_icon(point.get('statut', 'WARNING'), point.get('criticite'))
                    content += f"<li>{point_icon}<div><strong class='status-{point.get('criticite')}'>[{point.get('criticite')}]</strong> {point.get('message')}</div></li>"

        elif category == 'tls_protocols' and isinstance(data, list):
            content += "</ul><table class='tls-table'><tr><th>Protocole</th><th>Statut</th></tr>"
            for item in data:
                icon = get_status_icon(item.get('statut'))
                content += f"<tr><td>{item.get('protocole')}</td><td>{icon} <span class='status-{item.get('statut')}'>{item.get('message')}</span></td></tr>"
            content += "</table><ul>" # Re-open UL for consistency if needed later

        elif category == 'dns_records' and isinstance(data, dict):
             content += "</ul><div class='dns-list'>"
             for record_type, record_data in data.items():
                valeurs = record_data.get('valeurs') or [record_data.get('valeur')]
                message = record_data.get('message', ', '.join(filter(None, valeurs)))
                content += f"<p><strong>{record_type.upper()}:</strong> {message}</p>"
             content += "</div><ul>"

        elif category == 'whois_info' and isinstance(data, dict):
            content += "</ul><div class='dns-list'>"
            for key, value in data.items():
                 if key not in ['statut', 'criticite']:
                    content += f"<p><strong>{key.replace('_', ' ').title()}:</strong> {value}</p>"
            content += "</div><ul>"

        elif isinstance(data, dict) and 'statut' in data:
            status_icon = get_status_icon(data.get('statut'), data.get('criticite'))
            content += f"<li>{status_icon}<div><span class='status-{data.get('statut')}'>Analyse {data.get('statut').lower()}e</span> (problème identifié).</div></li>"

        elif isinstance(data, list):
            for item in data:
                 if isinstance(item, dict) and 'statut' in item:
                    item_icon = get_status_icon(item.get('statut'), item.get('criticite'))
                    msg = item.get('message', f"Analyse {item.get('statut').lower()}e")
                    content += f"<li>{item_icon}<div>{msg}</div></li>"

        else:
            content += f"<li><pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre></li>"

        content += "</ul>"
        return content

    # --- Render structured groups into cards ---
    main_report_content = "<main class='report-grid'>"

    group_icon_map = {
        "1. Configuration du protocole et du transport": "icon-lock",
        "🧠 2. Empreinte applicative et exposition CMS": "icon-code",
        "🌐 3. Infrastructure DNS et identité du domaine": "icon-dns",
        "📈 4. Score et indicateurs complémentaires": "icon-chart"
    }

    for group_title, group_data in report_structure.items():
        group_content = ""
        # Check if any category in this group has results
        has_content = any(cat in results for cat in group_data['categories'])

        if not has_content:
            continue

        for category in group_data['categories']:
            if category in results:
                title = title_map.get(category, category.replace('_', ' ').title())
                group_content += f"<div class='category-subsection'>"
                group_content += f"<h4>{title}</h4>"
                group_content += render_category_content(category, results[category])
                group_content += "</div>"
                rendered_categories.add(category)

        if group_content:
            icon_id = group_icon_map.get(group_title, "icon-chart")
            main_report_content += f"""
            <div class='card'>
                <div class='card-header'>
                    <svg class="icon"><use href="#{icon_id}"></use></svg>
                    <h3>{group_title.split('. ')[1]}</h3>
                </div>
                <div class='card-content'>
                    <p class='group-description'>{group_data['description']}</p>
                    {group_content}
                </div>
            </div>
            """

    # --- Render remaining categories that were not in any group ---
    # This part can be refactored or removed if all categories are in the structure
    other_categories_content = ""
    for category, data in results.items():
        if category not in rendered_categories and category not in ['hostname', 'score_final', 'note']:
            title = title_map.get(category, category.replace('_', ' ').title())
            icon_id = icon_map.get(category, "icon-chart")
            content = render_category_content(category, data)

            other_categories_content += f"""
            <div class='card'>
                <div class='card-header'>
                    <svg class="icon"><use href="#{icon_id}"></use></svg>
                    <h3>{title} (Non groupé)</h3>
                </div>
                <div class='card-content'>{content}</div>
            </div>
            """

    if other_categories_content:
        main_report_content += other_categories_content

    main_report_content += "</main>"
    html_content += main_report_content
    html_content += "</div></body></html>"

    # --- Write to file ---
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"\n✅ Rapport HTML généré avec succès : {filename}")
    except IOError as e:
        print(f"\n❌ Erreur lors de l'écriture du rapport HTML : {e}")
