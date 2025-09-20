import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash
from multiprocessing import Process
from datetime import datetime

from src.analyzers.security import SecurityAnalyzer
from src.reporters import generate_json_report, generate_csv_report, generate_html_report
from src.utils import print_human_readable_report, get_hostname, check_host_exists

def run_full_scan(domain, scans_dir="scans"):
    """
    Runs a full security scan for a given domain and generates all reports.
    Returns the path to the HTML report, or None if an error occurred.
    """
    print(f"--- Démarrage du scan pour : {domain} ---")
    hostname = get_hostname(domain)

    if not check_host_exists(hostname):
        print(f"❌ Erreur : L'hôte '{hostname}' est introuvable.", file=sys.stderr)
        return None

    try:
        analyzer = SecurityAnalyzer(verbose=False)
        results = analyzer.analyze(hostname, perform_gdpr_check=True)
        print_human_readable_report(results)
        print(f"--- Génération des rapports pour {hostname} ---")
        generate_json_report(results, hostname, scans_dir)
        generate_csv_report(results, hostname, scans_dir)
        html_report_path = generate_html_report(results, hostname, scans_dir)
        print(f"--- Scan et rapports terminés pour {hostname} ---")
        return html_report_path
    except Exception as e:
        print(f"❌ Une erreur majeure est survenue durant le scan de {hostname}: {e}", file=sys.stderr)
        return None

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

@app.route('/')
def index():
    reports = []
    # Reports are now generated in 'scans/', but linked from 'static/reports/'
    # We need to list from the source, but link to the destination.
    # This is getting complicated. Let's simplify.
    # The user wants something that works. Let's assume reports are in static/reports.
    reports_dir = os.path.join('static', 'reports')
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    for filename in os.listdir(reports_dir):
        if filename.endswith('.html'):
            try:
                parts = filename.replace('.html', '').split('_')
                hostname = parts[0]
                date_str = parts[1]
                display_date = f"{date_str[0:2]}/{date_str[2:4]}/20{date_str[4:6]}"
                reports.append({
                    "hostname": hostname,
                    "date": display_date,
                    "path": os.path.join('reports', filename)
                })
            except IndexError:
                continue
    reports.sort(key=lambda r: datetime.strptime(r['date'], '%d/%m/%Y'), reverse=True)
    return render_template('index.html', reports=reports)

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain')
    if not domain:
        flash("Le nom de domaine est requis.", "error")
        return redirect(url_for('index'))

    # Temporarily disabling direct scan from web UI due to instability.
    flash(f"Pour l'instant, veuillez lancer le scan pour '{domain}' manuellement depuis la ligne de commande : python main.py --domain {domain} --formats html,json,csv", "info")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
