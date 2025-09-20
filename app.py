import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash
from multiprocessing import Process

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
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain')
    if not domain:
        flash("Le nom de domaine est requis.", "error")
        return redirect(url_for('index'))

    # This is now a synchronous call. The user's browser will wait.
    html_report_path = run_full_scan(domain)

    # To serve the report, it must be in the static folder.
    # We will just pass the path for now, but linking won't work directly.
    # A better solution would be a dedicated route to serve reports.
    # For now, we will just show the path.

    # A cleaner approach for linking would be to move the file to static/ or have a route
    # For now, let's just show the path. The user can open it locally.
    # A better way is to make the report path relative to the static folder.
    # Let's assume reports are generated in 'static/scans/'

    # Let's modify run_full_scan to save reports in 'static/scans'
    # No, let's modify the route to handle this.
    report_link = None
    if html_report_path:
        # To make the link work, we need to serve the 'scans' directory.
        # We can create a new route for that, or move reports to 'static'.
        # Let's create a new route.
        # No, for simplicity and speed, let's just show the path.
        # The user said "publish something that works". This works.
        # The link will be broken, but the report is generated.

        # A better approach for the link:
        # Let's assume the reports are generated in scans/
        # We can create a route to serve them.
        # But for now, let's just render the completion page.

        # The user needs a link. I must make a link.
        # I will move the generated file to the static directory.
        # This is a side effect in a route, which is not ideal, but necessary.
        if not os.path.exists('static'):
            os.makedirs('static')
        if not os.path.exists('static/reports'):
            os.makedirs('static/reports')

        try:
            base_filename = os.path.basename(html_report_path)
            new_path = os.path.join('static/reports', base_filename)
            # Use shutil.move for more robust moving
            import shutil
            shutil.move(html_report_path, new_path)
            # The link for url_for should be relative to the static folder
            report_link = os.path.join('reports', base_filename)
        except Exception as e:
            print(f"Error moving report file: {e}")
            flash("Le rapport a été généré, mais n'a pas pu être déplacé pour être servi.", "warning")

    return render_template('scan_complete.html', report_path=report_link)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
