import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
import subprocess
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

@app.route('/')
def index():
    reports = []
    reports_dir = 'scans'
    if os.path.exists(reports_dir):
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
                        "path": filename
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

    # Use subprocess.Popen to run the CLI script in the background
    command = [sys.executable, 'main.py', '--domain', domain]
    print(f"--- Lancement de la commande : {' '.join(command)} ---")
    subprocess.Popen(command)

    flash(f"Le scan pour '{domain}' a été lancé en arrière-plan. La page sera rafraîchie dans quelques instants pour afficher le nouveau rapport.", "success")
    return redirect(url_for('index'))

@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory('scans', filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
