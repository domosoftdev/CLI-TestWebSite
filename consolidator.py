#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Outil de consolidation et d'analyse pour les rapports de sécurité JSON.
"""

import argparse
import json
import os
from datetime import datetime

SCAN_REPORTS_DIR = "scans/"

# Copied from security_checker.py to make the tool self-contained
REMEDIATION_ADVICE = {
    "CERT_EXPIRED": { "default": "Renouvelez votre certificat SSL/TLS immédiatement." },
    "CERT_VERIFY_FAILED": { "default": "Vérifiez que votre chaîne de certificats est complète (certificats intermédiaires) et que le certificat n'est pas auto-signé." },
    "TLS_OBSOLETE": { "description": "Désactivez les protocoles SSL/TLS obsolètes.", "nginx": "Dans votre bloc server, utilisez : ssl_protocols TLSv1.2 TLSv1.3;", "apache": "Dans votre configuration SSL, utilisez : SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", "default": "Consultez la documentation de votre serveur pour désactiver SSLv3, TLSv1.0 et TLSv1.1." },
    "NO_HTTPS_REDIRECT": { "nginx": "Dans votre bloc server pour le port 80, utilisez : return 301 https://$host$request_uri;", "apache": "Utilisez mod_rewrite pour forcer la redirection vers HTTPS.", "default": "Configurez votre serveur web pour forcer la redirection de tout le trafic HTTP vers HTTPS." },
    "DMARC_MISSING": { "default": "Ajoutez un enregistrement DMARC à votre zone DNS pour protéger contre l'usurpation d'e-mail. Exemple : 'v=DMARC1; p=none; rua=mailto:dmarc-reports@votre-domaine.com;'" },
    "SPF_MISSING": { "default": "Ajoutez un enregistrement SPF à votre zone DNS pour spécifier les serveurs autorisés à envoyer des e-mails pour votre domaine. Exemple : 'v=spf1 include:_spf.google.com ~all'" },
    "COOKIE_NO_SECURE": { "default": "Ajoutez l'attribut 'Secure' à tous vos cookies pour vous assurer qu'ils ne sont envoyés que sur des connexions HTTPS." },
    "COOKIE_NO_HTTPONLY": { "default": "Ajoutez l'attribut 'HttpOnly' à vos cookies de session pour empêcher leur accès via JavaScript." },
    "COOKIE_NO_SAMESITE": { "default": "Ajoutez l'attribut 'SameSite=Strict' ou 'SameSite=Lax' à vos cookies pour vous protéger contre les attaques CSRF." },
    "HSTS_MISSING": { "nginx": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';", "apache": "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'", "default": "Implémentez l'en-tête HSTS avec un 'max-age' d'au moins 6 mois (15552000 secondes)." },
    "XFO_MISSING": { "nginx": "add_header X-Frame-Options 'SAMEORIGIN';", "apache": "Header always set X-Frame-Options 'SAMEORIGIN'", "default": "Ajoutez l'en-tête 'X-Frame-Options: SAMEORIGIN' ou 'DENY' pour vous protéger du clickjacking." },
    "XCTO_MISSING": { "nginx": "add_header X-Content-Type-Options 'nosniff';", "apache": "Header always set X-Content-Type-Options 'nosniff'", "default": "Ajoutez l'en-tête 'X-Content-Type-Options: nosniff'." },
    "CSP_MISSING": { "default": "Envisagez d'implémenter une Content Security Policy (CSP) pour une défense en profondeur contre les attaques par injection de script (XSS)." },
    "SERVER_HEADER_VISIBLE": { "nginx": "Dans votre configuration nginx, ajoutez 'server_tokens off;'.", "apache": "Dans votre configuration apache, ajoutez 'ServerTokens Prod'.", "default": "Supprimez ou masquez les en-têtes qui révèlent la version de votre serveur." },
    "JS_LIB_OBSOLETE": { "default": "Une ou plusieurs bibliothèques JavaScript sont obsolètes. Mettez-les à jour vers leur dernière version stable pour corriger les vulnérabilités connues." },
    "WP_CONFIG_BAK_EXPOSED": { "default": "Supprimez immédiatement le fichier de sauvegarde de configuration WordPress exposé publiquement." },
    "WP_USER_ENUM_ENABLED": { "default": "Empêchez l'énumération des utilisateurs sur WordPress, par exemple en utilisant un plugin de sécurité ou en ajoutant des règles de réécriture." }
}

SUPPORTED_REPORTS = {
    "dmarc": "DMARC_MISSING",
    "spf": "SPF_MISSING",
    "hsts": "HSTS_MISSING",
    "xfo": "XFO_MISSING",
    "xcto": "XCTO_MISSING",
    "csp": "CSP_MISSING",
    "js-libs": "JS_LIB_OBSOLETE",
    "http-redirect": "NO_HTTPS_REDIRECT"
}

def load_scan_results():
    """
    Charge tous les rapports de scan JSON depuis le répertoire `scans/`.

    Retourne:
        list: Une liste de dictionnaires, chaque dictionnaire représentant un scan.
              Ex: [{'domain': 'google.com', 'date': datetime.obj, 'data': {...}}, ...]
    """
    scan_files = [f for f in os.listdir(SCAN_REPORTS_DIR) if f.endswith('.json')]
    results = []
    for filename in scan_files:
        try:
            # Le format du nom de fichier est {hostname}_{ddmmyy}.json
            parts = filename.replace('.json', '').split('_')
            domain = "_".join(parts[:-1])
            date_str = parts[-1]
            scan_date = datetime.strptime(date_str, '%d%m%y')

            filepath = os.path.join(SCAN_REPORTS_DIR, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            results.append({
                "domain": domain,
                "date": scan_date,
                "data": data
            })
        except (IndexError, ValueError, json.JSONDecodeError) as e:
            print(f"Avertissement : Impossible de parser le fichier '{filename}'. Erreur: {e}")
            continue

    # Trie les résultats par domaine puis par date (du plus récent au plus ancien)
    results.sort(key=lambda x: (x['domain'], x['date']), reverse=True)
    return results

def main():
    """
    Fonction principale pour l'outil de consolidation.
    """
    parser = argparse.ArgumentParser(description="Outil de consolidation pour les rapports de sécurité.")
    parser.add_argument("--list-scans", metavar="DOMAIN", help="Liste tous les scans disponibles pour un domaine, triés par date.")
    parser.add_argument("--compare", nargs=3, metavar=("DOMAIN", "DATE1", "DATE2"), help="Compare les scans d'un domaine entre deux dates (format YYYY-MM-DD).")
    parser.add_argument("--quick-wins", metavar="DOMAIN", nargs='?', const="all", help="Identifie les vulnérabilités 'quick win' pour un domaine spécifique ou pour tous les domaines.")
    parser.add_argument("--status", action="store_true", help="Affiche l'état des scans par rapport à une liste de cibles.")
    parser.add_argument("--oldest", action="store_true", help="Affiche les scans les plus anciens.")
    parser.add_argument("--list-expiring-certs", nargs='?', const=30, default=None, type=int, metavar='DAYS', help="Liste les certificats expirant bientôt (par défaut: 30 jours).")
    parser.add_argument("--report", nargs='+', metavar='TYPE', help="Génère un rapport d'actions pour un ou plusieurs types de vulnérabilités (ex: dmarc, hsts, ou 'all').")

    args = parser.parse_args()

    if not os.path.exists(SCAN_REPORTS_DIR):
        print(f"Le répertoire des scans '{SCAN_REPORTS_DIR}' n'existe pas. Veuillez le créer et y placer vos rapports JSON.")
        return

    all_scans = load_scan_results()

    if not all_scans and not args.status:
        print("Aucun rapport de scan trouvé dans le répertoire 'scans/'.")
        return

    if args.list_scans:
        display_scans_for_domain(all_scans, args.list_scans)
    elif args.compare:
        compare_scans(all_scans, args.compare[0], args.compare[1], args.compare[2])
    elif args.quick_wins:
        display_quick_wins(all_scans, args.quick_wins)
    elif args.status:
        display_scan_status(all_scans)
    elif args.oldest:
        display_oldest_scans(all_scans)
    elif args.list_expiring_certs is not None:
        display_expiring_certificates(all_scans, args.list_expiring_certs)
    elif args.report:
        generate_vulnerability_report(all_scans, args.report)
    else:
        # Si aucune commande n'est spécifiée, afficher un résumé
        print(f"✅ {len(all_scans)} rapport(s) de scan chargé(s).")
        # parser.print_help()

def display_scans_for_domain(all_scans, domain):
    """Affiche tous les scans disponibles pour un domaine spécifique."""
    scans_for_domain = [s for s in all_scans if s['domain'] == domain]
    if not scans_for_domain:
        print(f"Aucun scan trouvé pour le domaine '{domain}'.")
        return

    print(f"🔎 Scans disponibles pour '{domain}':")
    for scan in scans_for_domain:
        date_str = scan['date'].strftime('%Y-%m-%d')
        score = scan['data'].get('score_final', 'N/A')
        grade = scan['data'].get('note', 'N/A')
        print(f"  - Date: {date_str}, Score: {score}, Note: {grade}")

def display_scan_status(all_scans):
    """Affiche l'état des scans par rapport à la liste des cibles."""
    try:
        with open('targets.txt', 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Le fichier 'targets.txt' est introuvable. Veuillez le créer.")
        return

    scanned_domains = {s['domain'] for s in all_scans}
    print("📊 État des scans cibles :")

    scanned_count = 0
    for target in targets:
        if target in scanned_domains:
            print(f"  [✅] {target}")
            scanned_count += 1
        else:
            print(f"  [❌] {target}")

    print(f"\nTotal: {scanned_count} / {len(targets)} cibles scannées.")

def _extract_vulnerabilities(scan_data):
    """Helper pour extraire un set de vulnérabilités identifiables d'un rapport."""
    vulnerabilities = set()

    def find_issues(data, path=""):
        if isinstance(data, dict):
            # Si un item a un 'statut' et un 'remediation_id', on le considère comme une vulnérabilité potentielle
            if 'statut' in data and data['statut'] in ['ERROR', 'WARNING'] and 'remediation_id' in data:
                # Créer un identifiant unique pour la vulnérabilité
                vuln_id = f"{path}.{data['remediation_id']}"
                vulnerabilities.add(vuln_id)

            for key, value in data.items():
                find_issues(value, f"{path}.{key}" if path else key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                find_issues(item, f"{path}[{i}]")

    find_issues(scan_data)
    return vulnerabilities

def compare_scans(all_scans, domain, date1_str, date2_str):
    """Compare deux scans pour un domaine donné."""
    try:
        d1 = datetime.strptime(date1_str, '%Y-%m-%d').date()
        d2 = datetime.strptime(date2_str, '%Y-%m-%d').date()
    except ValueError:
        print("Erreur: Le format de la date doit être YYYY-MM-DD.")
        return

    # S'assurer que d1 est avant d2
    if d1 > d2:
        d1, d2 = d2, d1

    scan1 = next((s for s in all_scans if s['domain'] == domain and s['date'].date() == d1), None)
    scan2 = next((s for s in all_scans if s['domain'] == domain and s['date'].date() == d2), None)

    if not scan1 or not scan2:
        print(f"Impossible de trouver les deux scans pour '{domain}' aux dates {d1} et {d2}.")
        if not scan1: print(f"Aucun scan trouvé pour la date {d1}")
        if not scan2: print(f"Aucun scan trouvé pour la date {d2}")
        # Proposer les dates disponibles
        display_scans_for_domain(all_scans, domain)
        return

    print(f"🔄 Comparaison des scans pour '{domain}' entre {d1} et {d2}\n")

    # Comparaison des scores
    score1 = scan1['data'].get('score_final', 0)
    score2 = scan2['data'].get('score_final', 0)
    print(f"Score: {score1} (à {d1}) -> {score2} (à {d2})")
    if score2 < score1:
        print(f"  -> ✅ Amélioration du score de {score1 - score2} points.")
    elif score2 > score1:
        print(f"  -> ⚠️ Dégradation du score de {score2 - score1} points.")
    else:
        print("  -> 😐 Score inchangé.")

    # Comparaison des vulnérabilités
    vulns1 = _extract_vulnerabilities(scan1['data'])
    vulns2 = _extract_vulnerabilities(scan2['data'])

    fixed_vulns = vulns1 - vulns2
    new_vulns = vulns2 - vulns1
    persistent_vulns = vulns1 & vulns2

    print("\n--- Changements des vulnérabilités ---")
    if fixed_vulns:
        print("\n[✅ VULNÉRABILITÉS CORRIGÉES]")
        for v in sorted(list(fixed_vulns)):
            print(f"  - {v}")

    if new_vulns:
        print("\n[❌ NOUVELLES VULNÉRABILITÉS]")
        for v in sorted(list(new_vulns)):
            print(f"  - {v}")

    if not fixed_vulns and not new_vulns:
        print("\n[😐] Aucune nouvelle vulnérabilité détectée et aucune n'a été corrigée.")

    if persistent_vulns:
        print(f"\n[⚠️ {len(persistent_vulns)} VULNÉRABILITÉS PERSISTANTES]")


def display_oldest_scans(all_scans):
    """Affiche les cibles dont les scans sont les plus anciens."""
    try:
        with open('targets.txt', 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Le fichier 'targets.txt' est introuvable. Veuillez le créer.")
        return

    last_scan_dates = {}
    for target in targets:
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == target), None)
        last_scan_dates[target] = most_recent_scan['date'] if most_recent_scan else None

    # Trie les cibles par date de dernier scan, les non-scannées en premier
    sorted_targets = sorted(last_scan_dates.items(), key=lambda item: item[1] if item[1] is not None else datetime.min)

    print("🕒 Scans les plus anciens (par cible) :")
    for target, date in sorted_targets:
        if date:
            print(f"  - {target.ljust(25)} Dernier scan: {date.strftime('%Y-%m-%d')}")
        else:
            print(f"  - {target.ljust(25)} Dernier scan: JAMAIS (Priorité haute)")

QUICK_WIN_REMEDIATION_IDS = {
    "HSTS_MISSING", "XFO_MISSING", "XCTO_MISSING", "CSP_MISSING",
    "COOKIE_NO_SECURE", "COOKIE_NO_HTTPONLY", "COOKIE_NO_SAMESITE",
    "SERVER_HEADER_VISIBLE"
}

def display_quick_wins(all_scans, domain_filter):
    """Identifie et affiche les vulnérabilités 'quick win'."""

    target_domains = []
    if domain_filter == 'all':
        # Obtenir la liste unique de domaines depuis les scans
        target_domains = sorted(list({s['domain'] for s in all_scans}))
    else:
        target_domains = [domain_filter]

    print("🚀 Quick Wins (vulnérabilités faciles à corriger) :\n")

    found_any = False
    for domain in target_domains:
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == domain), None)

        if not most_recent_scan:
            if domain_filter != 'all':
                print(f"Aucun scan trouvé pour '{domain}'.")
            continue

        vulns = _extract_vulnerabilities(most_recent_scan['data'])
        quick_wins = {v for v in vulns if any(rem_id in v for rem_id in QUICK_WIN_REMEDIATION_IDS)}

        if quick_wins:
            found_any = True
            print(f"--- {domain} (Scan du {most_recent_scan['date'].strftime('%Y-%m-%d')}) ---")
            for v in sorted(list(quick_wins)):
                print(f"  - {v}")
            print()

    if not found_any:
        print("Aucun 'quick win' identifié dans les derniers scans.")


def display_expiring_certificates(all_scans, days_threshold):
    """Affiche les certificats SSL/TLS qui expirent bientôt."""
    today = datetime.now()
    expiring_certs = []

    # Obtenir la liste des domaines uniques à partir des scans
    unique_domains = sorted(list({s['domain'] for s in all_scans}))

    for domain in unique_domains:
        # Trouver le scan le plus récent pour ce domaine
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == domain), None)
        if not most_recent_scan:
            continue

        cert_info = most_recent_scan['data'].get('ssl_certificate', {})
        exp_date_str = cert_info.get('date_expiration')

        if not exp_date_str:
            continue

        try:
            exp_date = datetime.strptime(exp_date_str, '%Y-%m-%d')
            days_left = (exp_date - today).days

            if 0 <= days_left <= days_threshold:
                expiring_certs.append({
                    "domain": domain,
                    "exp_date": exp_date,
                    "days_left": days_left
                })
        except ValueError:
            print(f"Avertissement : Format de date invalide pour le certificat de '{domain}': '{exp_date_str}'")
            continue

    print(f"📜 Certificats expirant dans les {days_threshold} prochains jours :\n")

    if not expiring_certs:
        print("Aucun certificat n'expire dans la période spécifiée. ✅")
        return

    # Trie les certificats par date d'expiration (le plus proche en premier)
    expiring_certs.sort(key=lambda x: x['days_left'])

    for cert in expiring_certs:
        date_str = cert['exp_date'].strftime('%d %B %Y')
        days = cert['days_left']
        plural_s = 's' if days > 1 else ''
        print(f"  - {cert['domain'].ljust(30)} Expire le: {date_str} (dans {days} jour{plural_s})")


def generate_vulnerability_report(all_scans, report_types):
    """Génère un rapport listant les sites affectés par des vulnérabilités spécifiques."""

    # Gérer le mot-clé 'all'
    if 'all' in [rt.lower() for rt in report_types]:
        reports_to_run = list(SUPPORTED_REPORTS.keys())
    else:
        # Valider les types de rapports demandés
        reports_to_run = []
        for rt in report_types:
            if rt.lower() in SUPPORTED_REPORTS:
                reports_to_run.append(rt.lower())
            else:
                print(f"Avertissement : Le type de rapport '{rt}' n'est pas supporté. Les types supportés sont : {', '.join(SUPPORTED_REPORTS.keys())}")
        if not reports_to_run:
            print("Aucun rapport valide à générer.")
            return

    print(f"🔎 Génération du rapport d'actions pour : {', '.join(reports_to_run)}\n")

    # Obtenir la liste des domaines uniques à partir des scans
    unique_domains = sorted(list({s['domain'] for s in all_scans}))

    # Structurer les résultats par type de vulnérabilité
    results = {report_type: [] for report_type in reports_to_run}

    for domain in unique_domains:
        # Trouver le scan le plus récent pour ce domaine
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == domain), None)
        if not most_recent_scan:
            continue

        # Extraire les vulnérabilités de ce scan
        vulnerabilities = _extract_vulnerabilities(most_recent_scan['data'])

        # Vérifier si le domaine est affecté par les vulnérabilités demandées
        for report_type in reports_to_run:
            remediation_id = SUPPORTED_REPORTS[report_type]
            # Nous vérifions si un identifiant de vulnérabilité contient le remediation_id
            # C'est plus flexible que une égalité stricte
            if any(remediation_id in v_id for v_id in vulnerabilities):
                results[report_type].append(domain)

    # Afficher le rapport
    found_any_issue = False
    for report_type, affected_domains in results.items():
        remediation_id = SUPPORTED_REPORTS[report_type]
        advice = REMEDIATION_ADVICE.get(remediation_id, {}).get('default', 'Aucun conseil de remédiation disponible.')

        print(f"--- Rapport pour : {report_type.upper()} ---")
        print(f"    Action recommandée : {advice}\n")

        if affected_domains:
            found_any_issue = True
            print("    Sites affectés :")
            for domain in sorted(affected_domains):
                print(f"      - {domain}")
        else:
            print("    ✅ Aucun site affecté pour ce type de vulnérabilité.")
        print("-" * (20 + len(report_type)))
        print()

    if not found_any_issue:
        print("🎉 Félicitations ! Aucun des problèmes recherchés n'a été trouvé sur les derniers scans de vos domaines.")


if __name__ == "__main__":
    main()
