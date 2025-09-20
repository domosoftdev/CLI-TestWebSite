# -*- coding: utf-8 -*-
import socket

def check_host_exists(hostname):
    """Checks if a hostname can be resolved."""
    try:
        socket.gethostbyname_ex(hostname)
        return True
    except socket.gaierror:
        return False

def get_hostname(url):
    """Extracts the hostname from a URL."""
    if url.startswith('https://'): url = url[8:]
    if url.startswith('http://'): url = url[7:]
    if '/' in url: url = url.split('/')[0]
    return url

def print_human_readable_report(results):
    """Prints a human-readable summary of the analysis to the console."""
    STATUS_ICONS = {"SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}
    score = results.get('score_final', 'N/A')
    grade = results.get('note', 'N/A')
    hostname = results.get('hostname', 'N/A')

    print("\n" + "="*50)
    print(f" RAPPORT D'ANALYSE DE SÉCURITÉ POUR : {hostname}")
    print(f" SCORE DE DANGEROSITÉ : {score} (Note : {grade})")
    print("="*50)

    for category, data in results.items():
        if category in ['hostname', 'score_final', 'note']:
            continue
        print(f"\n--- {category.replace('_', ' ').title()} ---")

        if category == 'ssl_certificate' and isinstance(data, dict):
            icon = STATUS_ICONS.get(data.get('statut'), '❓')
            print(f"  {icon} [{data.get('criticite', 'INFO')}] {data.get('message')}")
            if data.get('points_a_corriger'):
                print("    - Points à corriger :")
                for point in data['points_a_corriger']:
                    icon = STATUS_ICONS.get(point.get('statut', '❓'), '❓')
                    print(f"      {icon} [{point.get('criticite')}] {point.get('message')}")
            if data.get('details'):
                print("    - Détails techniques :")
                details = data['details']
                for key, value in details.items():
                    print(f"      - {key.replace('_', ' ').title()} : {value}")

        elif isinstance(data, list) and data and isinstance(data[0], dict) and 'statut' in data[0]:
            for item in data:
                icon = STATUS_ICONS.get(item.get('statut'), '❓')
                print(f"  {icon} [{item.get('criticite', 'INFO')}] {item.get('message', 'Détail non disponible.')}")

        elif isinstance(data, dict) and 'statut' in data:
             icon = STATUS_ICONS.get(data.get('statut'), '❓')
             print(f"  {icon} [{data.get('criticite', 'INFO')}] {data.get('message', 'Détail non disponible.')}")

    print("="*50)
