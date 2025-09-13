# -*- coding: utf-8 -*-

"""
Algorithme de Calcul de Score de Parking de Domaine.
"""

import requests
from bs4 import BeautifulSoup
import dns.resolver
import uuid
import whois
from datetime import datetime, timedelta

from src.config import (
    KEYWORDS_FOR_SALE,
    KEYWORDS_PARKING_GENERIC,
    KNOWN_PARKING_NAMESERVERS,
    PARKING_SERVICES,
    DEFAULT_TIMEOUT,
    DNS_RESOLVERS
)

# --- FONCTIONS D'ANALYSE ---

def _calculate_content_score(content_text, title=""):
    """
    Calcule un score de parking basé sur la présence de mots-clés.
    """
    content_lower = content_text.lower()
    title_lower = title.lower()
    score = 0
    indicators = []

    # Vérification dans le titre (poids plus élevé)
    for keyword in KEYWORDS_FOR_SALE[:20]:  # Top 20 keywords
        if keyword in title_lower:
            score += 25
            indicators.append(f"Title: '{keyword}'")
            break

    # Vérification du contenu - For Sale
    for keyword in KEYWORDS_FOR_SALE:
        if keyword in content_lower:
            score += 10
            indicators.append(f"Content: '{keyword}'")
            break

    # Vérification du contenu - Parking Generic
    for keyword in KEYWORDS_PARKING_GENERIC:
        if keyword in content_lower:
            score += 8
            indicators.append(f"Parking: '{keyword}'")
            break

    # Vérification des services de parking
    for service in PARKING_SERVICES:
        if service in content_lower:
            score += 15
            indicators.append(f"Service: '{service}'")
            break

    # Bonus pour contenu très court (souvent signe de parking)
    word_count = len(content_text.split())
    if word_count < 30:
        score += 20
        indicators.append(f"Minimal content ({word_count} words)")

    return min(score, 100), indicators

def analyze_content(domain: str, verbose: bool = False) -> int:
    """Analyse le contenu HTTP d'un domaine."""
    if verbose:
        print("\n--- Analyse du Contenu ---")

    urls_to_test = [f"https://www.{domain}", f"https://{domain}", f"http://{domain}"]
    page_html = ""
    session = requests.Session()
    session.max_redirects = 5
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    for url in urls_to_test:
        try:
            if verbose:
                print(f"  [i] Test de l'URL : {url}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT, headers=headers)
            if response.status_code == 200:
                page_html = response.text
                if verbose:
                    print(f"  [+] Connexion réussie à : {url}")
                break
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"  [!] Échec de la connexion : {e}")
            continue

    if not page_html:
        if verbose:
            print("  [!] Impossible de récupérer le contenu de la page.")
        score, _ = _calculate_content_score("", "")
        return score

    soup = BeautifulSoup(page_html, 'html.parser')
    title = soup.title.string if soup.title else ""
    all_text = " ".join(line.strip() for line in soup.stripped_strings if line)

    score, indicators = _calculate_content_score(all_text, title)

    if verbose:
        print(f"  [+] Score de contenu calculé : {score}/100")
        if indicators:
            print("  [i] Indicateurs trouvés :")
            for indicator in indicators:
                print(f"    - {indicator}")

    return score

def analyze_technical(domain: str, verbose: bool = False) -> int:
    """Analyse les enregistrements DNS. Score: 0-30."""
    if verbose:
        print("\n--- Analyse Technique (max 30 pts) ---")
    score = 0
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DNS_RESOLVERS
    resolver.timeout, resolver.lifetime = 5, 5

    try:
        ns_records = resolver.resolve(domain, 'NS')
        ns_match_found = False
        for record in ns_records:
            ns_str = str(record.target).lower()
            if verbose:
                print(f"  [i] Serveur de noms trouvé : {ns_str.rstrip('.')}")
            for known_ns in KNOWN_PARKING_NAMESERVERS:
                if ns_str.startswith(known_ns.rstrip('.')) or ns_str.endswith(known_ns + '.'):
                    if verbose:
                        print(f"  [+] Le serveur de noms correspond à un service de parking connu ({known_ns}) : +15 pts")
                    score += 15
                    ns_match_found = True
                    break
            if ns_match_found:
                break
        if not ns_match_found and verbose:
            print("  [-] Aucun serveur de noms de parking connu trouvé.")
    except Exception as e:
        if verbose:
            print(f"  [!] Erreur lors de la résolution NS : {e}")

    try:
        ip_root_answers = resolver.resolve(domain, 'A')
        ip_root = {str(r) for r in ip_root_answers}
        if verbose:
            print(f"  [i] Adresses IP trouvées pour {domain} : {ip_root}")
        random_subdomain = f"test-wildcard-{uuid.uuid4().hex[:8]}.{domain}"
        ip_random_answers = resolver.resolve(random_subdomain, 'A')
        ip_random = {str(r) for r in ip_random_answers}
        if verbose:
            print(f"  [i] Adresses IP trouvées pour {random_subdomain} : {ip_random}")
        if ip_root and ip_random == ip_root:
            if verbose:
                print("  [+] Un enregistrement DNS Wildcard a été détecté : +5 pts")
            score += 5
        elif verbose:
            print("  [-] Pas de DNS Wildcard détecté.")
    except Exception as e:
        if verbose:
            print(f"  [!] Pas de DNS Wildcard détecté ou erreur : {e}")

    return score

def analyze_contextual(domain: str, verbose: bool = False) -> int:
    """Analyse les données WHOIS. Score: 0-30."""
    if verbose:
        print("\n--- Analyse Contextuelle (max 30 pts) ---")
    score = 0
    try:
        data = whois.whois(domain)
    except Exception as e:
        if verbose:
            print(f"  [!] Échec de la requête WHOIS : {e}")
        return 0

    if not data or not data.get('creation_date'):
        if verbose:
            print("  [!] Données WHOIS invalides ou incomplètes.")
        return 0

    privacy_keywords = ["privacy", "whoisguard", "redacted", "protection", "proxy"]
    registrant_info = str(data.get('registrant_name', '')) + str(data.get('org', ''))
    if any(keyword in registrant_info.lower() for keyword in privacy_keywords):
        if verbose:
            print("  [+] Protection de la confidentialité WHOIS détectée : +5 pts")
        score += 5
    elif verbose:
        print("  [-] Pas de protection de confidentialité détectée.")

    now = datetime.now()
    updated_date = data.get('updated_date')
    if isinstance(updated_date, list):
        updated_date = updated_date[0]
    creation_date = data.get('creation_date')
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if updated_date and (now - updated_date) < timedelta(days=30):
        if verbose:
            print(f"  [+] Domaine mis à jour récemment ({updated_date.date()}) : +10 pts")
        score += 10
    elif creation_date and (now - creation_date) < timedelta(days=90):
        if verbose:
            print(f"  [+] Domaine créé récemment ({creation_date.date()}) : +5 pts")
        score += 5
    elif verbose:
        print("  [-] Pas de mise à jour ou création récente.")

    domain_status = data.get('status', [])
    if isinstance(domain_status, str):
        domain_status = [domain_status]
    found_hold = False
    for s in domain_status:
        if "clienthold" in s.lower():
            if verbose:
                print(f"  [+] Statut 'clientHold' trouvé : +10 pts")
            score += 10
            found_hold = True
            break
    if not found_hold and verbose:
        print("  [-] Aucun statut 'clientHold' trouvé.")

    return score

def calculate_parking_score(domain: str, verbose: bool = False) -> int:
    """Orchestre les analyses et calcule le score final."""
    if verbose:
        print(f"Lancement de l'analyse complète du score de parking pour {domain}...")
    score_content = analyze_content(domain, verbose=verbose)
    score_technical = analyze_technical(domain, verbose=verbose)
    score_contextual = analyze_contextual(domain, verbose=verbose)
    score_total = score_content + score_technical + score_contextual

    if verbose:
        print(f"Score de parking final pour {domain}: {min(score_total, 100)}/100")

    return min(score_total, 100)
