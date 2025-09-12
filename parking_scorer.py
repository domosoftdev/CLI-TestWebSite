#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Algorithme de Calcul de Score de Parking de Domaine.
Ce script peut être exécuté de manière autonome pour obtenir le score de parking d'un domaine.
"""

import argparse
import sys
import requests
from bs4 import BeautifulSoup
import dns.resolver
import uuid
import whois
from datetime import datetime, timedelta

# --- CONSTANTES ---

# Listes complètes de mots-clés pour détecter les domaines parkés

KEYWORDS_FOR_SALE = [
    # Phrases explicites de vente
    "domain for sale",
    "domaine à vendre",
    "buy this domain",
    "acheter ce domaine",
    "domain available",
    "domaine disponible",
    "purchase this domain",
    "acquire this domain",
    "this domain is for sale",
    "ce domaine est à vendre",
    "buy now",
    "acheter maintenant",
    "make an offer",
    "faire une offre",
    "for sale by owner",
    "vente par le propriétaire",
    "domain auction",
    "buy it now",
    "achat immédiat",
    "domain broker",
    "courtier domaine",
    # Variations en plusieurs langues
    "zu verkaufen",
    "te koop",
    "in vendita",
    "para la venta",
    "på salg",
    "for salg",
    "myydään",
    "sprzedaż",
    "продается",
    "出售",
    # Phrases commerciales
    "inquire now",
    "contact owner",
    "contactez propriétaire",
    "renseignements",
    "price negotiable",
    "prix négociable",
    "best offer",
    "meilleure offre",
    "premium domain",
    "domaine premium",
    "valuable domain",
    "domaine de valeur",
    "investment opportunity",
    "opportunité d'investissement",
    "brandable domain",
    "domaine brandable",
    "exact match domain",
    # Services de vente de domaines
    "sedo",
    "afternic",
    "flippa",
    "dan.com",
    "undeveloped.com",
    "hugedomains",
    "godaddy auctions",
    "namecheap marketplace",
    "domain name sales",
    "vente nom de domaine",
    # Actions d'achat
    "click here to buy",
    "cliquez ici pour acheter",
    "purchase instantly",
    "instant buy",
    "achat instantané",
    "add to cart",
    "ajouter au panier",
    "checkout",
    "secure payment",
    "paiement sécurisé",
]

KEYWORDS_PARKING_GENERIC = [
    # Termes de parking explicites
    "parked domain",
    "domaine parqué",
    "domain parking",
    "parking de domaine",
    "parked free",
    "parqué gratuitement",
    "courtesy of",
    "gracieuseté de",
    "this domain is parked",
    "ce domaine est parqué",
    "domain name parking",
    "stationnement de nom de domaine",
    # États temporaires
    "under construction",
    "en construction",
    "coming soon",
    "bientôt disponible",
    "site under development",
    "site en développement",
    "website coming soon",
    "page temporarily unavailable",
    "page temporairement indisponible",
    "future home of",
    "futur domicile de",
    "placeholder page",
    "temporary page",
    "page temporaire",
    "work in progress",
    # Services de parking populaires
    "bodis",
    "parkingcrew",
    "above.com",
    "domcollect",
    "nameservers.com",
    "sedoparking",
    "parking page",
    "default page",
    "page par défaut",
    "registrar default page",
    "page par défaut du registraire",
    "web hosting default page",
    "page par défaut hébergement",
    # Publicités et revenus
    "sponsored links",
    "liens sponsorisés",
    "related searches",
    "recherches associées",
    "advertising",
    "publicité",
    "ads by",
    "publicités par",
    "revenue",
    "revenus",
    "monetization",
    "click here for",
    "cliquez ici pour",
    "search results",
    "résultats de recherche",
    "pay per click",
    "paiement par clic",
    # Messages de redirection
    "redirect",
    "redirection",
    "forwarding",
    "transfert",
    "this page will redirect",
    "cette page va rediriger",
    "automatic redirect",
    "redirection automatique",
    # États d'erreur ou vides
    "default web site page",
    "page web par défaut",
    "test page",
    "page de test",
    "it works",
    "ça marche",
    "apache default",
    "nginx default",
    "iis default",
    "server default page",
    "welcome to",
    "bienvenue à",
    "congratulations",
    "félicitations",
]

KEYWORDS_PLACEHOLDER_CONTENT = [
    # Contenu minimal typique
    "lorem ipsum",
    "placeholder text",
    "texte de remplacement",
    "sample text",
    "exemple de texte",
    "dummy text",
    "faux texte",
    "test content",
    "contenu de test",
    "default content",
    "contenu par défaut",
    "template",
    "modèle",
    # Messages génériques
    "this is the default page",
    "ceci est la page par défaut",
    "no website configured",
    "aucun site web configuré",
    "account suspended",
    "compte suspendu",
    "service unavailable",
    "service indisponible",
    "bandwidth exceeded",
    "bande passante dépassée",
    # États techniques
    "404 not found",
    "page not found",
    "page non trouvée",
    "503 service unavailable",
    "500 internal error",
    "maintenance mode",
    "mode maintenance",
    "offline",
    "hors ligne",
    "temporarily down",
    "temporairement arrêté",
]

KEYWORDS_SEARCH_RELATED = [
    # Termes de recherche
    "search",
    "recherche",
    "find",
    "trouver",
    "discover",
    "découvrir",
    "explore",
    "explorer",
    "browse",
    "naviguer",
    "directory",
    "annuaire",
    "categories",
    "catégories",
    "topics",
    "sujets",
    "keywords",
    "mots-clés",
    # Suggestions automatiques
    "related to",
    "lié à",
    "similar to",
    "similaire à",
    "you might like",
    "vous pourriez aimer",
    "recommended",
    "recommandé",
    "suggested",
    "suggéré",
    "popular searches",
    "recherches populaires",
    "trending",
    "tendance",
    "most searched",
    "plus recherché",
]

KEYWORDS_CONTACT_FORMS = [
    # Formulaires de contact basiques
    "contact us",
    "contactez-nous",
    "get in touch",
    "prenez contact",
    "send message",
    "envoyer message",
    "inquiry",
    "demande",
    "contact form",
    "formulaire de contact",
    "email us",
    "envoyez-nous",
    "your name",
    "votre nom",
    "your email",
    "votre email",
    "subject",
    "sujet",
    "message",
    "phone number",
    "numéro téléphone",
]

# Patterns regex utiles pour détecter le parking
REGEX_PATTERNS_PARKING = [
    r"domain.*for sale",
    r"buy.*domain",
    r"parked.*domain",
    r"under construction",
    r"coming soon",
    r"this domain.*available",
    r"contact.*owner",
    r"make.*offer",
    r"sponsored.*links?",
    r"related.*searches?",
    r"click here.*",
    r"default.*page",
    r"placeholder.*page",
]

# Services de parking populaires (pour vérifier les références)
PARKING_SERVICES = [
    # Principaux services
    "sedo.com",
    "parkingcrew.net",
    "bodis.com",
    "above.com",
    "domcollect.com",
    "afternic.com",
    "dan.com",
    "undeveloped.com",
    "hugedomains.com",
    "domainnameshop.com",
    "nameservers.com",
    # Services affiliés
    "google.com/adsense",
    "googlesyndication.com",
    "doubleclick.net",
    "adsystem.com",
    "advertising.com",
    "yahoo.com",
    "bing.com",
    # Registraires avec parking intégré
    "godaddy.com",
    "namecheap.com",
    "1and1.com",
    "hostgator.com",
    "bluehost.com",
    "dreamhost.com",
]

# Services de parking populaires (pour vérifier les références)
KNOWN_PARKING_NAMESERVERS = [
    "sedoparking.com",
    "bodis.com",
    "parkingcrew.net",
    "above.com",
    "abovedomains.com",
    "uniregistrymarket.link",
    "huge-domains.com",
    "afternic.com",
    "dan.com",
]

# Indicateurs HTML spécifiques
HTML_PARKING_INDICATORS = [
    # Balises meta typiques
    'meta name="description" content="parked"',
    'meta name="keywords" content="domain for sale"',
    'meta name="robots" content="noindex"',
    # Classes CSS communes
    'class="parked"',
    'class="parking"',
    'class="for-sale"',
    'class="placeholder"',
    'class="coming-soon"',
    # IDs communes
    'id="parking"',
    'id="parked"',
    'id="for-sale"',
    'id="placeholder"',
    'id="under-construction"',
    # Scripts de parking
    "parking.js",
    "domain-parking.js",
    "ads.js",
    "google_ad_client",
    "googletag.cmd",
]

# --- FONCTIONS D'ANALYSE ---


def analyserContenu(domaine: str, verbose: bool = False) -> int:
    """Analyse le contenu HTTP d'un domaine en utilisant la nouvelle logique de scoring."""
    if verbose:
        print("\n--- Analyse du Contenu ---")

    urls_a_tester = [
        f"https://www.{domaine}",
        f"https://{domaine}",
        f"http://{domaine}",
    ]
    page_html = ""
    session = requests.Session()
    session.max_redirects = 5
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    for url in urls_a_tester:
        try:
            if verbose:
                print(f"  [i] Test de l'URL : {url}")
            reponse = session.get(url, timeout=10, headers=headers)
            if reponse.status_code == 200:
                page_html = reponse.text
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
        score, _ = calculate_parking_score("", "")
        return score

    soup = BeautifulSoup(page_html, "html.parser")
    title = soup.title.string if soup.title else ""
    all_text = " ".join(line.strip() for line in soup.stripped_strings if line)

    score, indicators = calculate_parking_score(all_text, title)

    if verbose:
        print(f"  [+] Score de contenu calculé : {score}/100")
        if indicators:
            print("  [i] Indicateurs trouvés :")
            for indicator in indicators:
                print(f"    - {indicator}")

    return score


def analyserTechnique(domaine: str, verbose: bool = False) -> int:
    """Analyse les enregistrements DNS. Score: 0-30."""
    if verbose:
        print("\n--- Analyse Technique (max 30 pts) ---")
    score = 0
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout, resolver.lifetime = 5, 5

    try:
        ns_records = resolver.resolve(domaine, "NS")
        ns_match_found = False
        for record in ns_records:
            ns_str = str(record.target).lower()
            if verbose:
                print(f"  [i] Serveur de noms trouvé : {ns_str.rstrip('.')}")
            for known_ns in KNOWN_PARKING_NAMESERVERS:
                if ns_str.startswith(known_ns.rstrip(".")) or ns_str.endswith(
                    known_ns + "."
                ):
                    if verbose:
                        print(
                            f"  [+] Le serveur de noms correspond à un service de parking connu ({known_ns}) : +15 pts"
                        )
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
        ip_racine_answers = resolver.resolve(domaine, "A")
        ip_racine = {str(r) for r in ip_racine_answers}
        if verbose:
            print(f"  [i] Adresses IP trouvées pour {domaine} : {ip_racine}")
        sous_domaine_aleatoire = f"test-wildcard-{uuid.uuid4().hex[:8]}.{domaine}"
        ip_aleatoire_answers = resolver.resolve(sous_domaine_aleatoire, "A")
        ip_aleatoire = {str(r) for r in ip_aleatoire_answers}
        if verbose:
            print(
                f"  [i] Adresses IP trouvées pour {sous_domaine_aleatoire} : {ip_aleatoire}"
            )
        if ip_racine and ip_aleatoire == ip_racine:
            if verbose:
                print("  [+] Un enregistrement DNS Wildcard a été détecté : +5 pts")
            score += 5
        elif verbose:
            print("  [-] Pas de DNS Wildcard détecté.")
    except Exception as e:
        if verbose:
            print(f"  [!] Pas de DNS Wildcard détecté ou erreur : {e}")

    return score


def analyserContextuel(domaine: str, verbose: bool = False) -> int:
    """Analyse les données WHOIS. Score: 0-30."""
    if verbose:
        print("\n--- Analyse Contextuelle (max 30 pts) ---")
    score = 0
    try:
        data = whois.whois(domaine)
    except Exception as e:
        if verbose:
            print(f"  [!] Échec de la requête WHOIS : {e}")
        return 0

    if not data or not data.get("creation_date"):
        if verbose:
            print("  [!] Données WHOIS invalides ou incomplètes.")
        return 0

    privacy_keywords = ["privacy", "whoisguard", "redacted", "protection", "proxy"]
    registrant_info = str(data.get("registrant_name", "")) + str(data.get("org", ""))
    if any(keyword in registrant_info.lower() for keyword in privacy_keywords):
        if verbose:
            print("  [+] Protection de la confidentialité WHOIS détectée : +5 pts")
        score += 5
    elif verbose:
        print("  [-] Pas de protection de confidentialité détectée.")

    now = datetime.now()
    updated_date = data.get("updated_date")
    if isinstance(updated_date, list):
        updated_date = updated_date[0]
    creation_date = data.get("creation_date")
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if updated_date and (now - updated_date) < timedelta(days=30):
        if verbose:
            print(
                f"  [+] Domaine mis à jour récemment ({updated_date.date()}) : +10 pts"
            )
        score += 10
    elif creation_date and (now - creation_date) < timedelta(days=90):
        if verbose:
            print(f"  [+] Domaine créé récemment ({creation_date.date()}) : +5 pts")
        score += 5
    elif verbose:
        print("  [-] Pas de mise à jour ou création récente.")

    domain_status = data.get("status", [])
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


def calculerScoreParking(domaine: str, verbose: bool = False) -> int:
    """Orchestre les analyses et calcule le score final."""
    if verbose:
        print(f"Lancement de l'analyse complète pour {domaine}...")
    score_contenu = analyserContenu(domaine, verbose=verbose)
    score_technique = analyserTechnique(domaine, verbose=verbose)
    score_contextuel = analyserContextuel(domaine, verbose=verbose)
    score_total = score_contenu + score_technique + score_contextuel
    return min(score_total, 100)


# Fonction utilitaire pour scorer le contenu
def calculate_parking_score(content_text, title=""):
    """
    Calcule un score de parking basé sur la présence de mots-clés
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
            break  # Ajout du break

    # Vérification du contenu - For Sale
    for keyword in KEYWORDS_FOR_SALE:
        if keyword in content_lower:
            score += 10
            indicators.append(f"Content: '{keyword}'")
            break  # Ajout du break

    # Vérification du contenu - Parking Generic
    for keyword in KEYWORDS_PARKING_GENERIC:
        if keyword in content_lower:
            score += 8
            indicators.append(f"Parking: '{keyword}'")
            break  # Ajout du break

    # Vérification des services de parking
    for service in PARKING_SERVICES:
        if service in content_lower:
            score += 15
            indicators.append(f"Service: '{service}'")
            break  # Ajout du break

    # Bonus pour contenu très court (souvent signe de parking)
    word_count = len(content_text.split())
    if word_count < 30:
        score += 20
        indicators.append(f"Minimal content ({word_count} words)")

    return min(score, 100), indicators


# --- BLOC D'EXÉCUTION AUTONOME ---


def main():
    """Point d'entrée pour l'exécution en ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Calcule le score de parking d'un nom de domaine.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "domaine", help="Le nom de domaine à analyser (ex: exemple.com)."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Affiche le détail des tests et des points attribués.",
    )
    args = parser.parse_args()

    if "." not in args.domaine:
        print(
            f"Erreur : '{args.domaine}' ne semble pas être un nom de domaine valide.",
            file=sys.stderr,
        )
        sys.exit(1)

    score = calculerScoreParking(args.domaine, verbose=args.verbose)

    if args.verbose:
        print("\n" + "=" * 40)
        print(f"SCORE DE PARKING FINAL POUR {args.domaine.upper()}")
        print(f"Score : {score}/100")
        print("=" * 40)
    else:
        print(f"Score de parking pour {args.domaine}: {score}/100")


if __name__ == "__main__":
    main()
