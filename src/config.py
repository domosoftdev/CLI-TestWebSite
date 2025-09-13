# -*- coding: utf-8 -*-

"""
Centralized configuration file for the web security analysis tool.
This file groups all constants, file paths, API endpoints, and other
configuration variables to make them easily manageable.
"""

# --- General Application Configuration ---
SCAN_REPORTS_DIR = "scans/"
TARGETS_FILE = "targets.txt"
SUMMARY_REPORT_HTML_FILE = "summary_report.html"
EVOLUTION_GRAPH_FILE_FORMAT = "{domain}_evolution.png"

# --- Network & Timeouts ---
DEFAULT_TIMEOUT = 10
DNS_RESOLVERS = ['8.8.8.8', '1.1.1.1']
SELENIUM_PAGE_LOAD_TIMEOUT = 20

# --- APIs and External Services ---
OSV_API_URL = "https://api.osv.dev/v1/query"

# --- Scoring ---
SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
}

# --- Remediation Advice ---
# Centralized dictionary for remediation advice based on issue ID.
# Can be customized with server-specific advice (e.g., 'nginx', 'apache').
REMEDIATION_ADVICE = {
    "CERT_EXPIRED": {"default": "Renouvelez votre certificat SSL/TLS immédiatement."},
    "CERT_VERIFY_FAILED": {"default": "Vérifiez que votre chaîne de certificats est complète (certificats intermédiaires) et que le certificat n'est pas auto-signé."},
    "TLS_OBSOLETE": {"description": "Désactivez les protocoles SSL/TLS obsolètes.", "nginx": "Dans votre bloc server, utilisez : ssl_protocols TLSv1.2 TLSv1.3;", "apache": "Dans votre configuration SSL, utilisez : SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", "default": "Consultez la documentation de votre serveur pour désactiver SSLv3, TLSv1.0 et TLSv1.1."},
    "NO_HTTPS_REDIRECT": {"nginx": "Dans votre bloc server pour le port 80, utilisez : return 301 https://$host$request_uri;", "apache": "Utilisez mod_rewrite pour forcer la redirection vers HTTPS.", "default": "Configurez votre serveur web pour forcer la redirection de tout le trafic HTTP vers HTTPS."},
    "DMARC_MISSING": {"default": "Ajoutez un enregistrement DMARC à votre zone DNS pour protéger contre l'usurpation d'e-mail. Exemple : 'v=DMARC1; p=none; rua=mailto:dmarc-reports@votre-domaine.com;'"},
    "SPF_MISSING": {"default": "Ajoutez un enregistrement SPF à votre zone DNS pour spécifier les serveurs autorisés à envoyer des e-mails pour votre domaine. Exemple : 'v=spf1 include:_spf.google.com ~all'"},
    "COOKIE_NO_SECURE": {"default": "Ajoutez l'attribut 'Secure' à tous vos cookies pour vous assurer qu'ils ne sont envoyés que sur des connexions HTTPS."},
    "COOKIE_NO_HTTPONLY": {"default": "Ajoutez l'attribut 'HttpOnly' à vos cookies de session pour empêcher leur accès via JavaScript."},
    "COOKIE_NO_SAMESITE": {"default": "Ajoutez l'attribut 'SameSite=Strict' ou 'SameSite=Lax' à vos cookies pour vous protéger contre les attaques CSRF."},
    "HSTS_MISSING": {"nginx": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';", "apache": "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'", "default": "Implémentez l'en-tête HSTS avec un 'max-age' d'au moins 6 mois (15552000 secondes)."},
    "XFO_MISSING": {"nginx": "add_header X-Frame-Options 'SAMEORIGIN';", "apache": "Header always set X-Frame-Options 'SAMEORIGIN'", "default": "Ajoutez l'en-tête 'X-Frame-Options: SAMEORIGIN' ou 'DENY' pour vous protéger du clickjacking."},
    "XCTO_MISSING": {"nginx": "add_header X-Content-Type-Options 'nosniff';", "apache": "Header always set X-Content-Type-Options 'nosniff'", "default": "Ajoutez l'en-tête 'X-Content-Type-Options: nosniff'."},
    "CSP_MISSING": {"default": "Envisagez d'implémenter une Content Security Policy (CSP) pour une défense en profondeur contre les attaques par injection de script (XSS)."},
    "SERVER_HEADER_VISIBLE": {"nginx": "Dans votre configuration nginx, ajoutez 'server_tokens off;'.", "apache": "Dans votre configuration apache, ajoutez 'ServerTokens Prod'.", "default": "Supprimez ou masquez les en-têtes qui révèlent la version de votre serveur."},
    "JS_LIB_OBSOLETE": {"default": "Une ou plusieurs bibliothèques JavaScript sont obsolètes. Mettez-les à jour vers leur dernière version stable pour corriger les vulnérabilités connues."},
    "WP_CONFIG_BAK_EXPOSED": {"default": "Supprimez immédiatement le fichier de sauvegarde de configuration WordPress exposé publiquement."},
    "WP_USER_ENUM_ENABLED": {"default": "Empêchez l'énumération des utilisateurs sur WordPress, par exemple en utilisant un plugin de sécurité ou en ajoutant des règles de réécriture."}
}

# --- Consolidator Tool Configuration ---
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

QUICK_WIN_REMEDIATION_IDS = {
    "HSTS_MISSING", "XFO_MISSING", "XCTO_MISSING", "CSP_MISSING",
    "COOKIE_NO_SECURE", "COOKIE_NO_HTTPONLY", "COOKIE_NO_SAMESITE",
    "SERVER_HEADER_VISIBLE"
}

# --- Cookie Analyzer Configuration ---
CONSENT_BANNER_SELECTORS = [
    '[class*="cookie"]', '[id*="cookie"]',
    '[class*="consent"]', '[id*="consent"]',
    '[class*="gdpr"]', '[id*="gdpr"]'
]

# --- CMS Detection Configuration ---
CMS_PATHS = {
    'WordPress': ['/wp-login.php', '/wp-admin/'],
    'Joomla': ['/administrator/']
}

# --- Known JavaScript Libraries ---
KNOWN_JS_LIBRARIES = {
    "jquery": {"latest": "3.7.1", "ecosystem": "jQuery"},
    "react": {"latest": "18.2.0", "ecosystem": "npm"},
    "angular": {"latest": "1.7.9", "ecosystem": "npm"}
}

# --- Domain Parking Scorer Configuration ---
# Keywords for detecting "for sale" pages
KEYWORDS_FOR_SALE = [
    "domain for sale", "domaine à vendre", "buy this domain", "acheter ce domaine",
    "domain available", "domaine disponible", "purchase this domain", "acquire this domain",
    "this domain is for sale", "ce domaine est à vendre", "buy now", "acheter maintenant",
    "make an offer", "faire une offre", "for sale by owner", "vente par le propriétaire",
    "domain auction", "buy it now", "achat immédiat", "domain broker", "courtier domaine",
    "zu verkaufen", "te koop", "in vendita", "para la venta", "på salg", "for salg",
    "myydään", "sprzedaż", "продается", "出售", "inquire now", "contact owner",
    "contactez propriétaire", "renseignements", "price negotiable", "prix négociable",
    "best offer", "meilleure offre", "premium domain", "domaine premium",
    "valuable domain", "domaine de valeur", "investment opportunity",
    "opportunité d'investissement", "brandable domain", "domaine brandable",
    "exact match domain", "sedo", "afternic", "flippa", "dan.com", "undeveloped.com",
    "hugedomains", "godaddy auctions", "namecheap marketplace", "domain name sales",
    "vente nom de domaine", "click here to buy", "cliquez ici pour acheter",
    "purchase instantly", "instant buy", "achat instantané", "add to cart",
    "ajouter au panier", "checkout", "secure payment", "paiement sécurisé"
]

# Keywords for detecting generic parking pages
KEYWORDS_PARKING_GENERIC = [
    "parked domain", "domaine parqué", "domain parking", "parking de domaine",
    "parked free", "parqué gratuitement", "courtesy of", "gracieuseté de",
    "this domain is parked", "ce domaine est parqué", "domain name parking",
    "stationnement de nom de domaine", "under construction", "en construction",
    "coming soon", "bientôt disponible", "site under development", "site en développement",
    "website coming soon", "page temporarily unavailable", "page temporairement indisponible",
    "future home of", "futur domicile de", "placeholder page", "temporary page",
    "page temporaire", "work in progress", "bodis", "parkingcrew", "above.com",
    "domcollect", "nameservers.com", "sedoparking", "parking page", "default page",
    "page par défaut", "registrar default page", "page par défaut du registraire",
    "web hosting default page", "page par défaut hébergement", "sponsored links",
    "liens sponsorisés", "related searches", "recherches associées", "advertising",
    "publicité", "ads by", "publicités par", "revenue", "revenus", "monetization",
    "click here for", "cliquez ici pour", "search results", "résultats de recherche",
    "pay per click", "paiement par clic", "redirect", "redirection", "forwarding",
    "transfert", "this page will redirect", "cette page va rediriger",
    "automatic redirect", "redirection automatique", "default web site page",
    "page web par défaut", "test page", "page de test", "it works", "ça marche",
    "apache default", "nginx default", "iis default", "server default page",
    "welcome to", "bienvenue à", "congratulations", "félicitations"
]

# Keywords for detecting placeholder content
KEYWORDS_PLACEHOLDER_CONTENT = [
    "lorem ipsum", "placeholder text", "texte de remplacement", "sample text",
    "exemple de texte", "dummy text", "faux texte", "test content", "contenu de test",
    "default content", "contenu par défaut", "template", "modèle",
    "this is the default page", "ceci est la page par défaut", "no website configured",
    "aucun site web configuré", "account suspended", "compte suspendu",
    "service unavailable", "service indisponible", "bandwidth exceeded",
    "bande passante dépassée", "404 not found", "page not found", "page non trouvée",
    "503 service unavailable", "500 internal error", "maintenance mode",
    "mode maintenance", "offline", "hors ligne", "temporarily down", "temporairement arrêté"
]

# Keywords for detecting search-related pages
KEYWORDS_SEARCH_RELATED = [
    "search", "recherche", "find", "trouver", "discover", "découvrir", "explore",
    "explorer", "browse", "naviguer", "directory", "annuaire", "categories",
    "catégories", "topics", "sujets", "keywords", "mots-clés", "related to",
    "lié à", "similar to", "similaire à", "you might like", "vous pourriez aimer",
    "recommended", "recommandé", "suggested", "suggéré", "popular searches",
    "recherches populaires", "trending", "tendance", "most searched", "plus recherché"
]

# Keywords for detecting simple contact forms
KEYWORDS_CONTACT_FORMS = [
    "contact us", "contactez-nous", "get in touch", "prenez contact", "send message",
    "envoyer message", "inquiry", "demande", "contact form", "formulaire de contact",
    "email us", "envoyez-nous", "your name", "votre nom", "your email", "votre email",
    "subject", "sujet", "message", "phone number", "numéro téléphone"
]

# Regex patterns for detecting parking indicators
REGEX_PATTERNS_PARKING = [
    r'domain.*for sale', r'buy.*domain', r'parked.*domain', r'under construction',
    r'coming soon', r'this domain.*available', r'contact.*owner', r'make.*offer',
    r'sponsored.*links?', r'related.*searches?', r'click here.*', r'default.*page',
    r'placeholder.*page'
]

# Known parking service domains
PARKING_SERVICES = [
    "sedo.com", "parkingcrew.net", "bodis.com", "above.com", "domcollect.com",
    "afternic.com", "dan.com", "undeveloped.com", "hugedomains.com",
    "domainnameshop.com", "nameservers.com", "google.com/adsense",
    "googlesyndication.com", "doubleclick.net", "adsystem.com", "advertising.com",
    "yahoo.com", "bing.com", "godaddy.com", "namecheap.com", "1and1.com",
    "hostgator.com", "bluehost.com", "dreamhost.com"
]

# Known parking nameservers
KNOWN_PARKING_NAMESERVERS = [
    "sedoparking.com", "bodis.com", "parkingcrew.net", "above.com", "abovedomains.com",
    "uniregistrymarket.link", "huge-domains.com", "afternic.com", "dan.com"
]

# HTML indicators of parking
HTML_PARKING_INDICATORS = [
    'meta name="description" content="parked"',
    'meta name="keywords" content="domain for sale"',
    'meta name="robots" content="noindex"',
    'class="parked"', 'class="parking"', 'class="for-sale"', 'class="placeholder"',
    'class="coming-soon"', 'id="parking"', 'id="parked"', 'id="for-sale"',
    'id="placeholder"', 'id="under-construction"', 'parking.js', 'domain-parking.js',
    'ads.js', 'google_ad_client', 'googletag.cmd'
]
