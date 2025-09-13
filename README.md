[Read in English](README.en.md)

# Web Security Checker

Un outil simple en ligne de commande pour effectuer des vérifications de sécurité de base sur un site web.

## Description

Ce script Python analyse une URL donnée pour évaluer certains aspects de sa configuration de sécurité. C'est un outil de base destiné à fournir un aperçu rapide de la posture de sécurité d'un serveur web.

## Fonctionnalités

L'outil effectue les vérifications suivantes :

1.  **Certificat SSL/TLS** : Vérification de la chaîne de confiance et de la date d'expiration.
2.  **En-têtes de sécurité HTTP** : Analyse de la présence et de la configuration des en-têtes comme `Strict-Transport-Security`, `X-Frame-Options`, etc.
3.  **Redirections HTTPS** : S'assure que le trafic non sécurisé est redirigé vers HTTPS.
4.  **Protocoles SSL/TLS supportés** : Détecte les versions de protocoles obsolètes et vulnérables.
5.  **Enregistrements DNS de sécurité** : Vérifie la présence d'enregistrements comme `DMARC` et `SPF`.
6.  **Attributs des cookies** : Analyse des attributs `HttpOnly`, `Secure` et `SameSite`.
7.  **Informations WHOIS** : Récupération des données publiques du domaine.
8.  **Score de Parking** : Évalue la probabilité qu'un domaine soit "parké".

## Installation

1.  Assurez-vous d'avoir Python 3 installé sur votre système.
2.  Clonez ce dépôt.
3.  Installez les dépendances nécessaires en utilisant pip :

    ```bash
    pip install -r requirements.txt
    ```

## Utilisation

L'application est maintenant centralisée dans `main.py` et s'utilise avec des arguments en ligne de commande.

### Lancer une nouvelle analyse

Pour analyser un site web, utilisez l'argument `--domain`.

```bash
python3 main.py --domain google.com
```

#### Spécifier le répertoire de sortie

Par défaut, les rapports sont sauvegardés dans un répertoire `scans/`. Vous pouvez spécifier un autre répertoire avec l'argument `--scans-dir`. Ce répertoire sera utilisé à la fois pour la lecture des scans existants et la sauvegarde des nouveaux rapports.

```bash
python3 main.py --domain google.com --formats json --scans-dir /chemin/vers/mes/rapports
```

#### Générer des rapports

Vous pouvez générer des rapports aux formats JSON, CSV ou HTML avec l'argument `--formats`.

```bash
python3 main.py --domain google.com --formats json,csv,html
```

### Analyser les scans existants

L'outil fournit plusieurs commandes pour analyser l'historique des scans que vous avez générés.

#### Lister les scans pour un domaine

Utilisez `--list-scans` pour voir tous les rapports sauvegardés pour un domaine.

```bash
python3 main.py --list-scans google.com
```

#### Comparer deux scans

Utilisez `--compare` pour voir les changements (régressions ou améliorations) entre deux dates.

```bash
python3 main.py --compare google.com 2025-08-17 2025-08-18
```

#### Générer un graphique d'évolution

Utilisez `--graph` pour générer une image (`<domaine>_evolution.png`) montrant l'évolution du score de sécurité dans le temps.

**Note importante :** Cette fonctionnalité génère un fichier image statique. Il n'y a **pas d'application web** interactive.

```bash
python3 main.py --graph google.com
```

Le graphique sera sauvegardé dans le répertoire spécifié par `--scans-dir` (ou `scans/` par défaut).

#### Autres commandes de reporting

D'autres commandes comme `--status`, `--oldest`, `--quick-wins`, etc. sont également disponibles. Utilisez `python3 main.py --help` pour voir la liste complète des options.
