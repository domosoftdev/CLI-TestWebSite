# CLI-TestWebSite - Outil d'Analyse de Sécurité Web

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[**English Version**](#english-version)

## Description
CLI-TestWebSite est un outil en ligne de commande conçu pour analyser la sécurité des sites web. Il permet de détecter les vulnérabilités courantes, de vérifier la configuration SSL/TLS, les en-têtes de sécurité, les technologies utilisées, et bien plus encore.

## Fonctionnalités
- **Analyse SSL/TLS** : Vérification des certificats, des protocoles et des chaînes de confiance.
- **En-têtes de sécurité** : Vérification des en-têtes HTTP (HSTS, CSP, X-Frame-Options, etc.).
- **Détection de CMS** : Identification des technologies utilisées (WordPress, etc.) et des vulnérabilités associées.
- **Analyse DNS/WHOIS** : Vérification des enregistrements DNS et des informations WHOIS.
- **Conformité RGPD** : Module expérimental pour vérifier la conformité RGPD.
- **Génération de rapports** : Rapports détaillés au format JSON, CSV et HTML.
- **Comparaison de scans** : Comparez les résultats de scans entre deux dates pour suivre l'évolution des vulnérabilités.
- **Graphiques d'évolution** : Générez des graphiques pour visualiser l'évolution du score de sécurité.

## Prérequis
- Python 3.8 ou supérieur
- Les dépendances listées dans `requirements.txt`

## Installation
1. Clonez ce dépôt :
   ```bash
   git clone https://github.com/domosoftdev/CLI-TestWebSite.git
   ```
2. Installez les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

## Utilisation
### Lancer une analyse
```bash
python main.py --domain example.com --formats json,html,csv
```

### Options disponibles
| Option | Description |
|--------|-------------|
| `--domain` | Nom de domaine à analyser (ex: `example.com`) |
| `--formats` | Formats de rapport à générer (ex: `json,html,csv`) |
| `--scans-dir` | Répertoire pour sauvegarder les rapports (par défaut : `scans`) |
| `--gdpr` | Active l'analyse de conformité RGPD (expérimental) |
| `--verbose` | Affiche des informations détaillées pendant l'exécution |
| `--list-scans DOMAIN` | Liste tous les scans disponibles pour un domaine. |
| `--compare DOMAIN DATE1 DATE2` | Compare les scans d'un domaine entre deux dates (format : `YYYY-MM-DD`). |
| `--status` | Affiche l'état des scans par rapport à une liste de cibles. |
| `--graph DOMAIN` | Génère un graphique d'évolution du score pour un domaine. |

### Exemples
- Générer un rapport JSON pour `example.com` :
  ```bash
  python main.py --domain example.com --formats json
  ```
- Générer un rapport HTML et CSV pour `example.com` avec des détails verbeux :
  ```bash
  python main.py --domain example.com --formats html,csv --verbose
  ```
- Lister les scans disponibles pour `example.com` :
  ```bash
  python main.py --list-scans example.com
  ```
- Comparer les scans de `example.com` entre le 01-01-2025 et le 01-02-2025 :
  ```bash
  python main.py --compare example.com 2025-01-01 2025-02-01
  ```
- Générer un graphique d'évolution pour `example.com` :
  ```bash
  python main.py --graph example.com
  ```

## Contribution
Les contributions sont les bienvenues ! Pour contribuer :
1. Fork ce dépôt.
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/ma-nouvelle-fonctionnalité`).
3. Commitez vos changements (`git commit -am 'Ajout d'une nouvelle fonctionnalité'`).
4. Poussez la branche (`git push origin feature/ma-nouvelle-fonctionnalité`).
5. Ouvrez une Pull Request.

## Licence
Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

# English Version

# CLI-TestWebSite - Web Security Analysis Tool

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[**Version Française**](#cli-testwebsite---outil-danalyse-de-sécurité-web)

## Description
CLI-TestWebSite is a command-line tool designed to analyze the security of websites. It detects common vulnerabilities, checks SSL/TLS configuration, security headers, technologies used, and much more.

## Features
- **SSL/TLS Analysis**: Certificate, protocol, and trust chain verification.
- **Security Headers**: HTTP headers check (HSTS, CSP, X-Frame-Options, etc.).
- **CMS Detection**: Identification of technologies used (WordPress, etc.) and associated vulnerabilities.
- **DNS/WHOIS Analysis**: DNS records and WHOIS information verification.
- **GDPR Compliance**: Experimental module to check GDPR compliance.
- **Report Generation**: Detailed reports in JSON, CSV, and HTML formats.
- **Scan Comparison**: Compare scan results between two dates to track vulnerability evolution.
- **Evolution Graphs**: Generate graphs to visualize the evolution of the security score.

## Requirements
- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/domosoftdev/CLI-TestWebSite.git
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
### Run an Analysis
```bash
python main.py --domain example.com --formats json,html,csv
```

### Available Options
| Option | Description |
|--------|-------------|
| `--domain` | Domain name to analyze (e.g., `example.com`) |
| `--formats` | Report formats to generate (e.g., `json,html,csv`) |
| `--scans-dir` | Directory to save reports (default: `scans`) |
| `--gdpr` | Enable GDPR compliance analysis (experimental) |
| `--verbose` | Display detailed information during execution |
| `--list-scans DOMAIN` | List all available scans for a domain. |
| `--compare DOMAIN DATE1 DATE2` | Compare scans of a domain between two dates (format: `YYYY-MM-DD`). |
| `--status` | Display the status of scans relative to a target list. |
| `--graph DOMAIN` | Generate an evolution graph of the score for a domain. |

### Examples
- Generate a JSON report for `example.com`:
  ```bash
  python main.py --domain example.com --formats json
  ```
- Generate an HTML and CSV report for `example.com` with verbose details:
  ```bash
  python main.py --domain example.com --formats html,csv --verbose
  ```
- List available scans for `example.com`:
  ```bash
  python main.py --list-scans example.com
  ```
- Compare scans of `example.com` between 01-01-2025 and 01-02-2025:
  ```bash
  python main.py --compare example.com 2025-01-01 2025-02-01
  ```
- Generate an evolution graph for `example.com`:
  ```bash
  python main.py --graph example.com
  ```

## Contribution
Contributions are welcome! To contribute:
1. Fork this repository.
2. Create a branch for your feature (`git checkout -b feature/my-new-feature`).
3. Commit your changes (`git commit -am 'Add a new feature'`).
4. Push the branch (`git push origin feature/my-new-feature`).
5. Open a Pull Request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.