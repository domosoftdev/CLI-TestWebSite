# -*- coding: utf-8 -*-

"""
Module principal pour l'analyse de sécurité de site web.
Contient la logique pour vérifier les certificats, les en-têtes, et plus encore.
"""

import socket
import ssl
import requests
import re
import whois
import dns.resolver
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from packaging import version
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
)
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import general_name
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from sslyze.plugins.scan_commands import ScanCommand

# Importation depuis la nouvelle structure de modules et configuration
from src.config import (
    SEVERITY_SCORES,
    OSV_API_URL,
    KNOWN_JS_LIBRARIES,
    DEFAULT_TIMEOUT,
    CMS_PATHS
)
from src.analyzers.parking import calculate_parking_score
from src.analyzers.gdpr import GDPRChecker

class SecurityAnalyzer:
    """
    Classe principale pour orchestrer les différents scans de sécurité.
    """
    def __init__(self, verbose=False):
        self.verbose = verbose

    def analyze(self, hostname, perform_gdpr_check=False):
        """
        Lance une analyse de sécurité complète pour un nom de domaine donné.
        """
        if self.verbose:
            print(f"Lancement de l'analyse de sécurité complète pour {hostname}...")

        all_results = {'hostname': hostname}

        if perform_gdpr_check:
            if self.verbose:
                print("Lancement du sous-module d'analyse RGPD...")
            gdpr_checker = GDPRChecker(verbose=self.verbose)
            all_results['gdpr_compliance'] = gdpr_checker.check_gdpr_compliance(f"https://{hostname}")

        # Exécution des différents modules de scan
        ssl_cert_result = self._check_ssl_certificate(hostname)
        all_results['ssl_certificate'] = ssl_cert_result

        all_results['tls_protocols'] = self._scan_tls_protocols(hostname)
        all_results['http_redirect'] = self._check_http_to_https_redirect(hostname)
        all_results['security_headers'] = self._check_security_headers(hostname, ssl_cert_result=ssl_cert_result)
        all_results['cookie_security'] = self._check_cookie_security(hostname, ssl_cert_result=ssl_cert_result)
        all_results['cms_footprint_meta'] = self._check_cms_footprint(hostname, ssl_cert_result=ssl_cert_result)
        all_results['cms_footprint_paths'] = self._check_cms_paths(hostname, ssl_cert_result=ssl_cert_result)

        is_wordpress = any(path.get('cms') == 'WordPress' for path in all_results.get('cms_footprint_paths', []))
        if is_wordpress:
            if self.verbose:
                print("WordPress détecté, lancement des scans spécifiques...")
            all_results['wordpress_specifics'] = self._check_wordpress_specifics(hostname, ssl_cert_result=ssl_cert_result)

        all_results['dns_records'] = self._check_dns_records(hostname)
        all_results['js_libraries'] = self._check_js_libraries(hostname, ssl_cert_result=ssl_cert_result)
        all_results['whois_info'] = self._check_whois_info(hostname)
        all_results['parking_score'] = calculate_parking_score(hostname, verbose=self.verbose)

        # Calcul du score final
        score, grade = self._calculate_score(all_results)
        all_results['score_final'] = score
        all_results['note'] = grade

        if self.verbose:
            print(f"Analyse de sécurité terminée pour {hostname}. Score final: {score} ({grade})")

        return all_results

    def _calculate_score(self, results):
        """Calcule le score de dangerosité et la note associée."""
        total_score = 0

        def traverse_results(data):
            nonlocal total_score
            if isinstance(data, dict):
                if 'criticite' in data:
                    total_score += SEVERITY_SCORES.get(data['criticite'], 0)
                for value in data.values():
                    traverse_results(value)
            elif isinstance(data, list):
                for item in data:
                    traverse_results(item)

        traverse_results(results)

        if total_score == 0: grade = "A+"
        elif total_score <= 10: grade = "A"
        elif total_score <= 20: grade = "B"
        elif total_score <= 40: grade = "C"
        elif total_score <= 60: grade = "D"
        else: grade = "F"

        return total_score, grade

    def _query_osv_api(self, package_name, version, ecosystem):
        query = {"version": version, "package": {"name": package_name, "ecosystem": ecosystem}}
        try:
            response = requests.post(OSV_API_URL, json=query, timeout=15)
            if response.status_code == 200 and response.json().get('vulns'):
                return response.json()['vulns']
        except requests.exceptions.RequestException:
            return None
        return None

    def _check_ssl_certificate(self, hostname):
        if self.verbose: print(f"  - Vérification du certificat SSL pour {hostname}")
        try:
            server_location = ServerNetworkLocation(hostname=hostname, port=443)
            scan_request = ServerScanRequest(server_location=server_location, scan_commands={ScanCommand.CERTIFICATE_INFO})
            scanner = Scanner()
            scanner.queue_scans([scan_request])

            for result in scanner.get_results():
                if result.scan_status != ServerScanStatusEnum.COMPLETED:
                    return {"statut": "ERROR", "message": "La connexion au serveur a échoué.", "criticite": "HIGH"}

                cert_info_attempt = result.scan_result.certificate_info
                if cert_info_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    return {"statut": "ERROR", "message": f"Scan de certificat échoué: {cert_info_attempt.error_reason}", "criticite": "HIGH"}

                cert_info = cert_info_attempt.result
                if not cert_info.certificate_deployments:
                    return {"statut": "ERROR", "message": "Aucun certificat reçu.", "criticite": "HIGH"}

                deployment = cert_info.certificate_deployments[0]
                leaf_cert = deployment.received_certificate_chain[0]
                validation = deployment.path_validation_results[0]

                points_a_corriger = []

                # 1. Chain of trust
                if not validation.was_validation_successful:
                    error_str = str(validation.validation_error)
                    if "unable to get local issuer certificate" in error_str or "candidates exhausted" in error_str:
                        points_a_corriger.append({
                            "message": "La chaîne de certificats est incomplète. Le serveur ne fournit probablement pas tous les certificats intermédiaires.",
                            "criticite": "MEDIUM",
                            "remediation_id": "SSL_CHAIN_INCOMPLETE"
                        })
                    else:
                        points_a_corriger.append({
                            "message": f"La chaîne de certificats n'est pas fiable: {error_str}",
                            "criticite": "HIGH",
                            "remediation_id": "SSL_CHAIN_UNTRUSTED"
                        })

                # 2. Temporal Validity
                jours_restants = (leaf_cert.not_valid_after_utc - datetime.now(timezone.utc)).days
                if jours_restants < 0:
                    points_a_corriger.append({"message": "Le certificat a expiré.", "criticite": "CRITICAL"})
                elif jours_restants < 30:
                    points_a_corriger.append({"message": f"Le certificat expire bientôt (dans {jours_restants} jours).", "criticite": "LOW"})

                # 3. Crypto Strength
                public_key = leaf_cert.public_key()
                key_info = "Inconnu"
                if isinstance(public_key, rsa.RSAPublicKey):
                    key_info = f"RSA {public_key.key_size} bits"
                    if public_key.key_size < 2048:
                        points_a_corriger.append({"message": f"La taille de la clé RSA ({public_key.key_size} bits) est inférieure au minimum recommandé de 2048 bits.", "criticite": "HIGH"})
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_info = f"ECDSA {public_key.curve.name} ({public_key.curve.key_size} bits)"
                    if public_key.curve.key_size < 256:
                         points_a_corriger.append({"message": f"La taille de la clé ECDSA ({public_key.curve.key_size} bits) est inférieure au minimum recommandé de 256 bits.", "criticite": "HIGH"})

                sig_algo = leaf_cert.signature_hash_algorithm.name if leaf_cert.signature_hash_algorithm else "inconnu"
                if sig_algo.lower() in ['md5', 'sha1']:
                     points_a_corriger.append({"message": f"L'algorithme de signature ({sig_algo}) est faible et obsolète.", "criticite": "HIGH"})

                # Final result construction
                result_dict = {
                    "statut": "SUCCESS",
                    "message": "Analyse du certificat terminée.",
                    "criticite": "INFO",
                    "points_a_corriger": points_a_corriger,
                    "details": {
                        "date_expiration": leaf_cert.not_valid_after_utc.strftime('%Y-%m-%d'),
                        "jours_restants": jours_restants,
                        "noms_alternatifs_sujet (SAN)": [name for name in leaf_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(general_name.DNSName)],
                        "chaine_de_certificats": [{
                            "sujet": cert.subject.rfc4514_string(),
                            "emetteur": cert.issuer.rfc4514_string(),
                            "is_problematic": not validation.was_validation_successful and i == len(deployment.received_certificate_chain) - 1
                        } for i, cert in enumerate(deployment.received_certificate_chain)],
                        "force_cle_publique": key_info,
                        "algorithme_signature": sig_algo,
                    }
                }
                return result_dict

        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"statut": "ERROR", "message": f"Erreur inattendue: {e}", "criticite": "HIGH"}

    def _scan_tls_protocols(self, hostname):
        if self.verbose: print(f"  - Scan des protocoles TLS pour {hostname}")
        results = []
        try:
            server_location = ServerNetworkLocation(hostname=hostname, port=443)
            scan_request = ServerScanRequest(server_location=server_location, scan_commands={ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES})
            scanner = Scanner()
            scanner.queue_scans([scan_request])
            for result in scanner.get_results():
                if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                    return [{"statut": "ERROR", "message": f"Impossible de se connecter à {hostname} pour le scan TLS.", "criticite": "HIGH"}]
                proto_scans = {"SSL 2.0": result.scan_result.ssl_2_0_cipher_suites, "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites, "TLS 1.0": result.scan_result.tls_1_0_cipher_suites, "TLS 1.1": result.scan_result.tls_1_1_cipher_suites, "TLS 1.2": result.scan_result.tls_1_2_cipher_suites, "TLS 1.3": result.scan_result.tls_1_3_cipher_suites}
                for name, scan in proto_scans.items():
                    if scan.status == ScanCommandAttemptStatusEnum.ERROR: continue
                    if scan.result.accepted_cipher_suites:
                        crit = "HIGH" if name in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] else "INFO"
                        res = {"protocole": name, "statut": "ERROR" if crit == "HIGH" else "SUCCESS", "message": "Supporté", "criticite": crit}
                        if crit == "HIGH": res["remediation_id"] = "TLS_OBSOLETE"
                        results.append(res)
                    else:
                        results.append({"protocole": name, "statut": "SUCCESS", "message": "Non supporté", "criticite": "INFO"})
                return results
        except Exception as e:
            import traceback
            traceback.print_exc()
            return [{"statut": "ERROR", "message": f"Erreur inattendue lors du scan sslyze: {e}", "criticite": "HIGH"}]

    def _check_http_to_https_redirect(self, hostname):
        if self.verbose: print(f"  - Vérification de la redirection HTTP->HTTPS pour {hostname}")
        try:
            response = requests.get(f"http://{hostname}", allow_redirects=False, timeout=DEFAULT_TIMEOUT)
            if 300 <= response.status_code < 400 and response.headers.get('Location', '').startswith('https://'):
                return {"statut": "SUCCESS", "message": "Redirection correcte vers HTTPS.", "criticite": "INFO"}
            return {"statut": "ERROR", "message": "La redirection de HTTP vers HTTPS n'est pas correctement configurée.", "criticite": "MEDIUM", "remediation_id": "NO_HTTPS_REDIRECT"}
        except requests.exceptions.RequestException as e:
            return {"statut": "ERROR", "message": f"Erreur lors du test de redirection: {e}", "criticite": "HIGH"}

    def _check_dns_records(self, hostname):
        if self.verbose: print(f"  - Vérification des enregistrements DNS pour {hostname}")
        results = {}
        try:
            ns_ans = dns.resolver.resolve(hostname, 'NS'); results['ns'] = {"statut": "SUCCESS", "valeurs": [str(r.target) for r in ns_ans], "criticite": "INFO"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e: results['ns'] = {"statut": "ERROR", "message": f"Impossible de récupérer les enregistrements NS ({e})", "criticite": "LOW"}
        try:
            a_ans = dns.resolver.resolve(hostname, 'A'); results['a'] = {"statut": "SUCCESS", "valeurs": [r.address for r in a_ans], "criticite": "INFO"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e: results['a'] = {"statut": "ERROR", "message": f"Impossible de récupérer les enregistrements A ({e})", "criticite": "LOW"}
        try:
            mx_ans = dns.resolver.resolve(hostname, 'MX'); mx_records = sorted([(r.preference, str(r.exchange)) for r in mx_ans]); results['mx'] = {"statut": "SUCCESS", "valeurs": [f"Prio {p}: {e}" for p, e in mx_records], "criticite": "INFO"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e: results['mx'] = {"statut": "ERROR", "message": f"Impossible de récupérer les enregistrements MX ({e})", "criticite": "LOW"}
        try:
            dmarc_ans = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
            # A domain should only have one DMARC record, but it can be split into multiple strings.
            # We take the first answer and concatenate its parts without spaces.
            dmarc_rec = b"".join(dmarc_ans[0].strings).decode()
            results['dmarc'] = {"statut": "SUCCESS", "valeur": dmarc_rec, "criticite": "INFO"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, IndexError):
            results['dmarc'] = {"statut": "ERROR", "message": "Aucun enregistrement DMARC trouvé.", "criticite": "HIGH", "remediation_id": "DMARC_MISSING"}

        try:
            txt_ans = dns.resolver.resolve(hostname, 'TXT')
            spf_rec = None
            # A domain can have multiple TXT records. We need to find the SPF one.
            for rdata in txt_ans:
                # Each rdata can have multiple strings, which should be concatenated.
                txt_content = b"".join(rdata.strings).decode()
                if txt_content.startswith('v=spf1'):
                    spf_rec = txt_content
                    break  # Found SPF record, no need to check others

            if spf_rec:
                results['spf'] = {"statut": "SUCCESS", "valeur": spf_rec, "criticite": "INFO"}
            else:
                results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement SPF trouvé.", "criticite": "HIGH", "remediation_id": "SPF_MISSING"}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement TXT trouvé.", "criticite": "HIGH", "remediation_id": "SPF_MISSING"}
        return results

    def _check_cookie_security(self, hostname, ssl_cert_result=None):
        if self.verbose: print(f"  - Analyse des cookies pour {hostname}")
        results = []
        try:
            response = requests.get(f"https://{hostname}", timeout=DEFAULT_TIMEOUT)
            raw_cookies = response.raw.headers.get_all('Set-Cookie', [])
            if not raw_cookies: return [{"statut": "INFO", "message": "Aucun cookie n'a été défini par le serveur.", "criticite": "INFO"}]
            for header in raw_cookies:
                parts = [p.strip().lower() for p in header.split(';')]
                cookie_name = parts[0].split('=')[0]; attributes = set(parts[1:])
                cookie_res = {"nom": cookie_name}; secure_ok = 'secure' in attributes; httponly_ok = 'httponly' in attributes; samesite_ok = any(a.startswith('samesite=') for a in attributes)
                cookie_res["secure"] = {"present": secure_ok, "criticite": "INFO" if secure_ok else "HIGH", "remediation_id": "COOKIE_NO_SECURE"}
                cookie_res["httponly"] = {"present": httponly_ok, "criticite": "INFO" if httponly_ok else "MEDIUM", "remediation_id": "COOKIE_NO_HTTPONLY"}
                cookie_res["samesite"] = {"present": samesite_ok, "criticite": "INFO" if samesite_ok else "MEDIUM", "remediation_id": "COOKIE_NO_SAMESITE"}
                results.append(cookie_res)
            return results
        except requests.exceptions.SSLError:
            if ssl_cert_result and ssl_cert_result.get('points_a_corriger'):
                return [{"statut": "INFO", "message": "Analyse sautée à cause d'un problème de configuration SSL déjà identifié.", "criticite": "INFO"}]
            return [{"statut": "ERROR", "message": "Erreur SSL lors de la connexion.", "criticite": "HIGH"}]
        except requests.exceptions.RequestException as e:
            return [{"statut": "ERROR", "message": f"Erreur lors de la récupération des cookies: {e}", "criticite": "HIGH"}]

    def _check_security_headers(self, hostname, ssl_cert_result=None):
        if self.verbose: print(f"  - Analyse des en-têtes de sécurité pour {hostname}")
        results = {"empreinte": [], "en-tetes_securite": {}}
        try:
            response = requests.get(f"https://{hostname}", timeout=DEFAULT_TIMEOUT); headers = {k.lower(): v for k, v in response.headers.items()}; results['url_finale'] = response.url
            for h in ['server', 'x-powered-by', 'x-aspnet-version']:
                if h in headers: results['empreinte'].append({"header": h, "valeur": headers[h], "criticite": "LOW", "remediation_id": "SERVER_HEADER_VISIBLE"})
            hsts_header = headers.get('strict-transport-security')
            if hsts_header and 'max-age' in hsts_header and int(hsts_header.split('max-age=')[1].split(';')[0]) >= 15552000: results['en-tetes_securite']['hsts'] = {"statut": "SUCCESS", "criticite": "INFO"}
            else: results['en-tetes_securite']['hsts'] = {"statut": "ERROR", "criticite": "HIGH", "remediation_id": "HSTS_MISSING"}
            xfo_header = headers.get('x-frame-options', '').upper()
            if xfo_header in ['DENY', 'SAMEORIGIN']: results['en-tetes_securite']['x-frame-options'] = {"statut": "SUCCESS", "criticite": "INFO"}
            else: results['en-tetes_securite']['x-frame-options'] = {"statut": "ERROR", "criticite": "MEDIUM", "remediation_id": "XFO_MISSING"}
            xcto_header = headers.get('x-content-type-options', '').lower()
            if xcto_header == 'nosniff': results['en-tetes_securite']['x-content-type-options'] = {"statut": "SUCCESS", "criticite": "INFO"}
            else: results['en-tetes_securite']['x-content-type-options'] = {"statut": "ERROR", "criticite": "MEDIUM", "remediation_id": "XCTO_MISSING"}
            csp_header = headers.get('content-security-policy')
            if csp_header: results['en-tetes_securite']['csp'] = {"statut": "SUCCESS", "criticite": "INFO"}
            else: results['en-tetes_securite']['csp'] = {"statut": "WARNING", "criticite": "LOW", "remediation_id": "CSP_MISSING"}
            return results
        except requests.exceptions.SSLError:
            if ssl_cert_result and ssl_cert_result.get('points_a_corriger'):
                return {"statut": "INFO", "message": "Analyse sautée à cause d'un problème de configuration SSL déjà identifié.", "criticite": "INFO"}
            return {"statut": "ERROR", "message": "Erreur SSL lors de la connexion.", "criticite": "HIGH"}
        except requests.exceptions.RequestException as e:
            return {"statut": "ERROR", "message": f"Erreur lors de la récupération des en-têtes: {e}", "criticite": "HIGH"}

    def _check_cms_footprint(self, hostname, ssl_cert_result=None):
        if self.verbose: print(f"  - Recherche d'empreinte CMS pour {hostname}")
        try:
            response = requests.get(f"https://{hostname}", timeout=DEFAULT_TIMEOUT); soup = BeautifulSoup(response.content, 'lxml'); gen_tag = soup.find('meta', attrs={'name': 'generator'})
            if gen_tag and gen_tag.get('content'): return {"statut": "INFO", "message": f"Balise 'generator' trouvée: {gen_tag.get('content')}", "criticite": "INFO"}
            return {"statut": "INFO", "message": "Aucune balise meta 'generator' trouvée.", "criticite": "INFO"}
        except requests.exceptions.SSLError:
            if ssl_cert_result and ssl_cert_result.get('points_a_corriger'):
                return {"statut": "INFO", "message": "Analyse sautée à cause d'un problème de configuration SSL déjà identifié.", "criticite": "INFO"}
            return {"statut": "ERROR", "message": "Erreur SSL lors de la connexion.", "criticite": "HIGH"}
        except requests.exceptions.RequestException as e:
            return {"statut": "ERROR", "message": f"Erreur lors de l'analyse CMS: {e}", "criticite": "HIGH"}

    def _check_cms_paths(self, hostname, ssl_cert_result=None):
        if self.verbose: print(f"  - Vérification des chemins CMS connus pour {hostname}")
        results = []
        for cms, path_list in CMS_PATHS.items():
            for path in path_list:
                try:
                    if requests.head(f"https://{hostname}{path}", timeout=3, allow_redirects=True).status_code in [200, 302, 301]: results.append({"cms": cms, "path": path, "criticite": "INFO"})
                except requests.exceptions.SSLError:
                    # Don't report for every single path, just break
                    break
                except requests.exceptions.RequestException: continue
        return results

    def _check_js_libraries(self, hostname, ssl_cert_result=None):
        if self.verbose: print(f"  - Analyse des bibliothèques JavaScript pour {hostname}")
        results = []
        detected_libs = {}
        try:
            response = requests.get(f"https://{hostname}", timeout=DEFAULT_TIMEOUT)
            soup = BeautifulSoup(response.content, 'lxml')
            for script in soup.find_all('script', src=True):
                src = script['src']
                match = re.search(r'([a-zA-Z0-9.-]+?)[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:[._-]min)?\.js', src)
                if match:
                    lib_name = match.group(1).lower()
                    detected_version_str = match.group(2)
                    if lib_name in KNOWN_JS_LIBRARIES and lib_name not in detected_libs:
                        detected_libs[lib_name] = {"version": detected_version_str, "source": "filename"}
            for script in soup.find_all('script'):
                content = script.string
                if not content: continue
                if 'jquery' not in detected_libs and ('jQuery' in content or re.search(r'\$\s*\(', content)):
                    detected_libs['jquery'] = {"version": "inconnu", "source": "inline content"}
                if 'react' not in detected_libs and 'React.createElement' in content:
                    detected_libs['react'] = {"version": "inconnu", "source": "inline content"}
                if 'angular' not in detected_libs and 'angular.module' in content:
                    detected_libs['angular'] = {"version": "inconnu", "source": "inline content"}
            for lib_name, data in detected_libs.items():
                lib_info = KNOWN_JS_LIBRARIES[lib_name]
                latest_version_str = lib_info["latest"]
                detected_version_str = data["version"]
                result_entry = {"bibliotheque": lib_name, "version_detectee": detected_version_str, "derniere_version": latest_version_str, "vulnerabilities": []}
                if detected_version_str == "inconnu":
                    result_entry.update({"statut": "WARNING", "criticite": "LOW", "message": "Bibliothèque détectée mais version inconnue."})
                else:
                    try:
                        detected_v = version.parse(detected_version_str)
                        latest_v = version.parse(latest_version_str)
                        if detected_v < latest_v:
                            result_entry.update({"statut": "WARNING", "criticite": "MEDIUM", "remediation_id": "JS_LIB_OBSOLETE"})
                            vulns = self._query_osv_api(lib_name, detected_version_str, lib_info["ecosystem"])
                            if vulns:
                                result_entry["criticite"] = "HIGH"
                                for v in vulns: result_entry["vulnerabilities"].append({"id": v.get('id'), "summary": v.get('summary', 'Pas de résumé.'), "details": v.get('details', '')})
                        else:
                            result_entry.update({"statut": "SUCCESS", "criticite": "INFO"})
                    except version.InvalidVersion:
                        continue
                results.append(result_entry)
        except requests.exceptions.SSLError:
            if ssl_cert_result and ssl_cert_result.get('points_a_corriger'):
                return [{"statut": "INFO", "message": "Analyse sautée à cause d'un problème de configuration SSL déjà identifié.", "criticite": "INFO"}]
            return [{"statut": "ERROR", "message": "Erreur SSL lors de la connexion.", "criticite": "HIGH"}]
        except requests.exceptions.RequestException as e:
            return [{"statut": "ERROR", "message": f"Erreur lors de l'analyse des bibliothèques JS: {e}", "criticite": "HIGH"}]
        return results

    def _check_wordpress_specifics(self, hostname, ssl_cert_result=None):
        if self.verbose: print(f"  - Vérification des points spécifiques à WordPress pour {hostname}")
        results = {}; base_url = f"https://{hostname}"
        try:
            url = f"{base_url}/wp-config.php.bak"; response = requests.head(url, timeout=5, allow_redirects=False)
            if response.status_code == 200: results['config_backup'] = {"statut": "ERROR", "criticite": "CRITICAL", "message": f"Le fichier de sauvegarde {url} est exposé publiquement.", "remediation_id": "WP_CONFIG_BAK_EXPOSED"}
            else: results['config_backup'] = {"statut": "SUCCESS", "criticite": "INFO", "message": "Le fichier wp-config.php.bak n'a pas été trouvé."}
        except requests.exceptions.SSLError:
             results['config_backup'] = {"statut": "INFO", "criticite": "INFO", "message": "Analyse sautée à cause d'un problème de configuration SSL déjà identifié."}
        except requests.exceptions.RequestException: results['config_backup'] = {"statut": "INFO", "criticite": "INFO", "message": "Erreur réseau lors de la vérification de wp-config.php.bak."}
        try:
            url = f"{base_url}/?author=1"; response = requests.get(url, timeout=5, allow_redirects=False); location = response.headers.get('Location', '')
            if 300 <= response.status_code < 400 and '/author/' in location:
                username = location.split('/author/')[1].split('/')[0]; results['user_enum'] = {"statut": "ERROR", "criticite": "MEDIUM", "message": f"L'énumération d'utilisateurs est possible. Nom d'utilisateur trouvé : '{username}'.", "remediation_id": "WP_USER_ENUM_ENABLED"}
            else: results['user_enum'] = {"statut": "SUCCESS", "criticite": "INFO", "message": "L'énumération d'utilisateurs via ?author=1 ne semble pas possible."}
        except requests.exceptions.SSLError:
             results['user_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Analyse sautée à cause d'un problème de configuration SSL déjà identifié."}
        except requests.exceptions.RequestException: results['user_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Erreur réseau lors de la vérification de l'énumération d'utilisateurs."}
        try:
            response = requests.get(base_url, timeout=DEFAULT_TIMEOUT); soup = BeautifulSoup(response.content, 'lxml'); plugin_pattern = re.compile(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/'); found_plugins = set()
            for tag in soup.find_all(['link', 'script'], href=True) + soup.find_all('script', src=True):
                url = tag.get('href') or tag.get('src')
                if url:
                    match = plugin_pattern.search(url)
                    if match: found_plugins.add(match.group(1))
            if found_plugins: results['plugin_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Plugins détectés", "plugins": list(found_plugins)}
            else: results['plugin_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Aucun plugin détecté depuis la page d'accueil."}
        except requests.exceptions.SSLError:
            results['plugin_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Analyse sautée à cause d'un problème de configuration SSL déjà identifié."}
        except requests.exceptions.RequestException: results['plugin_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Erreur réseau lors de l'énumération des plugins."}
        return results

    def _format_whois_value(self, value):
        if isinstance(value, list):
            # Process each item in the list, applying timezone info to datetimes
            formatted_list = []
            for item in value:
                if isinstance(item, datetime):
                    # If datetime is naive, make it timezone-aware (UTC)
                    if item.tzinfo is None:
                        formatted_list.append(item.replace(tzinfo=timezone.utc).isoformat())
                    else:
                        formatted_list.append(item.isoformat())
                else:
                    formatted_list.append(str(item))
            return ", ".join(formatted_list)

        if isinstance(value, datetime):
            # If datetime is naive, make it timezone-aware (UTC)
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc).isoformat()
            return value.isoformat()

        return str(value) if value is not None else "N/A"

    def _check_whois_info(self, hostname):
        if self.verbose: print(f"  - Récupération des informations WHOIS pour {hostname}")
        try:
            w = whois.whois(hostname)
            if not hasattr(w, 'domain_name') or w.domain_name is None:
                return {"statut": "ERROR", "message": "Aucune donnée WHOIS trouvée.", "criticite": "LOW"}

            registrant_address = [
                self._format_whois_value(w.get('address')), self._format_whois_value(w.get('city')),
                self._format_whois_value(w.get('state')), self._format_whois_value(w.get('zipcode')),
                self._format_whois_value(w.get('country'))
            ]

            return {
                "statut": "SUCCESS", "criticite": "INFO",
                "registrar": self._format_whois_value(w.get('registrar')),
                "creation_date": self._format_whois_value(w.get('creation_date')),
                "expiration_date": self._format_whois_value(w.get('expiration_date')),
                "updated_date": self._format_whois_value(w.get('updated_date')),
                "domain_status": self._format_whois_value(w.get('status')),
                "name_servers": self._format_whois_value(w.get('name_servers')),
                "dnssec": "Activé" if w.get('dnssec') else "Désactivé ou non trouvé",
                "registrant_name": self._format_whois_value(w.get('name')),
                "registrant_org": self._format_whois_value(w.get('org')),
                "registrant_address": ", ".join(filter(lambda x: x and x != "N/A", registrant_address)) or "N/A",
            }
        except whois.parser.PywhoisError as e:
            return {"statut": "ERROR", "message": f"Impossible de récupérer les informations WHOIS : {e}", "criticite": "LOW"}
