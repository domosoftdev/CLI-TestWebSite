import unittest
import socket
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, mock_open

import dns.resolver
import dns.resolver
from sslyze import ScanCommand, ServerScanStatusEnum, ScanCommandAttemptStatusEnum
from security_analyzer import (
    get_hostname,
    _format_whois_value,
    calculate_score,
    check_security_headers,
    check_ssl_certificate,
    check_http_to_https_redirect,
    check_dns_records,
    scan_tls_protocols,
    check_cookie_security,
    check_cms_footprint,
    check_whois_info,
    print_human_readable_report,
    generate_csv_report,
    generate_html_report,
)


class TestSecurityAnalyzerHelpers(unittest.TestCase):
    def test_get_hostname(self):
        # This test now requires the corrected get_hostname function
        from urllib.parse import urlparse
        urls_to_test = {
            "https://www.google.com/path": "www.google.com",
            "http://google.com/path": "google.com",
            "www.example.co.uk/": "www.example.co.uk",
            "https://sub.domain.org": "sub.domain.org",
            "ftp://ftp.example.com": "ftp.example.com",
            "bare-domain.com": "bare-domain.com",
        }
        for url, expected_hostname in urls_to_test.items():
            with self.subTest(url=url):
                self.assertEqual(get_hostname(url), expected_hostname)

    def test_format_whois_value(self):
        test_time = datetime(2023, 10, 27, 10, 0, 0)
        test_cases = {
            "simple_string": ("hello", "hello"),
            "datetime_object": (test_time, "2023-10-27T10:00:00"),
            "list_of_strings": (["a", "b"], "a, b"),
            "none_value": (None, "N/A"),
        }
        for name, (input_val, expected_val) in test_cases.items():
            with self.subTest(name=name):
                self.assertEqual(_format_whois_value(input_val), expected_val)

    def test_calculate_score(self):
        test_data = {
            "test1": {"criticite": "CRITICAL"},
            "test2": [{"criticite": "HIGH"}],
            "test3": {"sub": {"criticite": "MEDIUM"}},
        }
        score, grade = calculate_score(test_data)
        self.assertEqual(score, 21) # 10 + 7 + 4
        self.assertEqual(grade, "C")


class TestSecurityAnalyzerNetwork(unittest.TestCase):

    @patch("security_analyzer.ssl.create_default_context")
    @patch("security_analyzer.socket.create_connection")
    def test_check_ssl_certificate_valid(self, mock_create_connection, mock_create_context):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "*.example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notAfter": (datetime.now() + timedelta(days=365)).strftime(
                "%b %d %H:%M:%S %Y GMT"
            ),
        }
        mock_socket_cm = MagicMock()
        mock_socket_cm.__enter__.return_value = mock_ssock
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_socket_cm
        mock_create_context.return_value = mock_context

        result = check_ssl_certificate("example.com")
        self.assertEqual(result["statut"], "SUCCESS")

    @patch("security_analyzer.socket.create_connection", side_effect=socket.timeout)
    def test_check_ssl_certificate_timeout(self, mock_create_connection):
        result = check_ssl_certificate("example.com")
        self.assertEqual(result["statut"], "ERROR")
        self.assertIn("timeout", result["message"])

    @patch("security_analyzer.requests.get")
    def test_check_security_headers_all_good(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
        }
        mock_response.url = "https://example.com"
        mock_get.return_value = mock_response
        results = check_security_headers("example.com")
        headers = results["en-tetes_securite"]
        self.assertEqual(headers["hsts"]["statut"], "SUCCESS")

    @patch("security_analyzer.requests.get")
    def test_check_http_to_https_redirect_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.headers = {"Location": "https://example.com"}
        mock_get.return_value = mock_response
        result = check_http_to_https_redirect("example.com")
        self.assertEqual(result["statut"], "SUCCESS")

    @patch("security_analyzer.dns.resolver.resolve")
    def test_check_dns_records_all_missing(self, mock_resolve):
        """
        Tests the DNS check when all relevant records are missing (NXDOMAIN).
        """
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        results = check_dns_records("missing-dns.com")
        self.assertEqual(results["ns"]["statut"], "ERROR")
        self.assertEqual(results["a"]["statut"], "ERROR")
        self.assertEqual(results["mx"]["statut"], "ERROR")
        self.assertEqual(results["dmarc"]["statut"], "ERROR")
        self.assertEqual(results["spf"]["statut"], "ERROR")

    @patch("security_analyzer.Scanner")
    def test_scan_tls_protocols_obsolete_found(self, MockScanner):
        """
        Tests the TLS protocol scan when an obsolete protocol (e.g., TLS 1.0) is found.
        """
        # We need to build a mock result object that mimics the sslyze structure
        mock_scan_result = MagicMock()

        # Mocking a successful scan for an obsolete protocol
        tls1_0_result = MagicMock()
        tls1_0_result.status = ScanCommandAttemptStatusEnum.COMPLETED
        tls1_0_result.result.accepted_cipher_suites = [MagicMock()] # Non-empty list means it's supported

        # Mocking a successful scan for a modern protocol
        tls1_3_result = MagicMock()
        tls1_3_result.status = ScanCommandAttemptStatusEnum.COMPLETED
        tls1_3_result.result.accepted_cipher_suites = [MagicMock()]

        # Mocking a disabled protocol
        ssl2_result = MagicMock()
        ssl2_result.status = ScanCommandAttemptStatusEnum.COMPLETED
        ssl2_result.result.accepted_cipher_suites = [] # Empty list means not supported

        mock_scan_result.scan_result.tls_1_0_cipher_suites = tls1_0_result
        mock_scan_result.scan_result.tls_1_3_cipher_suites = tls1_3_result
        mock_scan_result.scan_result.ssl_2_0_cipher_suites = ssl2_result
        # For simplicity, we assume other scans are similar or not run
        mock_scan_result.scan_result.ssl_3_0_cipher_suites = ssl2_result
        mock_scan_result.scan_result.tls_1_1_cipher_suites = ssl2_result
        mock_scan_result.scan_result.tls_1_2_cipher_suites = tls1_3_result

        mock_server_scan_result = MagicMock()
        mock_server_scan_result.scan_status = ServerScanStatusEnum.COMPLETED
        mock_server_scan_result.scan_result = mock_scan_result.scan_result

        # The scanner's get_results() method should yield our mock result
        mock_scanner_instance = MockScanner.return_value
        mock_scanner_instance.get_results.return_value = [mock_server_scan_result]

        results = scan_tls_protocols("example.com")

        # Find the result for TLS 1.0 and assert it's an error
        tls1_0_report = next((r for r in results if r["protocole"] == "TLS 1.0"), None)
        self.assertIsNotNone(tls1_0_report)
        self.assertEqual(tls1_0_report["statut"], "ERROR")
        self.assertEqual(tls1_0_report["criticite"], "HIGH")

        # Find the result for TLS 1.3 and assert it's a success
        tls1_3_report = next((r for r in results if r["protocole"] == "TLS 1.3"), None)
        self.assertIsNotNone(tls1_3_report)
        self.assertEqual(tls1_3_report["statut"], "SUCCESS")

    @patch("security_analyzer.requests.get")
    def test_check_cookie_security_insecure(self, mock_get):
        """
        Tests the cookie check when a cookie is missing Secure and HttpOnly flags.
        """
        mock_response = MagicMock()
        # The .raw attribute needs to be mocked for get_all()
        mock_response.raw = MagicMock()
        mock_response.raw.headers.get_all.return_value = ["sessionid=123; SameSite=Lax"]
        mock_get.return_value = mock_response

        results = check_cookie_security("example.com")
        self.assertEqual(len(results), 1)
        cookie = results[0]
        self.assertEqual(cookie["secure"]["present"], False)
        self.assertEqual(cookie["httponly"]["present"], False)
        self.assertEqual(cookie["samesite"]["present"], True)
        self.assertEqual(cookie["secure"]["criticite"], "HIGH")

    @patch("security_analyzer.requests.get")
    def test_check_cms_footprint_found(self, mock_get):
        """
        Tests the CMS footprint check when a generator tag is found.
        """
        mock_response = MagicMock()
        mock_response.content = b'<html><head><meta name="generator" content="WordPress 6.0"></head></html>'
        mock_get.return_value = mock_response

        result = check_cms_footprint("example.com")
        self.assertEqual(result["statut"], "INFO")
        self.assertIn("WordPress 6.0", result["message"])

    @patch("security_analyzer.whois.whois")
    def test_check_whois_info_success(self, mock_whois):
        """
        Tests the WHOIS check with a successful response.
        """
        mock_whois_object = MagicMock()
        mock_whois_object.domain_name = "EXAMPLE.COM"
        # The whois library returns a dictionary-like object, so we mock .get()
        mock_whois_object.get.side_effect = lambda key, default=None: {
            "registrar": "Test Registrar",
            "creation_date": datetime(2020, 1, 1),
            "expiration_date": datetime(2030, 1, 1),
        }.get(key, default)

        mock_whois.return_value = mock_whois_object

        result = check_whois_info("example.com")
        self.assertEqual(result["statut"], "SUCCESS")
        self.assertEqual(result["registrar"], "Test Registrar")
        self.assertIn("2020-01-01", result["creation_date"])


if __name__ == "__main__":
    unittest.main()


from io import StringIO

class TestSecurityAnalyzerOutput(unittest.TestCase):

    @patch("sys.stdout", new_callable=StringIO)
    def test_print_human_readable_report(self, mock_stdout):
        """
        Tests that the human-readable report prints key information correctly.
        """
        # This sample data needs to be realistic for the calculate_score function
        sample_results = {
            "hostname": "example.com",
            # The score is calculated, not taken directly from this dict
            "ssl_certificate": {"statut": "ERROR", "message": "Le certificat a expiré.", "criticite": "CRITICAL"}, # Score = 10
            "http_redirect": {"statut": "SUCCESS", "message": "Redirection correcte vers HTTPS.", "criticite": "INFO"}, # Score = 0
        }
        # Manually add the calculated score to the dictionary before printing
        sample_results["score_final"], sample_results["note"] = calculate_score(sample_results)

        print_human_readable_report(sample_results)

        output = mock_stdout.getvalue()

        self.assertIn("RAPPORT D'ANALYSE DE SÉCURITÉ POUR : example.com", output)
        self.assertIn("SCORE DE DANGEROSITÉ : 10 (Note : A)", output) # Correct calculated score
        self.assertIn("Le certificat a expiré.", output)
        self.assertIn("Redirection correcte vers HTTPS.", output)

    @patch("builtins.open", new_callable=mock_open)
    def test_generate_csv_report(self, mock_file):
        """
        Tests that the CSV report is generated with the correct headers and data.
        """
        # This data structure needs to match what the function expects to iterate over
        sample_results = {
            "ssl_certificate": {"statut": "ERROR", "criticite": "CRITICAL", "message": "Expired", "date_expiration": "2022-01-01", "jours_restants": -100},
            "tls_protocols": [{"statut": "WARNING", "protocole": "TLS 1.0", "criticite": "HIGH", "message": "Obsolete", "remediation_id": "TLS_OBSOLETE"}],
        }

        generate_csv_report(sample_results, "example.com")

        mock_file.assert_called_once_with(unittest.mock.ANY, "w", newline="", encoding="utf-8")

        handle = mock_file()
        # The writer writes rows one by one, so we need to check the call args list
        written_calls = handle.write.call_args_list
        # Combine all written parts into one string for easier checking
        full_written_content = "".join(call[0][0] for call in written_calls)

        self.assertIn("Catégorie,Sous-catégorie,Statut,Criticité,Description", full_written_content)
        self.assertIn("Certificat SSL,Détails du certificat,ERROR,CRITICAL", full_written_content)
        self.assertIn("Tls Protocols,TLS 1.0,WARNING,HIGH,Obsolete", full_written_content)

    @patch("builtins.open", new_callable=mock_open)
    def test_generate_html_report(self, mock_file):
        """
        Tests that the HTML report is generated with the correct data.
        """
        sample_results = {
            "hostname": "example.com",
            "score_final": 42,
            "note": "D",
            "ssl_certificate": {"statut": "ERROR", "message": "Le certificat a expiré.", "criticite": "CRITICAL"},
        }

        generate_html_report(sample_results, "example.com")

        mock_file.assert_called_once_with(unittest.mock.ANY, "w", encoding="utf-8")
        handle = mock_file()
        written_content = handle.write.call_args[0][0]

        self.assertIn("<h1>Rapport d'Analyse de Sécurité pour example.com</h1>", written_content)
        self.assertIn("Score de Dangerosité : 42 (Note: D)", written_content)
        self.assertIn("Le certificat a expiré.", written_content)
