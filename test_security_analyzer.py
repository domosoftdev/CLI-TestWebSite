import unittest
import socket
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from security_analyzer import (
    get_hostname,
    _format_whois_value,
    calculate_score,
    check_security_headers,
    check_ssl_certificate,
    check_http_to_https_redirect,
)


class TestSecurityAnalyzerHelpers(unittest.TestCase):
    def test_get_hostname(self):
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
            "list_of_datetimes": (
                [test_time, test_time],
                "2023-10-27T10:00:00, 2023-10-27T10:00:00",
            ),
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
        self.assertGreater(result["jours_restants"], 360)

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
        self.assertEqual(headers["x-frame-options"]["statut"], "SUCCESS")
        self.assertEqual(headers["x-content-type-options"]["statut"], "SUCCESS")

    @patch("security_analyzer.requests.get")
    def test_check_http_to_https_redirect_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.headers = {"Location": "https://example.com"}
        mock_get.return_value = mock_response
        result = check_http_to_https_redirect("example.com")
        self.assertEqual(result["statut"], "SUCCESS")

    @patch("security_analyzer.requests.get")
    def test_check_http_to_https_redirect_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200 # No redirect
        mock_response.headers = {}
        mock_get.return_value = mock_response
        result = check_http_to_https_redirect("example.com")
        self.assertEqual(result["statut"], "ERROR")

if __name__ == "__main__":
    unittest.main()
