import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import requests
import dns.resolver

# Import the functions to be tested
from src.analyzers.parking import (
    analyze_content,
    analyze_technical,
    analyze_contextual,
    calculate_parking_score,
    KNOWN_PARKING_NAMESERVERS,
)

class TestParkingScorer(unittest.TestCase):

    # --- Tests for the new, corrected analyze_content logic ---

    @patch('src.analyzers.parking.requests.Session.get')
    def test_analyze_content_clean_site(self, mock_get):
        """Should return a score of 0 for a legitimate site with sufficient content."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        long_content = " ".join(["word"] * 50)
        mock_response.text = f"<html><title>Legitimate Site</title><body>{long_content}</body></html>"
        mock_get.return_value = mock_response
        score = analyze_content("legit-site.com")
        self.assertEqual(score, 0)

    @patch('src.analyzers.parking.requests.Session.get')
    def test_analyze_content_low_content_penalty(self, mock_get):
        """Should return a score of 20 for a site with very little content."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>Empty</title><body>Hello world.</body></html>"
        mock_get.return_value = mock_response
        score = analyze_content("low-content-site.com")
        self.assertEqual(score, 20)

    @patch('src.analyzers.parking.requests.Session.get')
    def test_analyze_content_for_sale_in_title(self, mock_get):
        """Should return a high score for a 'for sale' keyword in the title."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>This domain is for sale</title><body>Check it out.</body></html>"
        mock_get.return_value = mock_response
        score = analyze_content("sale-in-title.com")
        # 25 (title) + 10 (sale content) + 20 (low content) = 55
        self.assertEqual(score, 55)

    @patch('src.analyzers.parking.requests.Session.get')
    def test_analyze_content_for_sale_in_content(self, mock_get):
        """Should return a score for a 'for sale' keyword in the body."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>My Site</title><body>This valuable domain is for sale.</body></html>"
        mock_get.return_value = mock_response
        score = analyze_content("sale-in-content.com")
        self.assertEqual(score, 30) # 10 (content) + 20 (low content)

    @patch('src.analyzers.parking.requests.Session.get')
    def test_analyze_content_generic_parking_keyword(self, mock_get):
        """Should return a score for a generic parking keyword."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>Coming Soon</title><body>This page is under construction.</body></html>"
        mock_get.return_value = mock_response
        score = analyze_content("generic-parked.com")
        self.assertEqual(score, 28) # 8 (generic keyword) + 20 (low content)

    @patch('src.analyzers.parking.requests.Session.get')
    def test_analyze_content_parking_service_mention(self, mock_get):
        """Should return a score for mentioning a parking service."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>My Site</title><body>This domain is parked with sedo.com.</body></html>"
        mock_get.return_value = mock_response
        score = analyze_content("service-mention.com")
        # "sedo" is in KEYWORDS_FOR_SALE (+10)
        # "This domain is parked" is in KEYWORDS_PARKING_GENERIC (+8)
        # "sedo.com" is in PARKING_SERVICES (+15)
        # low content (+20)
        # Total = 53
        self.assertEqual(score, 53)

    @patch('src.analyzers.parking.requests.Session.get')
    def test_analyze_content_all_signals(self, mock_get):
        """Should return a high score when all signals are present."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>domain for sale</title><body>Parked by sedo.com. This domain is available.</body></html>"
        mock_get.return_value = mock_response
        score = analyze_content("all-signals.com")
        # 25 (title) + 10 (sale content: "domain is available") + 15 (service: "sedo.com") + 20 (low content) = 70
        self.assertEqual(score, 70)

    @patch('src.analyzers.parking.requests.Session.get', side_effect=requests.exceptions.RequestException)
    def test_analyze_content_connection_fails(self, mock_get):
        """Should return a score of 20 if connection fails (treated as minimal content)."""
        score = analyze_content("unreachable-site.com")
        self.assertEqual(score, 20)

    # --- Tests for analyze_technical (Unchanged) ---

    @patch('src.analyzers.parking.dns.resolver.Resolver.resolve')
    def test_analyze_technical_known_ns_and_wildcard(self, mock_resolve):
        """Should return 20 for known NS (15) and wildcard (5)."""
        mock_ns_record = MagicMock()
        mock_ns_record.target = f"ns1.{KNOWN_PARKING_NAMESERVERS[0]}."
        mock_a_record = MagicMock()
        mock_a_record.__str__.return_value = "1.2.3.4"

        def resolve_side_effect(name, rdtype):
            if rdtype == 'NS':
                return [mock_ns_record]
            elif rdtype == 'A':
                return [mock_a_record]
            raise ValueError(f"Unexpected DNS query in test: {name} {rdtype}")

        mock_resolve.side_effect = resolve_side_effect
        score = analyze_technical("parked-by-ns.com")
        self.assertEqual(score, 20)

    @patch('src.analyzers.parking.dns.resolver.Resolver.resolve', side_effect=dns.resolver.NXDOMAIN)
    def test_analyze_technical_no_records(self, mock_resolve):
        """Should return 0 if no DNS records are found."""
        score = analyze_technical("non-existent-domain.com")
        self.assertEqual(score, 0)

    # --- Tests for analyze_contextual (Unchanged) ---

    @patch('src.analyzers.parking.whois.whois')
    def test_analyze_contextual_all_signals(self, mock_whois):
        """Should return 25 for all contextual signals."""
        mock_whois.return_value = {
            'creation_date': datetime.now() - timedelta(days=200),
            'updated_date': datetime.now() - timedelta(days=15),
            'org': 'Privacy Guard',
            'status': ['clientHold']
        }
        score = analyze_contextual("all-context-signals.com")
        self.assertEqual(score, 25)

    @patch('src.analyzers.parking.whois.whois', side_effect=Exception("WHOIS query fails"))
    def test_analyze_contextual_whois_fails(self, mock_whois):
        """Should return 0 if WHOIS query fails."""
        score = analyze_contextual("whois-error.com")
        self.assertEqual(score, 0)

    # --- Test for calculate_parking_score (Unchanged) ---

    @patch('src.analyzers.parking.analyze_content')
    @patch('src.analyzers.parking.analyze_technical')
    @patch('src.analyzers.parking.analyze_contextual')
    def test_calculate_parking_score_sums_and_caps_scores(self, mock_contextual, mock_technique, mock_contenu):
        """Should sum the scores from all analyzers and cap at 100."""
        # Scenario 1: Normal sum
        mock_contenu.return_value = 10
        mock_technique.return_value = 20
        mock_contextual.return_value = 15
        score = calculate_parking_score("some-domain.com")
        self.assertEqual(score, 45)

        # Scenario 2: Score exceeds 100, should be capped.
        mock_contenu.return_value = 50
        mock_technique.return_value = 30
        mock_contextual.return_value = 25 # Total is 105
        score = calculate_parking_score("max-score-domain.com")
        self.assertEqual(score, 100)

if __name__ == '__main__':
    unittest.main()
