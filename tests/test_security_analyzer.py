import unittest
from unittest.mock import patch, MagicMock
from src.analyzers.security import SecurityAnalyzer

class TestSecurityAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = SecurityAnalyzer()

    @patch('dns.resolver.resolve')
    def test_check_dns_records_spf_and_dmarc(self, mock_resolve):
        # Mock TXT record for SPF - single string
        mock_txt_spf = MagicMock()
        mock_txt_spf.strings = [b'v=spf1 include:_spf.google.com ~all']

        # Mock TXT record for DMARC - split into multiple strings
        mock_txt_dmarc = MagicMock()
        mock_txt_dmarc.strings = [b'v=DMARC1; p=none; rua=mailto:', b'dmarc-reports@example.com']

        def resolve_side_effect(name, rdtype):
            if rdtype == 'TXT':
                if name.startswith('_dmarc'):
                    return [mock_txt_dmarc]
                else:
                    return [mock_txt_spf]
            # Return empty list for other record types to avoid errors
            return []

        mock_resolve.side_effect = resolve_side_effect

        results = self.analyzer._check_dns_records('example.com')

        # Assertions for DMARC
        self.assertEqual(results['dmarc']['statut'], 'SUCCESS')
        self.assertEqual(results['dmarc']['valeur'], 'v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com')

        # Assertions for SPF
        self.assertEqual(results['spf']['statut'], 'SUCCESS')
        self.assertEqual(results['spf']['valeur'], 'v=spf1 include:_spf.google.com ~all')

if __name__ == '__main__':
    unittest.main()
