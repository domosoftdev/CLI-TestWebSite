import unittest
from security_analyzer import get_hostname

class TestSecurityAnalyzer(unittest.TestCase):

    def test_get_hostname(self):
        """
        Tests the get_hostname function with various URL formats.
        """
        urls_to_test = {
            "https://www.google.com/path": "www.google.com",
            "http://google.com/path": "google.com",
            "www.example.co.uk/": "www.example.co.uk",
            "https://sub.domain.org": "sub.domain.org",
            "ftp://ftp.example.com": "ftp.example.com", # Should work even with other protocols
            "bare-domain.com": "bare-domain.com",
        }

        for url, expected_hostname in urls_to_test.items():
            with self.subTest(url=url):
                self.assertEqual(get_hostname(url), expected_hostname)

if __name__ == '__main__':
    unittest.main()
