# -*- coding: utf-8 -*-

"""
Module principal pour l'audit de conformité RGPD.
"""

from datetime import datetime
from src.analyzers.cookies import CookieAnalyzer

class GDPRChecker:
    def __init__(self, verbose=False):
        self.cookie_analyzer = CookieAnalyzer(verbose=verbose)
        self.verbose = verbose

    def check_gdpr_compliance(self, url):
        """Point d'entrée principal pour l'audit RGPD."""
        if self.verbose:
            print(f"Lancement de l'analyse RGPD pour {url}...")

        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'cookies': self.cookie_analyzer.analyze(url),
        }

        if self.verbose:
            print("Analyse RGPD terminée.")

        return results
