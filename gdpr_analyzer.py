#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module principal pour l'audit de conformité RGPD.
"""

from datetime import datetime
from cookie_analyzer import CookieAnalyzer


class GDPRChecker:
    def __init__(self):
        self.cookie_analyzer = CookieAnalyzer()

    def check_gdpr_compliance(self, url, verbose=False):
        """Point d'entrée principal pour l'audit RGPD."""
        if verbose:
            print(f"  [>] Démarrage de l'analyse RGPD pour {url}...")

        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "cookies": self.cookie_analyzer.analyze(url, verbose=verbose),
        }
        return results
