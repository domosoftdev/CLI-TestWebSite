#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module spécialisé dans l'analyse des cookies et du consentement.
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException


class CookieAnalyzer:
    def __init__(self):
        self.driver = None

    def _setup_driver(self):
        """Configure et initialise le WebDriver Selenium."""
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(20)
        except WebDriverException as e:
            print(f"Erreur WebDriver: {e}")
            self.driver = None

    def _teardown_driver(self):
        """Ferme le WebDriver."""
        if self.driver:
            self.driver.quit()

    def analyze(self, url, verbose=False):
        """Lance l'analyse des cookies pour une URL donnée."""
        if verbose:
            print("      [>>] Démarrage de CookieAnalyzer...")
        self._setup_driver()
        if not self.driver:
            return {"error": "WebDriver could not be initialized."}

        results = {"consent_banner": self.check_consent_banner(url, verbose=verbose)}
        self._teardown_driver()
        return results

    def check_consent_banner(self, url: str, verbose=False) -> dict:
        """Détecte la présence d'une bannière de consentement."""
        if verbose:
            print("          [>>>] Recherche d'une bannière de consentement...")
        try:
            self.driver.get(url)
            if verbose:
                print(f"              [i] Page {url} chargée avec succès.")
        except WebDriverException as e:
            if verbose:
                print(f"              [!] Erreur lors du chargement de la page : {e}")
            return {"present": False, "error": f"Failed to load page: {e}"}

        consent_selectors = [
            '[class*="cookie"]',
            '[id*="cookie"]',
            '[class*="consent"]',
            '[id*="consent"]',
            '[class*="gdpr"]',
            '[id*="gdpr"]',
        ]

        for selector in consent_selectors:
            try:
                if verbose:
                    print(f"              [i] Test du sélecteur CSS : {selector}")
                elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                if elements:
                    if verbose:
                        print(f"              [+] Bannière trouvée avec le sélecteur : {selector}")
                    return {"present": True, "selector": selector, "error": None}
            except WebDriverException:
                if verbose:
                    print(f"              [!] Sélecteur invalide ou erreur : {selector}")
                continue  # Ignore errors from invalid selectors if any

        if verbose:
            print("          [+] Aucune bannière de consentement détectée.")
        return {"present": False, "selector": None, "error": None}
