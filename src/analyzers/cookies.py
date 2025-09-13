# -*- coding: utf-8 -*-

"""
Module spécialisé dans l'analyse des cookies et du consentement.
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException

from src.config import CONSENT_BANNER_SELECTORS, SELENIUM_PAGE_LOAD_TIMEOUT

class CookieAnalyzer:
    def __init__(self, verbose=False):
        self.driver = None
        self.verbose = verbose

    def _setup_driver(self):
        """Configure et initialise le WebDriver Selenium."""
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(SELENIUM_PAGE_LOAD_TIMEOUT)
        except WebDriverException as e:
            if self.verbose:
                print(f"Erreur WebDriver: {e}")
            self.driver = None

    def _teardown_driver(self):
        """Ferme le WebDriver."""
        if self.driver:
            self.driver.quit()

    def analyze(self, url):
        """Lance l'analyse des cookies pour une URL donnée."""
        self._setup_driver()
        if not self.driver:
            return {"error": "WebDriver could not be initialized."}

        results = {
            'consent_banner': self.check_consent_banner(url)
        }
        self._teardown_driver()
        return results

    def check_consent_banner(self, url: str) -> dict:
        """Détecte la présence d'une bannière de consentement."""
        try:
            self.driver.get(url)
        except WebDriverException as e:
            return {"present": False, "error": f"Failed to load page: {e}"}

        for selector in CONSENT_BANNER_SELECTORS:
            try:
                if self.driver.find_elements(By.CSS_SELECTOR, selector):
                    return {"present": True, "selector": selector, "error": None}
            except WebDriverException:
                continue # Ignore errors from invalid selectors if any

        return {"present": False, "selector": None, "error": None}
