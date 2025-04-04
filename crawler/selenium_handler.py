# Helper functions (e.g., URL normalization, link filtering).
from selenium.webdriver.common.by import By
import logging

class SeleniumHandler:
    def extract_shadow_dom(self, driver):
        shadow_roots = []
        try:
            shadow_hosts = driver.find_elements(By.CSS_SELECTOR, "*")
            for host in shadow_hosts:
                shadow_root = driver.execute_script("return arguments[0].shadowRoot", host)
                if shadow_root:
                    shadow_roots.append(shadow_root)
            logging.info(f"Extracted {len(shadow_roots)} shadow DOM elements.")
        except Exception as e:
            logging.error(f"Error extracting shadow DOM: {e}")
        return shadow_roots