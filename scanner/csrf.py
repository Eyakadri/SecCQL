from urllib.parse import urljoin
from selenium.webdriver.common.by import By
import logging

class CSRFScanner:
    def __init__(self, driver):
        self.driver = driver

    def test_csrf(self, form, url):
        """Test a form for CSRF vulnerabilities."""
        action = form.get("action", urljoin(url, form.get("action", "")))
        inputs = form.get("inputs", [])
        csrf_token_name = None
        csrf_token_found = any(
            "csrf" in input_field.get("name", "").lower() or "token" in input_field.get("name", "").lower()
            for input_field in inputs
        )

        if not csrf_token_found:
            logging.warning(f"Potential CSRF vulnerability found at {action}: No CSRF token detected.")
            print(f"Potential CSRF vulnerability found at {action}: No CSRF token detected.")
            return True

        try:
            self.driver.get(action)
            for input_field in inputs:
                name = input_field.get("name")
                if name and input_field.get("type") != "hidden":
                    input_element = self.driver.find_element(By.NAME, name)
                    input_element.clear()
                    input_element.send_keys("test")

            self.driver.execute_script(f"document.getElementsByName('{csrf_token_name}')[0].remove()")
            submit_button = self.driver.find_element(By.XPATH, "//form//button[@type='submit'] | //form//input[@type='submit']")
            submit_button.click()

            if "error" not in self.driver.page_source.lower():
                logging.warning(f"Potential CSRF vulnerability found at {action}: Form accepted without CSRF token.")
                print(f"Potential CSRF vulnerability found at {action}: Form accepted without CSRF token.")
                return True
        except Exception as e:
            logging.error(f"Error testing CSRF on {action}: {e}")

        return False