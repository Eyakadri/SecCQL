import time
import unittest
from unittest.mock import patch, MagicMock
from scanner.xss import XSSScanner
from scanner.sqli import SQLInjectionScanner
from scanner.ssrf import SSRFScanner
from scanner.idor import IDORScanner
from scanner.csrf import CSRFScanner
from scanner.command_injection import CommandInjectionScanner

class TestXSSScanner(unittest.TestCase):
    @patch("scanner.xss.WebDriverWait")
    @patch("scanner.xss.webdriver.Chrome")
    def test_basic_xss_detection(self, mock_driver, mock_wait):
        # Setup mock driver and wait
        mock_driver.return_value.find_elements.return_value = [MagicMock()]
        mock_wait.return_value.until.return_value = True
        
        form = {"action": "/test", "inputs": [{"name": "username"}]}
        url = "http://example.com"
        scanner = XSSScanner(driver=mock_driver)
        
        with patch("scanner.xss.requests.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.text = "<script>alert('XSS')</script>"
            self.assertTrue(scanner.test_xss(form, url))

class TestSQLInjectionScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SQLInjectionScanner(driver=None)  # Mock driver

    def test_sqli_payloads(self):
        # Ensure payloads are loaded correctly
        self.assertGreater(len(self.scanner.payloads), 0, "SQLi payloads should not be empty.")

    @patch("scanner.sqli.requests.post")
    def test_basic_sqli_detection(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "syntax error"
        mock_post.return_value = mock_response

        form = {"action": "/test", "inputs": [{"name": "username"}]}
        url = "http://example.com"
        self.assertTrue(self.scanner.test_sql_injection(form, url), "Basic SQLi should be detected.")

    @patch("scanner.sqli.requests.post")
    def test_error_based_sqli_detection(self, mock_post):
        # Mock response to simulate error-based SQLi
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "SQL syntax error"
        mock_post.return_value = mock_response

        form = {"action": "/test", "inputs": [{"name": "username"}]}
        url = "http://example.com"
        self.assertTrue(self.scanner.test_sql_injection(form, url), "Error-based SQLi should be detected.")

    @patch("scanner.sqli.requests.post")
    def test_time_based_blind_sqli_detection(self, mock_post):
        # Setup mock with delay
        def delayed_response(*args, **kwargs):
            time.sleep(2)
            return MagicMock(status_code=200)
        
        mock_post.side_effect = delayed_response
        scanner = SQLInjectionScanner()
        form = {"action": "/test", "inputs": [{"name": "user"}]}
        
        start_time = time.time()
        result = scanner.test_sql_injection(form, "http://test.com")
        elapsed = time.time() - start_time
        
        self.assertTrue(result)
        self.assertGreater(elapsed, 1.5)

    def test_empty_form(self):
        form = {}
        url = "http://example.com"
        self.assertFalse(self.scanner.test_sql_injection(form, url), "Empty form should not be vulnerable.")

    def test_invalid_form(self):
        form = {"action": "/test", "inputs": []}
        url = "http://example.com"
        self.assertFalse(self.scanner.test_sql_injection(form, url), "Invalid form should not be vulnerable.")

    @patch("scanner.sqli.logging.warning")
    def test_logging_vulnerabilities(self, mock_warning):
        # Mock response to simulate a vulnerable scenario
        form = {"action": "/test", "inputs": [{"name": "username"}]}
        url = "http://example.com"

        with patch("scanner.sqli.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "syntax error"
            mock_post.return_value = mock_response

            self.scanner.test_sql_injection(form, url)
            mock_warning.assert_called_with("Basic SQLi found at /test with payload: ' OR '1'='1'")

class TestSSRFScanner(unittest.TestCase):

    def test_ssrf_payloads(self):
        # Test to ensure that SSRF payloads are not empty
        scanner = SSRFScanner()
        self.assertGreater(len(scanner.payloads), 0, "SSRF payloads should not be empty.")

    def test_validate_payloads(self):
        scanner = SSRFScanner()
        valid_payloads = [
            "http://169.254.169.254",
            "http://localhost/admin",
            "http://internal/api"
        ]
        scanner.payloads = valid_payloads
        self.assertTrue(scanner.validate_payloads())

    @patch("scanner.ssrf.requests.get")
    def test_basic_ssrf_detection(self, mock_get):
        # Mock the response for SSRF detection
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Valid SSRF response"
        mock_get.return_value = mock_response

        form = {"action": "/test", "inputs": [{"name": "url"}]}
        url = "https://example.com"
        scanner = SSRFScanner()

        # Test if SSRF is detected correctly
        self.assertTrue(scanner.test_ssrf(form, url), "Basic SSRF should be detected.")

    @patch("scanner.ssrf.requests.get")
    def test_error_based_ssrf_detection(self, mock_get):
        # Simulate an error-based SSRF scenario
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        form = {"action": "/test", "inputs": [{"name": "url"}]}
        url = "https://example.com"
        scanner = SSRFScanner()

        # Test if SSRF is detected for error-based scenarios
        self.assertTrue(scanner.test_ssrf(form, url), "Error-based SSRF should be detected.")

    @patch("scanner.ssrf.requests.get")
    def test_time_based_blind_ssrf_detection(self, mock_get):
        # Simulate a delay in SSRF response (time-based blind SSRF)
        mock_response = MagicMock()
        mock_response.status_code = 200

        def slow_response(*args, **kwargs):
            time.sleep(5)  # Simulate delay in the response
            return mock_response

        mock_get.side_effect = slow_response

        form = {"action": "/test", "inputs": [{"name": "url"}]}
        url = "https://example.com"
        scanner = SSRFScanner()

        # Test if SSRF is detected for time-based blind scenarios
        self.assertTrue(scanner.test_ssrf(form, url), "Time-based Blind SSRF should be detected.")

    @patch("scanner.ssrf.requests.get")
    def test_invalid_url_format(self):
        scanner = SSRFScanner()
        with self.assertRaises(ValueError):
            scanner.test_ssrf({}, "invalid_url")

class TestIDORScanner(unittest.TestCase):
    def test_idor_default_ids(self):
        scanner = IDORScanner()
        self.assertGreater(len(scanner.test_ids), 0, "IDOR test IDs should not be empty.")

class TestCSRFScanner(unittest.TestCase):
    def test_csrf_detection(self, mock_post):
        scanner = CSRFScanner()
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = "CSRF vulnerable"
        
        form = {
            "action": "/submit",
            "inputs": [{"name": "user"}, {"name": "token", "value": "123"}]
        }
        
        # Test with missing token
        vulnerable = scanner.test_csrf(form, "http://test.com")
        self.assertTrue(vulnerable)
        
        # Test with token
        form["inputs"][1]["value"] = "valid_csrf_token"
        mock_post.return_value.text = "OK"
        self.assertFalse(scanner.test_csrf(form, "http://test.com"))

    @patch("scanner.csrf.send_request")
    def test_known_vulnerable_endpoint(self, mock_send_request):
        """
        Test the scanner against a known vulnerable endpoint.
        """
        scanner = CSRFScanner(driver=None)  # Mock driver
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "CSRF vulnerability detected"
        mock_send_request.return_value = mock_response

        url = "https://vulnerable-site.com"
        self.assertTrue(scanner.test_csrf(url), "CSRF vulnerability should be detected.")

    @patch("scanner.csrf.send_request")
    def test_csrf_vulnerability_detection(self, mock_send_request):
        """
        Test the CSRF scanner against a simulated vulnerable endpoint.
        """
        scanner = CSRFScanner(driver=None)  # Mock driver
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "This site is vulnerable to CSRF"
        mock_send_request.return_value = mock_response

        url = "https://example.com/vulnerable-endpoint"
        self.assertTrue(scanner.test_csrf(url), "CSRF vulnerability should be detected.")

    @patch("scanner.csrf.send_request")
    def test_no_csrf_vulnerability(self, mock_send_request):
        """
        Test the CSRF scanner against a secure endpoint.
        """
        scanner = CSRFScanner(driver=None)  # Mock driver
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "This site is secure"
        mock_send_request.return_value = mock_response

        url = "https://example.com/secure-endpoint"
        self.assertFalse(scanner.test_csrf(url), "No CSRF vulnerability should be detected.")

class TestCommandInjectionScanner(unittest.TestCase):
    def test_command_injection_payloads(self):
        scanner = CommandInjectionScanner()
        self.assertGreater(len(scanner.payloads), 0, "Command injection payloads should not be empty.")

    def test_validate_payloads(self):
        scanner = CommandInjectionScanner()
        scanner.payloads = ["; ls", "| cat /etc/passwd", "&& whoami"]
        self.assertTrue(scanner.validate_payloads())
        
        scanner.payloads = ["", None, "  "]
        self.assertFalse(scanner.validate_payloads())

    def test_log_vulnerability(self):
        scanner = CommandInjectionScanner()
        with self.assertLogs(level="WARNING") as log:
            scanner.log_vulnerability("http://example.com", "; ls")
            self.assertIn("Potential command injection vulnerability found at http://example.com with payload: ; ls", log.output[0])

if __name__ == "__main__":
    unittest.main()
