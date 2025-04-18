import unittest
from scanner.xss import XSSScanner
from scanner.sqli import SQLInjectionScanner
from scanner.ssrf import SSRFScanner
from scanner.idor import IDORScanner
from scanner.csrf import CSRFScanner
from scanner.command_injection import CommandInjectionScanner

class TestXSSScanner(unittest.TestCase):
    def test_xss_payloads(self):
        scanner = XSSScanner(driver=None)  # Mock driver
        self.assertGreater(len(scanner.payloads), 0, "XSS payloads should not be empty.")

class TestSQLInjectionScanner(unittest.TestCase):
    def test_sqli_payloads(self):
        scanner = SQLInjectionScanner(driver=None)  # Mock driver
        self.assertGreater(len(scanner.payloads), 0, "SQLi payloads should not be empty.")

class TestSSRFScanner(unittest.TestCase):
    def test_ssrf_payloads(self):
        scanner = SSRFScanner()
        self.assertGreater(len(scanner.payloads), 0, "SSRF payloads should not be empty.")

    def test_validate_payloads(self):
        scanner = SSRFScanner()
        self.assertTrue(scanner.validate_payloads(), "All SSRF payloads should be valid.")

class TestIDORScanner(unittest.TestCase):
    def test_idor_default_ids(self):
        scanner = IDORScanner()
        self.assertGreater(len(scanner.test_ids), 0, "IDOR test IDs should not be empty.")

class TestCSRFScanner(unittest.TestCase):
    def test_csrf_detection(self):
        scanner = CSRFScanner(driver=None)  # Mock driver
        form = {"action": "/submit", "inputs": [{"name": "username"}, {"name": "password"}]}
        self.assertTrue(scanner.test_csrf(form, "http://example.com"))

class TestCommandInjectionScanner(unittest.TestCase):
    def test_command_injection_payloads(self):
        scanner = CommandInjectionScanner()
        self.assertGreater(len(scanner.payloads), 0, "Command injection payloads should not be empty.")

    def test_validate_payloads(self):
        scanner = CommandInjectionScanner(payloads=["; ls", "&& whoami", ""])
        self.assertFalse(scanner.validate_payloads(), "Payload validation should fail for empty payloads.")

        scanner = CommandInjectionScanner(payloads=["; ls", "&& whoami"])
        self.assertTrue(scanner.validate_payloads(), "Payload validation should pass for valid payloads.")

    def test_log_vulnerability(self):
        scanner = CommandInjectionScanner()
        with self.assertLogs(level="WARNING") as log:
            scanner.log_vulnerability("http://example.com", "; ls")
            self.assertIn("Potential command injection vulnerability found at http://example.com with payload: ; ls", log.output[0])

if __name__ == "__main__":
    unittest.main()
