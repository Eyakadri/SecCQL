import unittest
from scanner.xss import XSSScanner
from scanner.sqli import SQLInjectionScanner

class TestXSSScanner(unittest.TestCase):
    def test_xss_payloads(self):
        scanner = XSSScanner(driver=None)  # Mock driver
        self.assertGreater(len(scanner.payloads), 0, "XSS payloads should not be empty.")

class TestSQLInjectionScanner(unittest.TestCase):
    def test_sqli_payloads(self):
        scanner = SQLInjectionScanner(driver=None)  # Mock driver
        self.assertGreater(len(scanner.payloads), 0, "SQLi payloads should not be empty.")

if __name__ == "__main__":
    unittest.main()
