import unittest
from auditor.core import audit_security
from auditor import enforce_security_headers

class TestAuditor(unittest.TestCase):
    def test_audit_security_success(self):
        """
        Test audit_security function with valid inputs.
        """
        results = audit_security("https://example.com")
        self.assertIn("vulnerabilities", results)
        self.assertGreaterEqual(len(results["vulnerabilities"]), 0)

    def test_audit_security_invalid_url(self):
        """
        Test audit_security function with an invalid URL.
        """
        with self.assertRaises(ValueError):
            audit_security("invalid_url")

    def test_audit_security_empty_url(self):
        """
        Test audit_security function with an empty URL.
        """
        with self.assertRaises(ValueError):
            audit_security("")

    def test_missing_security_headers(self):
        headers = {"Content-Type": "application/json"}
        results = enforce_security_headers(headers)
        self.assertIn("Content-Security-Policy", results)
        self.assertIn("X-Content-Type-Options", results)
        self.assertIn("X-Frame-Options", results)

if __name__ == "__main__":
    unittest.main()
