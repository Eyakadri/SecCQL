import unittest
import os
from reporter.report_generator import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = ReportGenerator()
        self.vulnerabilities = [
            {"type": "XSS", "description": "Cross-site scripting detected.", "severity": "High", "recommendation": "Sanitize inputs."},
            {"type": "SQL Injection", "description": "SQLi vulnerability found.", "severity": "Critical", "recommendation": "Use parameterized queries."},
        ]
        self.output_file = "test_report"

    def tearDown(self):
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    def test_generate_text_report(self):
        self.generator.generate_text_report(self.vulnerabilities, self.output_file)
        self.assertTrue(os.path.exists(self.output_file))

    def test_generate_json_report(self):
        self.generator.generate_json_report(self.vulnerabilities, self.output_file)
        self.assertTrue(os.path.exists(self.output_file))

    def test_generate_csv_report(self):
        self.generator.generate_csv_report(self.vulnerabilities, self.output_file)
        self.assertTrue(os.path.exists(self.output_file))

if __name__ == "__main__":
    unittest.main()
