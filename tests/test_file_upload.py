import unittest
import os
import tempfile
from penetration_tester.file_upload import (
    is_file_safe,
    prevent_directory_traversal,
    test_insecure_cookies,
    process_file_upload
)

class TestFileUpload(unittest.TestCase):
    """Test suite for file upload security functions."""
    
    def setUp(self):
        """Create temporary files for testing."""
        self.safe_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        self.safe_file.write(b"Safe content")
        self.safe_file.close()
        
        self.empty_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        self.empty_file.close()
        
        self.xss_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        self.xss_file.write(b"<script>alert('XSS')</script>")
        self.xss_file.close()

        # Test binary file
        self.binary_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        self.binary_file.write(b'\x00\x01Binary\xFF\xFE')
        self.binary_file.close()

    def tearDown(self):
        """Clean up temporary files."""
        for f in [self.safe_file.name, self.empty_file.name, 
                 self.xss_file.name, self.binary_file.name]:
            try:
                os.unlink(f)
            except OSError:
                pass

    def test_is_file_safe_with_valid_file(self):
        """Test that safe files are recognized as safe."""
        self.assertTrue(is_file_safe(self.safe_file.name))

    def test_is_file_safe_with_invalid_extension(self):
        """Test that dangerous extensions are blocked."""
        self.assertFalse(is_file_safe("malicious.exe"))
        self.assertFalse(is_file_safe("evil.php"))
        self.assertFalse(is_file_safe("dangerous.bat"))

    def test_is_file_safe_with_empty_file(self):
        """Test that empty files are considered unsafe."""
        self.assertFalse(is_file_safe(self.empty_file.name))

    def test_is_file_safe_with_malicious_content(self):
        """Test that files with dangerous content are blocked."""
        self.assertFalse(is_file_safe(self.xss_file.name))

    def test_is_file_safe_with_binary_in_text(self):
        """Test that binary files masquerading as text are blocked."""
        self.assertFalse(is_file_safe(self.binary_file.name))

    def test_prevent_directory_traversal(self):
        """Test directory traversal prevention."""
        test_cases = [
            ("../../etc/passwd", "passwd"),
            ("..\\..\\windows\\system32", "system32"),
            ("C:\\Users\\Admin\\..\\..\\system32", "system32"),
            ("/var/www/../log/access.log", "access.log"),
            ("normal_file.txt", "normal_file.txt"),
            ("", "invalid_filename"),
            ("just/a/path/", "invalid_filename"),
            (".../.../etc/passwd", "passwd"),
            ("%2e%2e/etc/passwd", "passwd"),
            ("valid.name.txt", "valid.name.txt"),
            ("invalid/name.txt", "name.txt"),
            ("invalid\\name.txt", "name.txt"),
        ]
        
        for input_path, expected in test_cases:
            with self.subTest(input_path=input_path):
                result = prevent_directory_traversal(input_path)
                self.assertEqual(result, expected)

    def test_sanitize_reserved_names(self):
        """Test that reserved filenames are sanitized."""
        reserved_names = [
            "CON.txt", "PRN.jpg", "AUX", "NUL.pdf", "COM1.doc",
            "LPT9", "COM8", "LPT1.docx", "con", "prn.txt"
        ]
        for name in reserved_names:
            with self.subTest(name=name):
                sanitized = prevent_directory_traversal(name)
                self.assertEqual(sanitized, "invalid_filename")

    def test_insecure_cookies_detection(self):
        """Test insecure cookie detection."""
        test_cases = [
            (
                [{"name": "session", "secure": True, "httpOnly": True, "sameSite": "Strict"}],
                {'insecure': [], 'total_issues': 0}
            ),
            (
                [{"name": "auth", "secure": False, "httpOnly": True}],
                {'insecure': [{'name': 'auth', 'issues': [
                    'missing secure flag', 
                    'invalid SameSite value'
                ]}], 'total_issues': 2}
            ),
            (
                [{"name": "__Secure-ID", "secure": False}],
                {'insecure': [{'name': '__Secure-ID', 'issues': [
                    'missing secure flag',
                    'invalid SameSite value',
                    '__Secure- prefix requires secure flag'
                ]}], 'total_issues': 3}
            ),
            (
                [{"name": "__Host-ID", "secure": True, "path": "/", "domain": "example.com"}],
                {'insecure': [{'name': '__Host-ID', 'issues': [
                    '__Host- prefix requirements not met'
                ]}], 'total_issues': 1}
            )
        ]
        
        for cookies, expected in test_cases:
            with self.subTest(cookies=cookies):
                result = test_insecure_cookies(cookies)
                self.assertEqual(result['total_issues'], expected['total_issues'])
                self.assertEqual(len(result['insecure']), len(expected['insecure']))
                if result['insecure']:
                    self.assertEqual(
                        sorted(result['insecure'][0]['issues']),
                        sorted(expected['insecure'][0]['issues'])
                    )

    def test_process_file_upload(self):
        """Test complete file upload processing."""
        # Test successful upload
        result = process_file_upload(self.safe_file.name)
        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'File uploaded successfully')
        self.assertIsNotNone(result['checksum'])
        
        # Test malicious file
        result = process_file_upload(self.xss_file.name)
        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'File failed security checks')
        
        # Test empty file
        result = process_file_upload(self.empty_file.name)
        self.assertFalse(result['success'])
        
        # Test invalid filename
        result = process_file_upload("../../etc/passwd")
        self.assertFalse(result['success'])

if __name__ == "__main__":
    unittest.main(failfast=True)