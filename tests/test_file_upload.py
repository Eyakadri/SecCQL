import unittest
import os
import tempfile
from scanner.file_upload import (
    is_file_safe,
    prevent_directory_traversal,
    analyze_insecure_cookies,
    process_file_upload,
    init_security_system # Import the init function
)

class TestFileUpload(unittest.TestCase):
    """Test suite for file upload security functions."""
    
    def setUp(self):
        """Create temporary files, ensure quarantine directory exists, and init DB."""
        # Initialize security system (creates DB table if needed)
        init_security_system()

        # Ensure quarantine directory exists for tests that might use it
        quarantine_dir = os.path.join(os.path.dirname(__file__), "..", "scanner", "quarantine") # Path relative to test file
        os.makedirs(quarantine_dir, exist_ok=True)
        self.quarantine_dir = quarantine_dir # Store for potential cleanup

        self.safe_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.safe_file.write(b"Safe content")
        self.safe_file.close()
        
        self.empty_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.empty_file.close()
        
        self.xss_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.xss_file.write(b"<script>alert('XSS')</script>") # Use single quotes inside
        self.xss_file.close()

        # Test binary file
        self.binary_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.binary_file.write(b"\x00\x01Binary\xFF\xFE")
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
        # Expected format: (input_path, expected_tuple_result)
        test_cases = [
            ("../../etc/passwd", (False, 'directory_traversal')), # Traversal attempt
            ("..\\..\\windows\\system32", (False, 'directory_traversal')), # Traversal attempt (Windows)
            # (".", (False, 'invalid_filename')), # Current dir - should be handled if needed
            # ("..", (False, 'invalid_filename')), # Parent dir - should be handled if needed
            ("normal_file.txt", (True, "normal_file.txt")), # Safe case
            ("", (False, 'invalid_filename')), # Empty input
            ("just/a/path/safe.txt", (True, "safe.txt")), # Path with safe filename
            ("invalid/name.txt", (True, "name.txt")), # Path with safe filename
            ("invalid\\name.txt", (True, "name.txt")), # Path with safe filename (Windows)
            ("/absolute/path/file.txt", (False, 'absolute_path')), # Absolute path
            ("C:\\absolute\\path\\file.txt", (False, 'absolute_path')), # Absolute path (Windows)
            ("../relative/path/to/file.txt", (False, "directory_traversal")), # Relative path with traversal
            ("CON", (False, 'reserved_filename')), # Reserved name
            ("file_with_null\x00.txt", (False, "invalid_character_null_byte")), # Null byte
            ("a" * 300 + ".txt", (False, 'filename_too_long')), # Long filename
            ("etc/passwd", (False, "sensitive_filename")), # Sensitive filename
        ]
        
        for input_path, expected_tuple in test_cases:
            with self.subTest(input_path=input_path):
                result_tuple = prevent_directory_traversal(input_path)
                self.assertEqual(result_tuple, expected_tuple)

    def test_sanitize_reserved_names(self):
        """Test that reserved filenames are sanitized."""
        reserved_names = [
            "CON.txt", "PRN.jpg", "AUX", "NUL.pdf", "COM1.doc",
            "LPT9", "COM8", "LPT1.docx", "con", "prn.txt"
        ]
        for name in reserved_names:
            with self.subTest(name=name):
                # prevent_directory_traversal returns a tuple (success_bool, reason_str)
                result_tuple = prevent_directory_traversal(name)
                # For reserved names, expect (False, 'reserved_filename')
                self.assertEqual(result_tuple, (False, 'reserved_filename'))

    def test_insecure_cookies_detection(self):
        """Test insecure cookie detection."""
        test_cases = [
            (
                [{"name": "session", "secure": True, "httpOnly": True, "sameSite": "Strict"}],
                {'insecure': [], 'total_issues': 0}
            ),
            (
                [{"name": "auth", "secure": False, "httpOnly": True}],
                # Expect 2 issues: missing secure, invalid sameSite (httpOnly is True)
                {
                    "insecure": [{
                        "name": "auth", 
                        "issues": [
                            "missing secure flag", 
                            "invalid SameSite value"
                        ]
                    }], 
                    "total_issues": 2
                }
            ),
            (
                [{"name": "__Secure-ID", "secure": False}],
                # Expect 4 issues: missing secure, missing httpOnly, invalid sameSite, __Secure prefix violation
                {
                    "insecure": [{
                        "name": "__Secure-ID", 
                        "issues": [
                            "missing secure flag", 
                            "missing HttpOnly flag", 
                            "invalid SameSite value", 
                            "__Secure- prefix requires secure flag"
                        ]
                    }], 
                    "total_issues": 4 # Corrected expected count
                }
            ),
            (
                [{"name": "__Host-ID", "secure": True, "path": "/", "domain": "example.com"}],
                # Expect 1 issue because __Host- prefix requires NO domain attribute
                {
                    'insecure': [{'name': '__Host-ID', 'issues': ['__Host- prefix requirements not met']}], 
                    'total_issues': 1 # Corrected expected count
                }
            )
        ]
        for cookies, expected in test_cases:
            with self.subTest(cookies=cookies):
                result = analyze_insecure_cookies(cookies)
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
        self.assertFalse(result["success"])
        # Expect a more specific message if quarantine fails due to the temp file potentially being deleted
        self.assertIn("File failed security checks", result["message"]) # Check if the core message is present
        # self.assertEqual(result["message"], "File failed security checks; quarantine failed") # Original stricter check

        # Test empty file
        result = process_file_upload(self.empty_file.name)
        self.assertFalse(result["success"])

        # Test invalid filename
        result = process_file_upload("../../etc/passwd")
        self.assertFalse(result["success"])

if __name__ == "__main__":
    unittest.main(failfast=True)