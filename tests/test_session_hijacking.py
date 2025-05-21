import unittest
from datetime import datetime, timedelta
from scanner.session_hijacking import is_token_secure, is_token_expired, simulate_session_fixation, rotate_token

class TestSessionHijacking(unittest.TestCase):
    def test_is_token_secure(self):
        self.assertTrue(is_token_secure("a" * 32))
        self.assertFalse(is_token_secure("short"))

    def test_is_token_expired(self):
        creation_time = datetime.now() - timedelta(minutes=31)
        self.assertTrue(is_token_expired(creation_time))
        creation_time = datetime.now() - timedelta(minutes=29)
        self.assertFalse(is_token_expired(creation_time))

    def test_simulate_session_fixation(self):
        self.assertEqual(simulate_session_fixation("original", "malicious"), "malicious")

    def test_rotate_token(self):
        original_token = "a" * 32
        new_token = rotate_token(original_token)
        self.assertNotEqual(original_token, new_token)
        self.assertTrue(is_token_secure(new_token))

if __name__ == "__main__":
    unittest.main()
