import unittest
import time
from scanner.brute_force import simulate_login, hash_password, is_password_strong

class TestBruteForce(unittest.TestCase):
    def test_successful_login(self):
        attempts = {}
        self.assertFalse(simulate_login("admin", "password123", attempts))

    def test_failed_login(self):
        attempts = {}
        self.assertFalse(simulate_login("admin", "wrongpassword", attempts))

    def test_account_lockout(self):
        attempts = {}
        for _ in range(5):
            simulate_login("admin", "wrongpassword", attempts)
        self.assertFalse(simulate_login("admin", "wrongpassword", attempts))
        time.sleep(60)  # Simulate lockout expiration
        self.assertFalse(simulate_login("admin", "password123", attempts))

    def test_hash_password(self):
        self.assertEqual(hash_password("test"), hash_password("test"))

    def test_special_characters_in_login(self):
        attempts = {}
        self.assertFalse(simulate_login("admin", "!@#$%^&*", attempts))

    def test_empty_credentials(self):
        attempts = {}
        self.assertFalse(simulate_login("", "", attempts))

    def test_weak_password(self):
        self.assertFalse(is_password_strong("weak"))
        self.assertFalse(is_password_strong("12345678"))

if __name__ == "__main__":
    unittest.main()
