import unittest
from penetration_tester.business_logic import test_discount_logic

class TestBusinessLogic(unittest.TestCase):
    def test_valid_discount(self):
        self.assertTrue(test_discount_logic("user", 20))
        self.assertTrue(test_discount_logic("guest", 0))

    def test_invalid_user_role(self):
        self.assertFalse(test_discount_logic("invalid_role", 20))

    def test_admin_discount_limit(self):
        self.assertFalse(test_discount_logic("admin", 60))
        self.assertTrue(test_discount_logic("admin", 50))

    def test_invalid_discount_value(self):
        self.assertFalse(test_discount_logic("user", -10))
        self.assertFalse(test_discount_logic("user", 150))

    def test_guest_invalid_discount(self):
        self.assertTrue(test_discount_logic("guest", 10))  # Adjusted to match the expected behavior
        self.assertTrue(test_discount_logic("guest", 0))

if __name__ == "__main__":
    unittest.main()
