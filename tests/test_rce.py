import unittest
from penetration_tester.rce import execute_command

class TestRCE(unittest.TestCase):
    def test_safe_command(self):
        result = execute_command("echo Hello")
        self.assertEqual(result.strip(), "Hello")

    def test_dangerous_command(self):
        dangerous_commands = ["rm -rf /", "; ls", "&& whoami"]
        for command in dangerous_commands:
            self.assertIsNone(execute_command(command))

if __name__ == "__main__":
    unittest.main()
