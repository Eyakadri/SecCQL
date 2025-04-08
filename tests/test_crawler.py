import unittest
from crawler.utils import find_api_endpoints

class TestCrawlerUtils(unittest.TestCase):
    def test_find_api_endpoints(self):
        html = '<script>fetch("https://api.example.com/data")</script>'
        endpoints = find_api_endpoints(html)
        self.assertIn("https://api.example.com/data", endpoints)

if __name__ == "__main__":
    unittest.main()
