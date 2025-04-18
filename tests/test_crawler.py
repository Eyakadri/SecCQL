import unittest
from unittest.mock import MagicMock, patch
from crawler.utils import find_api_endpoints
from crawler.crawler import WebCrawler

class TestCrawlerUtils(unittest.TestCase):
    def test_find_api_endpoints(self):
        html = '<script>fetch("https://api.example.com/data")</script>'
        endpoints = find_api_endpoints(html)
        self.assertIn("https://api.example.com/data", endpoints)

    def test_find_api_endpoints_empty_html(self):
        endpoints = find_api_endpoints("")
        self.assertEqual(len(endpoints), 0)

    @patch("crawler.crawler.WebCrawler.fetch_page")
    def test_extract_links(self, mock_fetch_page):
        mock_fetch_page.return_value = """
            <html>
                <body>
                    <a href="http://example.com/page1">Page 1</a>
                    <a href="http://example.com/page2">Page 2</a>
                </body>
            </html>
        """
        crawler = WebCrawler(base_url="http://example.com")
        links = crawler.extract_links(mock_fetch_page.return_value, crawler.base_url)
        self.assertIn("http://example.com/page1", links)
        self.assertIn("http://example.com/page2", links)
        self.assertEqual(len(links), 2)

    @patch("crawler.crawler.WebCrawler.fetch_page")
    def test_extract_forms(self, mock_fetch_page):
        mock_fetch_page.return_value = """
            <html>
                <body>
                    <form action="/submit" method="POST">
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                        <input type="submit" value="Login" />
                    </form>
                </body>
            </html>
        """
        crawler = WebCrawler(base_url="http://example.com")
        forms = crawler.extract_forms(mock_fetch_page.return_value)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "/submit")
        self.assertEqual(forms[0]["method"], "POST")
        self.assertEqual(len(forms[0]["inputs"]), 3)

    @patch("crawler.crawler.WebCrawler.simulate_human_interaction")
    def test_simulate_human_interaction(self, mock_simulate_human_interaction):
        crawler = WebCrawler(base_url="http://example.com")
        crawler.simulate_human_interaction()
        mock_simulate_human_interaction.assert_called_once()

if __name__ == "__main__":
    unittest.main()
