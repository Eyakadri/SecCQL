import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class IDORScanner:
    def __init__(self):
        self.test_ids = ["1", "2", "3", "4"]  # Example resource IDs to test

    def test_idor(self, url, session=None):
        """
        Test for IDOR vulnerabilities by manipulating resource IDs in the URL or query parameters.

        Args:
            url (str): The target URL to test.
            session (requests.Session, optional): A session object for making requests.

        Returns:
            bool: True if an IDOR vulnerability is detected, False otherwise.
        """
        session = session or requests.Session()
        try:
            logging.info(f"Testing IDOR on {url}")

            # Parse the URL to identify query parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Test IDOR in query parameters
            for param, values in query_params.items():
                for test_id in self.test_ids:
                    modified_params = query_params.copy()
                    modified_params[param] = test_id
                    modified_query = urlencode(modified_params, doseq=True)
                    modified_url = urlunparse(parsed_url._replace(query=modified_query))

                    if self._test_url(modified_url, session):
                        logging.warning(f"Potential IDOR vulnerability found at {modified_url}")
                        print(f"Potential IDOR vulnerability found at {modified_url}")
                        return True

            # Test IDOR in the path (if applicable)
            for test_id in self.test_ids:
                if "1" in parsed_url.path:  # Replace "1" as an example ID
                    modified_path = parsed_url.path.replace("1", test_id)
                    modified_url = urlunparse(parsed_url._replace(path=modified_path))

                    if self._test_url(modified_url, session):
                        logging.warning(f"Potential IDOR vulnerability found at {modified_url}")
                        print(f"Potential IDOR vulnerability found at {modified_url}")
                        return True

        except Exception as e:
            logging.error(f"Error testing IDOR on {url}: {e}")
        return False

    def _test_url(self, url, session):
        """
        Send a request to the modified URL and check for unauthorized access.
        """
        try:
            response = session.get(url, timeout=10)  # Increased timeout
            if response.status_code == 200 and "unauthorized" not in response.text.lower():
                logging.info(f"Valid response received for {url}")
                return True
        except requests.RequestException as e:
            logging.error(f"Error sending request to {url}: {e}")
        return False