import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup  # Added for dynamic ID extraction

class IDORScanner:
    def __init__(self, test_ids=None):
        """
        Initialize the IDOR scanner with configurable test IDs.
        Args:
            test_ids (list, optional): List of resource IDs to test. Defaults to ["1", "2", "3", "4"].
        """
        self.test_ids = test_ids or ["1", "2", "3", "4"]  # Default test IDs
        self.log_file = "idor_vulnerabilities.log"  # Log file for detected vulnerabilities
        logging.basicConfig(filename=self.log_file, level=logging.INFO)

    def test_idor(self, url, session=None):
        """
        Test for IDOR vulnerabilities by manipulating resource IDs in the URL or query parameters.

        Args:
            url (str): The target URL to test.
            session (requests.Session, optional): A session object for making requests.

        Returns:
            bool: True if an IDOR vulnerability is detected, False otherwise.
        """
        if not self._is_valid_url(url):
            logging.error(f"Invalid URL: {url}")
            return False

        session = session or requests.Session()
        try:
            logging.info(f"Testing IDOR on {url}")

            # Parse the URL to identify query parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Dynamically extract IDs from the page
            dynamic_ids = self._extract_ids_from_page(url, session)
            test_ids = self.test_ids + dynamic_ids

            # Test IDOR in query parameters
            for param, values in query_params.items():
                for test_id in test_ids:
                    modified_params = query_params.copy()
                    modified_params[param] = test_id
                    modified_query = urlencode(modified_params, doseq=True)
                    modified_url = urlunparse(parsed_url._replace(query=modified_query))

                    if self._test_url(modified_url, session):
                        logging.warning(f"Potential IDOR vulnerability found at {modified_url}")
                        print(f"Potential IDOR vulnerability found at {modified_url}")
                        return True

            # Test IDOR in the path (if applicable)
            for test_id in test_ids:
                if any(id in parsed_url.path for id in dynamic_ids):  # Replace dynamic IDs
                    modified_path = parsed_url.path
                    for id in dynamic_ids:
                        modified_path = modified_path.replace(id, test_id)
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
            response = session.get(url, timeout=10)
            if response.status_code == 200 and "unauthorized" not in response.text.lower():
                logging.info(f"Valid response received for {url}")
                logging.warning(f"Potential IDOR vulnerability found at {url}")
                return True
        except requests.RequestException as e:
            logging.error(f"Error sending request to {url}: {e}")
        return False

    def _extract_ids_from_page(self, url, session):
        """
        Extract potential resource IDs from the page content.

        Args:
            url (str): The target URL.
            session (requests.Session): The session object for making requests.

        Returns:
            list: A list of extracted IDs.
        """
        try:
            response = session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            ids = set()
            for link in soup.find_all("a", href=True):
                parsed_link = urlparse(link["href"])
                params = parse_qs(parsed_link.query)
                for param, values in params.items():
                    ids.update(values)
            for input_tag in soup.find_all("input", {"type": "hidden"}):
                if input_tag.get("name") and input_tag.get("value").isdigit():
                    ids.add(input_tag["value"])
            logging.info(f"Extracted dynamic IDs: {ids}")
            return list(ids)
        except Exception as e:
            logging.error(f"Error extracting IDs from {url}: {e}")
            return []

    def _is_valid_url(self, url):
        """
        Validate the given URL.

        Args:
            url (str): The URL to validate.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False