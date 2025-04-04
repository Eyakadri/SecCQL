import re
from bs4 import BeautifulSoup

def find_api_endpoints(html):
    """
    Extracts API endpoints (URLs) from script tags in the given HTML content.

    Args:
        html (str): The HTML content as a string.

    Returns:
        set: A set of unique API endpoint URLs found in the script tags.
    """
    if not html:
        return set()  # Return an empty set if the input is None or empty

    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")
    endpoints = set()
    for script in scripts:
        if script.string:
            # Refined regex to avoid false positives
            endpoints.update(re.findall(r'https?://[^\s\'"<>]+', script.string))
    return endpoints