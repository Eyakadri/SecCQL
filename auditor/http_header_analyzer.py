import requests
import logging

def analyze_headers(url):
    """
    Analyze HTTP headers for security configurations.

    Args:
        url (str): The URL to analyze.

    Returns:
        dict: Analysis results for security headers.
    """
    try:
        response = requests.head(url, timeout=10)
        headers = response.headers
        results = {
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing"),
        }
        logging.info(f"HTTP header analysis for {url} completed.")
        return results
    except Exception as e:
        logging.error(f"Failed to analyze headers for {url}: {e}")
        return {"error": str(e)}

def enforce_security_headers(headers):
    """
    Ensure CSP, HSTS, and X-Frame-Options are enforced.
    """
    required_headers = {
        "Content-Security-Policy": "default-src 'self';",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
    }
    for header, value in required_headers.items():
        if headers.get(header) != value:
            logging.warning(f"Missing or incorrect security header: {header}")
