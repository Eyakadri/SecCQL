import requests
import logging

def check_gdpr_compliance(url):
    """
    Check GDPR compliance for a given URL.

    Args:
        url (str): The URL to check.

    Returns:
        dict: GDPR compliance results.
    """
    try:
        response = requests.get(url, timeout=10)
        cookies = response.cookies
        compliance = {
            "has_cookie_banner": "cookie" in response.text.lower(),
            "uses_secure_cookies": all(cookie.secure for cookie in cookies),
            "has_privacy_policy": "privacy policy" in response.text.lower(),
        }
        logging.info(f"GDPR compliance check for {url} completed successfully.")
        print(f"GDPR compliance results for {url}: {compliance}")  # Display results in the console
        return compliance
    except requests.exceptions.Timeout:
        logging.error(f"GDPR compliance check for {url} timed out.")
        print(f"GDPR compliance check for {url} timed out.")  # Display error in the console
        return {"error": "Request timed out"}
    except Exception as e:
        logging.error(f"Failed to check GDPR compliance for {url}: {e}")
        print(f"Failed to check GDPR compliance for {url}: {e}")  # Display error in the console
        return {"error": str(e)}
