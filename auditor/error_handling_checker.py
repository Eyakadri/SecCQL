import requests
import logging

def check_error_handling(url):
    """
    Check for improper error handling in a web application.

    Args:
        url (str): The URL to check.

    Returns:
        dict: Error handling analysis results.
    """
    error_pages = ["/nonexistent", "/error", "/404"]
    results = {}
    try:
        for page in error_pages:
            test_url = f"{url.rstrip('/')}{page}"
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200 and "error" in response.text.lower():
                results[page] = "Improper error handling detected"
            else:
                results[page] = "Proper error handling"
        logging.info(f"Error handling check for {url} completed successfully.")
        return results
    except requests.exceptions.Timeout:
        logging.error(f"Error handling check for {url} timed out.")
        return {"error": "Request timed out"}
    except Exception as e:
        logging.error(f"Failed to check error handling for {url}: {e}")
        return {"error": str(e)}
