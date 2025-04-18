import requests
import logging

def check_certificate_transparency(domain):
    """
    Check certificate transparency logs for a given domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: Certificate transparency log details.
    """
    ct_log_url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(ct_log_url, timeout=10)
        if response.status_code == 200:
            logs = response.json()
            logging.info(f"Certificate transparency logs for {domain} retrieved.")
            return {"logs": logs[:5]}  # Return the first 5 logs for brevity
        else:
            logging.warning(f"Failed to retrieve certificate transparency logs for {domain}.")
            return {"error": "Failed to retrieve logs"}
    except Exception as e:
        logging.error(f"Error checking certificate transparency for {domain}: {e}")
        return {"error": str(e)}
