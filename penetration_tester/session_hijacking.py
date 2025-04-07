# Session token analysis

import secrets
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def is_token_secure(token):
    """
    Check if the session token is secure by analyzing its length and randomness.
    """
    if len(token) < 32:
        logging.warning("Session token is too short, making it vulnerable to brute-force attacks.")
        return False

    try:
        generated_token = secrets.token_hex(len(token) // 2)
        if token == generated_token:  # Avoid predictable tokens
            logging.warning("Session token is predictable.")
            return False
    except Exception as e:
        logging.error(f"Error validating token randomness: {e}")
        return False

    logging.info("Session token appears secure.")
    return True

def is_token_expired(creation_time, max_age_minutes=30):
    """
    Check if the session token has expired based on its creation time.
    """
    expiration_time = creation_time + timedelta(minutes=max_age_minutes)
    if datetime.now() > expiration_time:
        logging.warning("Session token has expired.")
        return True

    logging.info("Session token is still valid.")
    return False

if __name__ == "__main__":
    # Example usage
    test_token = secrets.token_hex(16)  # Generate a random token
    creation_time = datetime.now()

    logging.info(f"Generated token: {test_token}")
    is_token_secure(test_token)
    is_token_expired(creation_time)