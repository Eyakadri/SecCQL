# Brute-force attack simulation

import time
import logging
import hashlib
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

MAX_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 minutes
IP_ATTEMPTS = {}

def hash_password(password):
    """
    Hash the password for secure comparison.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def is_password_strong(password):
    """
    Check if the password meets strength requirements.
    """
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password):
        logging.warning(f"Weak password rejected: {password}")
        return False
    return True

def simulate_login(username, password, attempt_tracker, mfa_code=None, ip_address=None):
    """
    Simulate a login system with brute-force detection.

    Args:
        username (str): The username attempting to log in.
        password (str): The password provided by the user.
        attempt_tracker (dict): A dictionary tracking login attempts.
        mfa_code (str, optional): The MFA code provided by the user.
        ip_address (str, optional): The IP address of the user attempting to log in.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    correct_username = "admin"
    correct_password_hash = hash_password("password123")

    # Check password strength
    if not is_password_strong(password):
        return False

    # Enforce MFA for admin users
    if username == "admin" and mfa_code != "123456":  # Example MFA enforcement
        logging.warning(f"MFA required for admin user {username}. Login denied.")
        return False

    # Initialize tracker for new user
    if username not in attempt_tracker:
        attempt_tracker[username] = {'attempts': 0, 'last_attempt': 0}

    # Check lockout status
    time_since_last_attempt = time.time() - attempt_tracker[username]['last_attempt']
    if attempt_tracker[username]['attempts'] >= MAX_ATTEMPTS:
        if time_since_last_attempt < LOCKOUT_TIME:
            logging.warning(f"Account locked for user {username}. Time remaining: {LOCKOUT_TIME - time_since_last_attempt:.2f} seconds.")
            return False
        else:
            logging.info(f"Lockout period expired for user {username}. Resetting attempts.")
            attempt_tracker[username]['attempts'] = 0  # Reset attempts after lockout period

    # IP-based throttling
    if ip_address:
        if ip_address not in IP_ATTEMPTS:
            IP_ATTEMPTS[ip_address] = 0
        IP_ATTEMPTS[ip_address] += 1
        if IP_ATTEMPTS[ip_address] > 10:  # Example threshold
            logging.warning(f"IP {ip_address} temporarily blocked due to excessive login attempts.")
            return False

    # Check credentials
    if username == correct_username and hash_password(password) == correct_password_hash:
        logging.info(f"Login successful for user {username}. Attempts reset.")
        attempt_tracker.pop(username, None)  # Clear tracker on successful login
        return True
    else:
        attempt_tracker[username]['attempts'] += 1
        attempt_tracker[username]['last_attempt'] = time.time()
        logging.warning(f"Login failed for user {username}. Incorrect credentials. Attempts: {attempt_tracker[username]['attempts']}")
        return False

if __name__ == "__main__":
    # Example usage
    attempts = {}
    simulate_login("admin", "wrongpassword", attempts, ip_address="192.168.1.1")
    simulate_login("admin", "password123", attempts, mfa_code="123456", ip_address="192.168.1.1")