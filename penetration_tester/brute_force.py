# Brute-force attack simulation

import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

MAX_ATTEMPTS = 5
LOCKOUT_TIME = 60  # in seconds

def simulate_login(username, password, attempt_tracker):
    """
    Simulate a login system with brute-force detection.
    """
    correct_username = "admin"
    correct_password = "password123"

    if username in attempt_tracker and attempt_tracker[username]['attempts'] >= MAX_ATTEMPTS:
        if time.time() - attempt_tracker[username]['last_attempt'] < LOCKOUT_TIME:
            logging.warning(f"Account locked for user {username}. Try again later.")
            return False
        else:
            attempt_tracker[username]['attempts'] = 0  # Reset attempts after lockout period

    if username == correct_username and password == correct_password:
        logging.info(f"Login successful for user {username}.")
        attempt_tracker.pop(username, None)  # Clear tracker on successful login
        return True
    else:
        logging.warning(f"Login failed for user {username}.")
        if username not in attempt_tracker:
            attempt_tracker[username] = {'attempts': 0, 'last_attempt': 0}
        attempt_tracker[username]['attempts'] += 1
        attempt_tracker[username]['last_attempt'] = time.time()
        return False

if __name__ == "__main__":
    # Example usage
    attempts = {}
    simulate_login("admin", "wrongpassword", attempts)
    simulate_login("admin", "password123", attempts)