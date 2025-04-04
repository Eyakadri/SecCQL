# Business logic vulnerability testing

import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def test_discount_logic(user_role, discount):
    """
    Test for business logic flaws in discount application.
    """
    if user_role == "admin" and discount > 50:
        logging.warning("Admin users should not receive discounts greater than 50%.")
        return False

    if discount < 0 or discount > 100:
        logging.warning("Invalid discount value detected.")
        return False

    logging.info("Discount logic passed validation.")
    return True

if __name__ == "__main__":
    # Example usage
    test_discount_logic("admin", 60)  # Replace with test cases
