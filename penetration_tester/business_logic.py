# Business logic vulnerability testing

import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def test_discount_logic(user_role, discount):
    """
    Test for business logic flaws in discount application.

    Args:
        user_role (str): The role of the user (e.g., admin, user, guest).
        discount (float): The discount percentage to validate.

    Returns:
        bool: True if the discount logic passes validation, False otherwise.
    """
    valid_roles = {"admin", "user", "guest"}
    if user_role not in valid_roles:
        logging.warning(f"Invalid user role detected: {user_role}. Allowed roles: {valid_roles}")
        return False

    if user_role == "admin" and discount > 50:
        logging.warning(f"Admin users should not receive discounts greater than 50%. Discount provided: {discount}%")
        return False

    if discount < 0 or discount > 100:
        logging.warning(f"Invalid discount value detected: {discount}. Must be between 0 and 100.")
        return False

    logging.info(f"Discount logic passed validation for role: {user_role}, discount: {discount}%.")
    return True

if __name__ == "__main__":
    # Example usage
    test_discount_logic("admin", 60)  # Replace with test cases
