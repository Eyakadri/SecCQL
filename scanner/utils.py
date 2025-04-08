import re
# Helper functions for scanning

def detect_open_redirect(url):
    """
    Detect open redirect vulnerabilities in a URL.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if an open redirect is detected, False otherwise.
    """
    redirect_patterns = [
        r"(?i)redirect=(https?://)",
        r"(?i)next=(https?://)",
        r"(?i)url=(https?://)"
    ]
    for pattern in redirect_patterns:
        if re.search(pattern, url):
            return True
    return False

def validate_form_structure(form):
    """
    Validate the structure of a form.

    Args:
        form (dict): The form to validate.

    Returns:
        bool: True if the form is valid, False otherwise.
    """
    return bool(form.get("inputs") and form.get("action"))