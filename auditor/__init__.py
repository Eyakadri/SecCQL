# ...existing code...
def enforce_security_headers(headers):
    """
    Ensures that the provided headers include necessary security headers.
    Returns a list of missing headers if any.
    """
    required_headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
    missing_headers = [header for header in required_headers if header not in headers]
    return missing_headers
# ...existing code...