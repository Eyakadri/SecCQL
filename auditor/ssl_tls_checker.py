import ssl
import socket
import logging

def check_ssl(hostname, port=443):
    """
    Check SSL/TLS configuration for a given hostname.

    Args:
        hostname (str): The hostname to check.
        port (int): The port to connect to (default: 443).

    Returns:
        dict: SSL/TLS configuration details.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                logging.info(f"SSL certificate for {hostname}:{port} is valid.")
                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "protocol": ssock.version(),
                }
    except ssl.SSLError as ssl_error:
        logging.error(f"SSL error for {hostname}:{port}: {ssl_error}")
        return {"error": f"SSL error: {ssl_error}"}
    except socket.timeout:
        logging.error(f"Connection to {hostname}:{port} timed out.")
        return {"error": "Connection timed out"}
    except Exception as e:
        logging.error(f"SSL/TLS check failed for {hostname}:{port}: {e}")
        return {"error": str(e)}
