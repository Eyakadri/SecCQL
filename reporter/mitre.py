MITRE_MAPPING = {
    "XSS": "T1059.007",
    "SQL Injection": "T1190",
    "CSRF": "T1539",
    "SSRF": "T1071.001",
    "IDOR": "T1078",
    "Command Injection": "T1059",
}

def map_to_mitre(vulnerabilities):
    """
    Map vulnerabilities to MITRE ATT&CK framework techniques.

    Args:
        vulnerabilities (list): List of vulnerability dictionaries.

    Returns:
        list: Vulnerabilities with MITRE mappings.
    """
    for vulnerability in vulnerabilities:
        vulnerability["mitre"] = MITRE_MAPPING.get(vulnerability["type"], "Unknown")
    return vulnerabilities
