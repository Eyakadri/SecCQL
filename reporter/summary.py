from collections import Counter

def generate_summary(vulnerabilities):
    """
    Generate a summary of vulnerabilities by type and severity.

    Args:
        vulnerabilities (list): List of vulnerability dictionaries.

    Returns:
        dict: Summary of vulnerabilities.
    """
    summary = {
        "total": len(vulnerabilities),
        "by_type": Counter(v["type"] for v in vulnerabilities),
        "by_severity": Counter(v["severity"] for v in vulnerabilities),
    }
    return summary
