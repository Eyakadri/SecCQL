# Vulnerability Scanning Module

This module contains tools for detecting common web application vulnerabilities, including SSRF (Server-Side Request Forgery) and IDOR (Insecure Direct Object References).

## SSRF Scanner

The SSRF scanner tests URLs and forms for SSRF vulnerabilities by injecting payloads and analyzing responses.

### Usage

```python
from ssrf import SSRFScanner

scanner = SSRFScanner()
url = "http://example.com/vulnerable-endpoint"
if scanner.test_ssrf(url):
    print("SSRF vulnerability detected!")
```

## IDOR Scanner

The IDOR scanner tests for vulnerabilities by manipulating resource IDs in URLs or query parameters.

### Usage

```python
from idor import IDORScanner

scanner = IDORScanner()
url = "http://example.com/resource?id=1"
if scanner.test_idor(url):
    print("IDOR vulnerability detected!")
```

## Logs

Detected vulnerabilities are logged to the following files:
- `ssrf_vulnerabilities.log`
- `idor_vulnerabilities.log`