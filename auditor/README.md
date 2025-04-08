# Auditor Module

The `auditor` module analyzes web application configurations for security issues.

## Features
- **SSL/TLS Checker**: Verifies SSL/TLS configurations.
- **HTTP Header Analyzer**: Checks for security headers like `Content-Security-Policy`.
- **GDPR Compliance Checker**: Ensures compliance with GDPR regulations.
- **Error Handling Checker**: Detects improper error handling.

## Usage
```python
from auditor.ssl_tls_checker import check_ssl
from auditor.http_header_analyzer import analyze_headers

check_ssl("https://example.com")
analyze_headers("https://example.com")
```
