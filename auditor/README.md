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

# Check SSL/TLS configuration
ssl_results = check_ssl("example.com")
print(ssl_results)

# Analyze HTTP headers
header_results = analyze_headers("https://example.com")
print(header_results)
```
