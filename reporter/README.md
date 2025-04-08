# Reporter Module

The `reporter` module generates detailed vulnerability reports based on scan results.

## Features
- **HTML Templates**: Customizable templates for generating reports.
- **PDF Generation**: Export reports as PDF using WeasyPrint.
- **MITRE Mapping**: Map vulnerabilities to MITRE ATT&CK techniques.
- **Summary Generation**: Summarize vulnerabilities by type and severity.

## Usage

### Generate a PDF Report
```python
from reporter.report_generator import ReportGenerator
from reporter.summary import generate_summary
from reporter.mitre import map_to_mitre

vulnerabilities = [
    {"type": "XSS", "description": "Cross-site scripting detected.", "severity": "High", "recommendation": "Sanitize inputs."},
    {"type": "SQL Injection", "description": "SQLi vulnerability found.", "severity": "Critical", "recommendation": "Use parameterized queries."},
]

# Generate summary and map to MITRE
summary = generate_summary(vulnerabilities)
vulnerabilities = map_to_mitre(vulnerabilities)

# Generate PDF
reporter = ReportGenerator()
reporter.generate_pdf(vulnerabilities, "output/report.pdf")
```

## Dependencies
- `jinja2`
- `weasyprint`
