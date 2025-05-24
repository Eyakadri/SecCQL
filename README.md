# ⚔️ SecCQL: Advanced Web Application Security Testing Framework

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md) 

**SecCQL** is a powerful, modular, and interactive command-line toolkit meticulously crafted for advanced web application penetration testing. Designed by security professionals for security professionals, `SecCQL` empowers you to scan, audit, exploit, and report vulnerabilities with unparalleled precision and efficiency—all directly from your terminal.

---

## ✨ Key Features & Highlights

SecCQL stands out with its robust feature set designed for modern web security challenges:

*   **🚀 Interactive Command Console:** Leverage a sophisticated and user-friendly interactive console powered by `cmd2`, offering command history, tab completion, and dynamic context.
*   **🧩 Modular Architecture:** Easily extend and customize the framework. SecCQL features a modular design for scanners (SQLi, XSS, CSRF, RCE, SSRF, IDOR, File Upload, Business Logic, Brute Force), auditors (SSL/TLS, Headers, GDPR), and reporting.
*   **🌐 Deep Crawling & Session Awareness:** Discover more of the target application with an intelligent web crawler that handles sessions, respects `robots.txt` (optional), and uses techniques like Selenium Stealth to mimic human interaction and bypass certain protections.
*   **🧠 Smart Vulnerability Detection:** Go beyond basic checks. SecCQL employs sophisticated techniques for detecting complex vulnerabilities, including time-based blind SQLi, advanced XSS payloads, and context-aware CSRF testing.
*   **🛡️ Comprehensive Auditing:** Perform detailed security audits covering SSL/TLS configuration, HTTP security headers (CSP, HSTS, etc.), cookie security attributes (HttpOnly, Secure, SameSite), GDPR compliance checks, and more.
*   **📊 Flexible Reporting:** Generate detailed and customizable vulnerability reports in various formats, including plain text, JSON, and CSV. Visualize findings with automatically generated severity charts.
*   **🦾 Red Team Ready:** Built with customization in mind, SecCQL can be easily integrated into existing red team workflows and tailored for specific engagement needs.

---

## 🎯 Use Cases

SecCQL is versatile and ideal for various security tasks:

*   Comprehensive Web Application Security Assessments
*   Automated Vulnerability Scanning and Verification
*   Red Team Operations and Penetration Testing Engagements
*   Bug Bounty Hunting Reconnaissance and Exploitation
*   Security Compliance Audits (OWASP Top 10, GDPR)
*   CTF Challenge Automation and Tooling

---

## ⚙️ Installation

Get SecCQL up and running in a few simple steps:

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/Eyakadri/SecCQL.git
    cd SecCQL
    ```

2.  **Install Dependencies:**
    It's highly recommended to use a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```
    *Note: Ensure you have Python 3.9 or newer installed.* 

3.  **Setup (Optional but Recommended):**
    Install SecCQL as a command-line tool:
    ```bash
    pip install .
    ```
    This allows you to run `SecCQL` directly from anywhere in your terminal.

---

## 🚀 Usage

Launch the interactive console:

```bash
SecCQL
```

Once inside the console, use `help` or `?` to see available commands. Here are some examples:

*   **Start a Scan:**
    ```
    SecCQL > scan
    # Follow the interactive prompts to select scan type and target URL
    ```

*   **Perform an Audit:**
    ```
    SecCQL > audit
    # Select the audit type (e.g., API Security, Cookie Security, CSP)
    ```

*   **Crawl a Website:**
    ```
    SecCQL > crawl
    # Enter the starting URL and choose whether to save data
    ```

*   **Generate a Report:**
    ```
    SecCQL > report
    # Enter report name and select format (text, json, csv)
    ```
---

## 📂 Project Structure

```
SecCQL/
├── auditor/         # Security auditing modules (SSL, Headers, GDPR, etc.)
├── cli/             # Command-line interface logic (cmd2 console, commands)
├── config/          # Configuration files (if any)
├── crawler/         # Web crawling components (crawler, db_handler, selenium)
├── reporter/        # Report generation (text, json, csv, charts, html)
├── scanner/         # Vulnerability scanning modules (SQLi, XSS, CSRF, etc.)
├── tests/           # Unit and integration tests
├── .gitignore       # Git ignore rules
├── LICENSE          # Project License file (MIT)
├── main.py          # Main entry point (primarily for crawler execution)
├── README.md        # This file!
├── requirements.txt # Python dependencies
└── setup.py         # Installation script
```

---

## 🛠️ Technology Stack

*   **Python 3.9+**
*   **cmd2:** For the interactive console interface
*   **requests:** For making HTTP requests
*   **BeautifulSoup4:** For parsing HTML
*   **Selenium & selenium-stealth:** For advanced web crawling and interaction
*   **InquirerPy:** For interactive prompts
*   **Rich:** For beautiful terminal output
*   **Matplotlib:** For generating report charts
*   **Jinja2:** For HTML report templating
*   **SQLite:** For local data storage (crawler data, security attempts)

---

## 🤝 Contributing

Contributions are highly welcome! Whether it's reporting a bug, suggesting a feature, or submitting a pull request, your help is appreciated. Please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide (you might need to create this file) for details on the process.

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/YourFeature` or `bugfix/YourBugfix`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some feature'`).
5.  Push to the branch (`git push origin feature/YourFeature`).
6.  Open a Pull Request.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

---

🧑‍💻 **Crafted for offensive security professionals. Stay sharp. Stay stealthy.** 🧑‍💻

--- 

Made with ❤️ by the SecCQL Developer.
