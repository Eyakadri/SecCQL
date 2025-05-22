# ⚔️ secCQL — Modular Web Application Pentest CLI
![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![License](https://img.shields.io/badge/License-MIT-yellow)

**seccql** is a powerful, modular, and interactive command-line toolkit for advanced web application penetration testing. Built by hackers for hackers, `seccql` is designed to scan, audit, exploit, and report with precision — all from your terminal.

---

## 🔥 Highlights

- ✅ Interactive command console with `cmd2`
- 🧩 Modular architecture for scanners, auditors, and exploits
- 🌐 Deep crawling and session-aware testing
- 🧠 Smart simulations: business logic, RCE, brute-force, etc.
- 📑 Exportable reports (plaintext, JSON, CSV)
- 🦾 Fully customizable for red team workflows

## 📌 Use Cases

- Red team simulation exercises
- Web application security assessments
- CTF automation tooling
- Bug bounty recon and testing
- Compliance (GDPR/OWASP) audits

## 📂 Project Structure
---

SECCQL/
    ├── auditor/
    ├── cli/
    ├── config/
    ├── crawler/
    ├── reporter/
    ├── scanner/
    └── tests/
├── main.py
├── setup.py
├── requirements.txt
├── README.md

---
## Directory Overview

- **auditor/**: Contains code for auditing functionality
- **cli/**: Command-line interface components
- **config/**: Configuration files and settings
- **crawler/**: Web crawling components
- **reporter/**: Reporting and output generation
- **scanner/**: Scanning functionality
- **tests/**: Test cases and testing utilities

## Key Files

- `main.py`: Main entry point for the application
- `setup.py`: Installation and setup configuration
- `requirements.txt`: Python dependencies
- `README.md`: Project documentation (this file)

## ✨ Features

- **✅ Comprehensive Auditing**: Ensure compliance with GDPR and other standards.
- **🛡️ Advanced Scanning**: Detect vulnerabilities like SQL injection, XSS, CSRF, and more.
- **💥 Penetration Testing**: Simulate real-world attacks to identify weaknesses.
- **📊 Custom Reporting**: Generate detailed vulnerability reports with templates.

---

## ⚙️ Tech Stack
- Python 3.8+
- cmd2

## ⚙️ Installation

Follow these steps to set up the project:

1. Clone the repository:
   ```bash
   git clone https://github.com/Eyakadri/SecCQL.git
   ```
2. Navigate to the project directory:
   ```bash
   cd SecCQL
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Run it
   ```bash
   SecCQL
   ```

## 🤝 Contributing

We welcome contributions! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

## 🧑‍💻 Crafted for offensive security professionals. Stay sharp. Stay stealthy.

--- 

Made with ❤️ by the SecCQL Developer.
