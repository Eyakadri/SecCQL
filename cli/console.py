from scanner import business_logic
from crawler.crawler import run_crawler
from reporter import report_generator
from auditor import core as auditor_core
from scanner import brute_force, file_upload, rce, session_hijacking, utils as scanner_utils
from InquirerPy import prompt
from cli.commands import cli
import cmd2
from cmd2 import (
    with_argparser,
    with_category,
    with_default_category
)
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import time
from typing import List, Dict, Any
import os
from pathlib import Path
import pickle
import importlib

from auditor.http_header_analyzer import analyze_headers
from auditor.ssl_tls_checker import check_ssl
from auditor.gdpr_checker import check_gdpr_compliance
from auditor.error_handling_checker import check_error_handling
from auditor.cert_transparency import check_certificate_transparency
from scanner.sqli import SQLInjectionScanner
from scanner.xss import XSSScanner
from scanner.csrf import CSRFScanner
from scanner.command_injection import CommandInjectionScanner
from scanner.ssrf import SSRFScanner
from scanner.idor import IDORScanner
from auditor.core import check_api_security, check_cookie_security, check_csp
from reporter.report_generator import ReportGenerator

console = Console()

# Constants
HISTORY_FILE = os.path.expanduser("~/.seccql_history")
CONFIG_DIR = os.path.expanduser("~/.seccql")
MODULES_DIR = "modules"

@with_default_category("Core Commands")
@with_category("CLI Commands")
class SecCQLConsole(cmd2.Cmd):
    """SecCQL Advanced Penetration Testing Console"""

    def __init__(self):
        # Persistent history setup
        self._create_config_dir()
        super().__init__(
            persistent_history_file=HISTORY_FILE,
            persistent_history_length=1000,
            startup_script=".seccqlrc",
            allow_cli_args=False
        )

        # Custom prompt with dynamic context
        self.prompt = "SecCQL > "
        self.intro = self._get_banner()

        # Module system
        self.current_module = None
        self.available_modules = self._load_modules()

        # Session state
        self.session_data = {
            'targets': [],
            'scan_results': {},
            'credentials': {}
        }

    def _create_config_dir(self):
        """Ensure config directory exists"""
        Path(CONFIG_DIR).mkdir(exist_ok=True)

    def _get_banner(self):
        """Generate the ASCII art banner"""
        return """
███████╗███████╗ ██████╗ ██████╗ ██████╗ ██╗
██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██║
███████╗█████╗  ██║     ██║     ██║   ██║██║
╚════██║██╔══╝  ██║     ██║     ██║▄▄ ██║██║
███████║███████╗╚██████╗╚██████╗╚██████╔╝███████╗
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚══▀▀═╝ ╚══════╝

SecCQL - Security Testing Framework For Web Applications

Type help or ? to get started
"""

    # ----- Scan Command -----
    scan_parser = cmd2.Cmd2ArgumentParser()
    scan_parser.add_argument('target', nargs='?', help="Target URL or IP (optional for interactive mode)")
    scan_parser.add_argument('-p', '--profile', choices=['fast', 'full', 'stealth'], default='fast')
    scan_parser.add_argument('-o', '--output', help="Output file")

    @with_argparser(scan_parser)
    def do_scan(self, args):
        """Perform a security scan (both interactive and CLI modes supported)"""
        if args.target is None:
            # Interactive mode
            questions = [
                {
                    "type": "list",
                    "name": "scan_type",
                    "message": "Select scan type:",
                    "choices": [
                        "SQL Injection", "XSS", "CSRF", "Command Injection", "SSRF", "IDOR",
                        "Brute Force", "Remote Code Execution (RCE)", "Business Logic", "File Upload", "Session Hijacking"
                    ],
                },
                {
                    "type": "input",
                    "name": "url",
                    "message": "Enter target URL:",
                    "validate": lambda val: val.startswith(('http://', 'https://')) or "URL must start with http:// or https://"
                }
            ]
            answers = prompt(questions)
            scan_type = answers['scan_type']
            url = answers['url']

            try:
                console.print(f"[cyan]🚀 Running {scan_type} scan on {url}...[/]")

                if scan_type == "SQL Injection":
                    scanner = SQLInjectionScanner(driver=None)
                    form = {
                        "action": url,
                        "method": "post",
                        "inputs": [{"name": "username"}, {"name": "password"}],  # Example inputs
                    }
                    try:
                        result = scanner.test_sql_injection(form, url)
                    except ValueError as e:
                        console.print(f"[red]❌ Error during SQL Injection scan: {e}[/]")
                        return False
                elif scan_type == "XSS":
                    scanner = XSSScanner(driver=None)  # Replace `None` with a Selenium WebDriver instance if needed
                    result = scanner.test_xss({"action": url, "inputs": []}, url)
                elif scan_type == "CSRF":
                    scanner = CSRFScanner(driver=None)  # Replace `None` with a Selenium WebDriver instance if needed
                    result = scanner.test_csrf({"action": url, "inputs": []}, url)
                elif scan_type == "Command Injection":
                    scanner = CommandInjectionScanner()
                    result = scanner.test_command_injection({"action": url, "inputs": []}, url)
                elif scan_type == "SSRF":
                    scanner = SSRFScanner()
                    result = scanner.test_ssrf(url)
                elif scan_type == "IDOR":
                    scanner = IDORScanner()
                    result = scanner.test_idor(url)
                elif scan_type == "Brute Force":
                    self._run_brute_force_test()
                elif scan_type == "Remote Code Execution (RCE)":
                    self._run_rce_test()
                elif scan_type == "Business Logic":
                    self._run_business_logic_test()
                elif scan_type == "File Upload":
                    self._run_file_upload_test()
                elif scan_type == "Session Hijacking":
                    self._run_session_hijacking_test()
                else:
                    console.print("[red]❌ Unknown scan type selected[/]")
                    return False

                if result:
                    console.print(f"[green]✅ {scan_type} scan completed successfully! Vulnerability detected.[/]")
                else:
                    console.print(f"[yellow]⚠ {scan_type} scan completed. No vulnerabilities detected.[/]")
                return True

            except KeyboardInterrupt:
                console.print("[yellow]⚠ Scan cancelled by user[/]")
                return False
            except Exception as e:
                console.print(f"[red]❌ Scan failed: {e}[/]")
                return False
        else:
            # CLI mode
            with Progress() as progress:
                task = progress.add_task(f"[cyan]Scanning {args.target}", total=100)
                for i in range(10):
                    time.sleep(0.1)
                    progress.update(task, advance=10)
                    if i == 5:
                        self._run_scan_module(args.target, args.profile)

            self.session_data['scan_results'][args.target] = {
                'status': 'completed',
                'profile': args.profile,
                'timestamp': time.time()
            }

            if args.output:
                self._save_results(args.output)
                console.print(f"[green]✓ Results saved to {args.output}[/]")
            else:
                self._display_scan_results(args.target)
            return True

    def _run_scan_module(self, target: str, profile: str):
        """Execute the appropriate scanner module"""
        console.print(f"[yellow]Running {profile} scan on {target}[/]")

        # Example: Simulate scan results
        vulnerabilities = [
            {"type": "XSS", "description": "Cross-site scripting detected.", "severity": "High", "recommendation": "Sanitize inputs."},
            {"type": "SQL Injection", "description": "SQLi vulnerability found.", "severity": "Critical", "recommendation": "Use parameterized queries."},
        ]

        self.session_data['scan_results'][target] = {
            'status': 'completed',
            'profile': profile,
            'timestamp': time.time(),
            'vulnerabilities': vulnerabilities,
        }

    def _display_scan_results(self, target: str):
        """Show results in a rich table"""
        table = Table(title=f"Scan Results for {target}")
        table.add_column("Vulnerability", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Confidence", style="yellow")

        # Example data
        table.add_row("SQL Injection", "High", "90%")
        table.add_row("XSS", "Medium", "75%")
        console.print(table)

    def _save_results(self, filename: str):
        """Save scan results to file"""
        with open(filename, 'wb') as f:
            pickle.dump(self.session_data['scan_results'], f)

    # ----- Module System -----
    def _load_modules(self) -> Dict[str, Any]:
        """Dynamically load available modules"""
        modules = {}
        for module_file in Path(MODULES_DIR).glob('*.py'):
            if module_file.stem == '__init__':
                continue
            try:
                module = importlib.import_module(f"{MODULES_DIR}.{module_file.stem}")
                modules[module_file.stem] = module
            except ImportError as e:
                console.print(f"[red]Failed to load module {module_file.stem}: {e}[/]")
        return modules

    use_parser = cmd2.Cmd2ArgumentParser()
    use_parser.add_argument('module', help="Module to use")

    @with_argparser(use_parser)
    def do_use(self, args):
        """Select a module to use"""
        if args.module in self.available_modules:
            self.current_module = args.module
            self.prompt = f"SecCQL ({args.module}) > "
            console.print(f"[green]Using module: {args.module}[/]")
            if hasattr(self.available_modules[args.module], 'setup'):
                self.available_modules[args.module].setup(self)
        else:
            console.print(f"[red]Module not found: {args.module}[/]")
            console.print("Available modules:")
            for mod in self.available_modules:
                console.print(f"  - {mod}")

    def do_back(self, _):
        """Exit the current module"""
        if self.current_module:
            if hasattr(self.available_modules[self.current_module], 'cleanup'):
                self.available_modules[self.current_module].cleanup(self)
            self.current_module = None
            self.prompt = "SecCQL > "
            console.print("[green]Returned to main console[/]")
        else:
            console.print("[yellow]Not currently in a module[/]")

    # ----- Session Management -----
    def do_sessions(self, _):
        """List active sessions"""
        table = Table(title="Active Sessions")
        table.add_column("ID")
        table.add_column("Target")
        table.add_column("Status")

        for target, data in self.session_data['scan_results'].items():
            table.add_row(str(hash(target)), target, data['status'])
        console.print(table)

    # ----- Other Commands -----
    def do_audit(self, _):
        """Perform an audit."""
        questions = [
            {
                "type": "list",
                "name": "audit_type",
                "message": "Select audit type:",
                "choices": ["API Security", "Cookie Security", "Content Security Policy (CSP)", "All"],
            },
        ]
        answers = prompt(questions)
        audit_type = answers["audit_type"]

        results = []
        if audit_type == "API Security":
            api_endpoints = [{"url": "/api/login", "requires_auth": False}]  # Example data
            results.extend(check_api_security(api_endpoints))
        elif audit_type == "Cookie Security":
            cookies = [{"name": "session", "secure": False, "httpOnly": True}]  # Example data
            results.extend(check_cookie_security(cookies))
        elif audit_type == "Content Security Policy (CSP)":
            headers = {"Content-Security-Policy": ""}  # Example data
            results.extend(check_csp(headers))
        elif audit_type == "All":
            # Run all checks
            results.extend(check_api_security([{"url": "/api/login", "requires_auth": False}]))
            results.extend(check_cookie_security([{"name": "session", "secure": False, "httpOnly": True}]))
            results.extend(check_csp({"Content-Security-Policy": ""}))

        # Generate a report
        reporter = ReportGenerator()
        reporter.generate_audit_report(results, "audit_report.html")
        console.print("[green]Audit completed. Report saved to audit_report.html[/]")

    def do_report(self, _):
        """Generate a report."""
        questions = [
            {
                "type": "input",
                "name": "report_name",
                "message": "Enter report name:",
            },
            {
                "type": "list",
                "name": "format",
                "message": "Select report format:",
                "choices": ["text", "json", "csv"],
            },
        ]
        answers = prompt(questions)
        report_name = answers["report_name"]
        report_format = answers["format"]

        console.print(f"[cyan]Generating {report_name} report in {report_format} format...[/]")

        # Use real scan results from session data
        vulnerabilities = []
        for target, results in self.session_data['scan_results'].items():
            vulnerabilities.extend(results.get('vulnerabilities', []))

        if not vulnerabilities:
            console.print("[yellow]⚠ No vulnerabilities found to include in the report.[/]")
            return

        generator = ReportGenerator()
        output_file = f"{report_name}.{report_format}"

        if report_format == "text":
            generator.generate_text_report(vulnerabilities, output_file)
        elif report_format == "json":
            generator.generate_json_report(vulnerabilities, output_file)
        elif report_format == "csv":
            generator.generate_csv_report(vulnerabilities, output_file)

        console.print(f"[green]Report generated: {output_file}[/]")

    def do_crawl(self, _):
        """Start the web crawler."""
        questions = [
            {
                "type": "input",
                "name": "start_url",
                "message": "Enter starting URL:",
            },
            {
                "type": "confirm",
                "name": "save_to_db",
                "message": "Save to database?",
                "default": True,
            },
        ]
        answers = prompt(questions)
        console.print(f"[cyan]Crawling from {answers['start_url']}...[/]")
        run_crawler(answers['start_url'], answers['save_to_db'])

    def _run_brute_force_test(self):
        """Perform brute force attack simulation."""
        questions = [
            {
                "type": "input",
                "name": "username",
                "message": "Enter username:",
            },
            {
                "type": "input",
                "name": "password",
                "message": "Enter password:",
            },
            {
                "type": "input",
                "name": "ip_address",
                "message": "Enter IP address:",
            },
        ]
        answers = prompt(questions)
        brute_force.simulate_login(
            username=answers["username"],
            password=answers["password"],
            attempt_tracker={},
            ip_address=answers["ip_address"]
        )

    def _run_rce_test(self):
        """Perform remote code execution simulation."""
        questions = [
            {
                "type": "input",
                "name": "command",
                "message": "Enter command to execute:",
            }
        ]
        answers = prompt(questions)
        result = rce.execute_command(answers["command"])
        if result:
            console.print(f"[green]Command executed successfully: {result}[/]")
        else:
            console.print("[red]Command execution failed or blocked[/]")

    def _run_business_logic_test(self):
        """Perform business logic vulnerability testing."""
        questions = [
            {
                "type": "list",
                "name": "user_role",
                "message": "Select user role:",
                "choices": ["admin", "user", "guest"],
            },
            {
                "type": "input",
                "name": "discount",
                "message": "Enter discount percentage:",
                "validate": lambda val: val.isdigit() and 0 <= int(val) <= 100 or "Discount must be between 0 and 100",
            },
        ]
        answers = prompt(questions)
        result = business_logic.test_discount_logic(
            user_role=answers["user_role"],
            discount=float(answers["discount"])
        )
        if result:
            console.print("[green]Business logic test passed[/]")
        else:
            console.print("[red]Business logic test failed[/]")

    def _run_file_upload_test(self):
        """Perform file upload security testing."""
        questions = [
            {
                "type": "input",
                "name": "file_path",
                "message": "Enter file path:",
            },
            {
                "type": "input",
                "name": "ip_address",
                "message": "Enter IP address:",
            },
        ]
        answers = prompt(questions)
        result = file_upload.process_file_upload(
            file_path=answers["file_path"],
            ip_address=answers["ip_address"]
        )
        if result["success"]:
            console.print(f"[green]File uploaded successfully. Checksum: {result['checksum']}[/]")
        else:
            console.print(f"[red]File upload failed: {result['message']}[/]")

    def _run_session_hijacking_test(self):
        """Perform session hijacking simulation."""
        questions = [
            {
                "type": "input",
                "name": "session_token",
                "message": "Enter session token:",
            },
        ]
        answers = prompt(questions)
        is_secure = session_hijacking.is_token_secure(answers["session_token"])
        if is_secure:
            console.print("[green]Session token is secure[/]")
        else:
            console.print("[red]Session token is not secure[/]")

    # ----- Auditor Commands -----
    def do_audit_ssl(self, args):
        """Check SSL/TLS configuration for a target."""
        questions = [
            {
                "type": "input",
                "name": "hostname",
                "message": "Enter hostname (e.g., example.com):",
            },
            {
                "type": "input",
                "name": "port",
                "message": "Enter port (default: 443):",
                "default": "443",
            },
        ]
        answers = prompt(questions)
        hostname = answers["hostname"]
        port = int(answers["port"])
        result = check_ssl(hostname, port)
        console.print(f"[cyan]SSL/TLS Check Results for {hostname}:{port}[/]")
        console.print(result)

    def do_audit_headers(self, args):
        """Analyze HTTP headers for security configurations."""
        questions = [
            {
                "type": "input",
                "name": "url",
                "message": "Enter target URL:",
            },
        ]
        answers = prompt(questions)
        url = answers["url"]
        result = analyze_headers(url)
        console.print(f"[cyan]HTTP Header Analysis Results for {url}[/]")
        console.print(result)

    def do_audit_gdpr(self, args):
        """Check GDPR compliance for a target."""
        questions = [
            {
                "type": "input",
                "name": "url",
                "message": "Enter target URL:",
            },
        ]
        answers = prompt(questions)
        url = answers["url"]
        result = check_gdpr_compliance(url)
        console.print(f"[cyan]GDPR Compliance Results for {url}[/]")
        console.print(result)

    def do_audit_error_handling(self, args):
        """Check for improper error handling in a web application."""
        questions = [
            {
                "type": "input",
                "name": "url",
                "message": "Enter target URL:",
            },
        ]
        answers = prompt(questions)
        url = answers["url"]
        result = check_error_handling(url)
        console.print(f"[cyan]Error Handling Check Results for {url}[/]")
        console.print(result)

    def do_audit_all(self, args):
        """Run all auditor checks on a target."""
        questions = [
            {
                "type": "input",
                "name": "url",
                "message": "Enter target URL:",
            },
            {
                "type": "input",
                "name": "hostname",
                "message": "Enter hostname (e.g., example.com):",
            },
            {
                "type": "input",
                "name": "port",
                "message": "Enter port (default: 443):",
                "default": "443",
            },
        ]
        answers = prompt(questions)
        url = answers["url"]
        hostname = answers["hostname"]
        port = int(answers["port"])

        console.print("[cyan]Running all auditor checks...[/]")

        ssl_result = check_ssl(hostname, port)
        console.print(f"[cyan]SSL/TLS Check Results for {hostname}:{port}[/]")
        console.print(ssl_result)

        header_result = analyze_headers(url)
        console.print(f"[cyan]HTTP Header Analysis Results for {url}[/]")
        console.print(header_result)

        gdpr_result = check_gdpr_compliance(url)
        console.print(f"[cyan]GDPR Compliance Results for {url}[/]")
        console.print(gdpr_result)

        error_handling_result = check_error_handling(url)
        console.print(f"[cyan]Error Handling Check Results for {url}[/]")
        console.print(error_handling_result)

    # ----- Utilities -----
    def do_clear(self, _):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def postcmd(self, stop: bool, line: str) -> bool:
        """Post-command processing"""
        return stop

    def precmd(self, line: str) -> str:
        """Pre-command processing"""
        return line

def main():
    """Entry point for the SecCQL interactive console."""
    app = SecCQLConsole()
    app.cmdloop()

if __name__ == "__main__":
    main()