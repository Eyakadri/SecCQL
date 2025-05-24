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
import importlib
import json
import threading
import validators
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

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

def is_valid_url(url: str) -> bool:
    return validators.url(url)

def is_valid_port(port_str: str) -> bool:
    if not port_str.isdigit():
        return False
    port = int(port_str)
    return 1 <= port <= 65535

def clear_screen():
    """Cross-platform clear screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def create_webdriver():
    """Create a headless Selenium WebDriver instance."""
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    try:
        driver = webdriver.Chrome(options=options)
        return driver
    except Exception as e:
        console.print(f"[red]Failed to initialize Selenium WebDriver: {e}[/]")
        return None

@with_default_category("Core Commands")
@with_category("CLI Commands")
class SecCQLConsole(cmd2.Cmd):
    """SecCQL Advanced Penetration Testing Console"""

    def __init__(self):
        self._create_config_dir()
        super().__init__(
            persistent_history_file=HISTORY_FILE,
            persistent_history_length=1000,
            startup_script=".seccqlrc",
            allow_cli_args=False
        )

        self.prompt = "SecCQL > "
        self.intro = self._get_banner()

        self.current_module = None
        self.available_modules = self._load_modules()

        self.session_data = {
            'targets': [],
            'scan_results': {},
            'credentials': {}
        }

        self.webdriver = create_webdriver()

    def _create_config_dir(self):
        Path(CONFIG_DIR).mkdir(exist_ok=True)

    def _get_banner(self):
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
                    "validate": lambda val: is_valid_url(val) or "Invalid URL format"
                }
            ]
            answers = prompt(questions)
            scan_type = answers['scan_type']
            url = answers['url']

            try:
                console.print(f"[cyan]🚀 Running {scan_type} scan on {url}...[/]")

                # Run scan in a thread to keep UI responsive
                thread = threading.Thread(target=self._run_interactive_scan, args=(scan_type, url))
                thread.start()
                thread.join()

            except KeyboardInterrupt:
                console.print("[yellow]⚠ Scan cancelled by user[/]")
                return False
            except Exception as e:
                console.print(f"[red]❌ Scan failed: {e}[/]")
                return False
        else:
            # CLI mode
            if not is_valid_url(args.target):
                console.print("[red]Invalid target URL provided.[/]")
                return False

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
                try:
                    self._save_results(args.output)
                    console.print(f"[green]✓ Results saved to {args.output}[/]")
                except Exception as e:
                    console.print(f"[red]Failed to save results: {e}[/]")
            else:
                self._display_scan_results(args.target)
            return True

    def _run_interactive_scan(self, scan_type: str, url: str):
        """Run interactive scan with proper WebDriver and error handling."""
        result = None
        try:
            if scan_type == "SQL Injection":
                scanner = SQLInjectionScanner(driver=self.webdriver)
                form = {
                    "action": url,
                    "method": "post",
                    "inputs": [{"name": "username"}, {"name": "password"}],
                }
                result = scanner.test_sql_injection(form, url)
            elif scan_type == "XSS":
                scanner = XSSScanner(driver=self.webdriver)
                result = scanner.test_xss({"action": url, "inputs": []}, url)
            elif scan_type == "CSRF":
                scanner = CSRFScanner(driver=self.webdriver)
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
                return
            elif scan_type == "Remote Code Execution (RCE)":
                self._run_rce_test()
                return
            elif scan_type == "Business Logic":
                self._run_business_logic_test()
                return
            elif scan_type == "File Upload":
                self._run_file_upload_test()
                return
            elif scan_type == "Session Hijacking":
                self._run_session_hijacking_test()
                return
            else:
                console.print("[red]❌ Unknown scan type selected[/]")
                return

            if result:
                console.print(f"[green]✅ {scan_type} scan completed successfully! Vulnerability detected.[/]")
            else:
                console.print(f"[yellow]⚠ {scan_type} scan completed. No vulnerabilities detected.[/]")
        except Exception as e:
            console.print(f"[red]Error during {scan_type} scan: {e}[/")

    def _run_scan_module(self, target: str, profile: str):
        """Execute the appropriate scanner module"""
        console.print(f"[yellow]Running {profile} scan on {target}[/]")

        # Placeholder for real scan logic; simulate results
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
        results = self.session_data['scan_results'].get(target)
        if not results or 'vulnerabilities' not in results:
            console.print(f"[yellow]No scan results found for {target}[/]")
            return

        table = Table(title=f"Scan Results for {target}")
        table.add_column("Vulnerability", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Recommendation", style="green")

        for vuln in results['vulnerabilities']:
            table.add_row(vuln.get("type", "N/A"), vuln.get("severity", "N/A"), vuln.get("recommendation", "N/A"))

        console.print(table)

    def _save_results(self, filename: str):
        """Save scan results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.session_data['scan_results'], f, indent=2)
        except Exception as e:
            console.print(f"[red]Failed to save results: {e}[/]")

    def _load_modules(self) -> Dict[str, Any]:
        """Dynamically load available modules"""
        modules = {}
        modules_path = Path(MODULES_DIR)
        if not modules_path.exists() or not modules_path.is_dir():
            console.print(f"[yellow]Modules directory '{MODULES_DIR}' not found. Skipping module loading.[/]")
            return modules

        for module_file in modules_path.glob('*.py'):
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
            mod = self.available_modules[args.module]
            if hasattr(mod, 'setup') and callable(mod.setup):
                try:
                    mod.setup(self)
                except Exception as e:
                    console.print(f"[red]Error during module setup: {e}[/]")
        else:
            console.print(f"[red]Module not found: {args.module}[/]")
            console.print("Available modules:")
            for mod in self.available_modules:
                console.print(f"  - {mod}")

    def do_back(self, _):
        """Exit the current module"""
        if self.current_module:
            mod = self.available_modules.get(self.current_module)
            if mod and hasattr(mod, 'cleanup') and callable(mod.cleanup):
                try:
                    mod.cleanup(self)
                except Exception as e:
                    console.print(f"[red]Error during module cleanup: {e}[/]")
            self.current_module = None
            self.prompt = "SecCQL > "
            console.print("[green]Returned to main console[/]")
        else:
            console.print("[yellow]Not currently in a module[/]")

    def do_sessions(self, _):
        """List active sessions"""
        table = Table(title="Active Sessions")
        table.add_column("ID")
        table.add_column("Target")
        table.add_column("Status")

        for target, data in self.session_data['scan_results'].items():
            table.add_row(str(hash(target)), target, data.get('status', 'unknown'))
        console.print(table)

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
            api_endpoints = [{"url": "/api/login", "requires_auth": False}]
            results.extend(check_api_security(api_endpoints))
        elif audit_type == "Cookie Security":
            cookies = [{"name": "session", "secure": False, "httpOnly": True}]
            results.extend(check_cookie_security(cookies))
        elif audit_type == "Content Security Policy (CSP)":
            headers = {"Content-Security-Policy": ""}
            results.extend(check_csp(headers))
        elif audit_type == "All":
            results.extend(check_api_security([{"url": "/api/login", "requires_auth": False}]))
            results.extend(check_cookie_security([{"name": "session", "secure": False, "httpOnly": True}]))
            results.extend(check_csp({"Content-Security-Policy": ""}))

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

        vulnerabilities = []
        for target, results in self.session_data['scan_results'].items():
            vulnerabilities.extend(results.get('vulnerabilities', []))

        if not vulnerabilities:
            console.print("[yellow]⚠ No vulnerabilities found to include in the report.[/]")
            return

        generator = ReportGenerator()
        output_file = f"{report_name}.{report_format}"

        try:
            if report_format == "text":
                generator.generate_text_report(vulnerabilities, output_file)
            elif report_format == "json":
                generator.generate_json_report(vulnerabilities, output_file)
            elif report_format == "csv":
                generator.generate_csv_report(vulnerabilities, output_file)
            console.print(f"[green]Report generated: {output_file}[/]")
        except Exception as e:
            console.print(f"[red]Failed to generate report: {e}[/]")

    def do_crawl(self, _):
        """Start the web crawler."""
        questions = [
            {
                "type": "input",
                "name": "start_url",
                "message": "Enter starting URL:",
                "validate": lambda val: is_valid_url(val) or "Invalid URL format"
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
        try:
            run_crawler(answers['start_url'], answers['save_to_db'])
        except Exception as e:
            console.print(f"[red]Crawler error: {e}[/]")

    def _run_brute_force_test(self):
        questions = [
            {"type": "input", "name": "username", "message": "Enter username:"},
            {"type": "input", "name": "password", "message": "Enter password:"},
            {"type": "input", "name": "ip_address", "message": "Enter IP address:"},
        ]
        answers = prompt(questions)
        try:
            brute_force.simulate_login(
                username=answers["username"],
                password=answers["password"],
                attempt_tracker={},
                ip_address=answers["ip_address"]
            )
            console.print("[green]Brute force simulation completed.[/]")
        except Exception as e:
            console.print(f"[red]Brute force simulation failed: {e}[/]")

    def _run_rce_test(self):
        questions = [{"type": "input", "name": "command", "message": "Enter command to execute:"}]
        answers = prompt(questions)
        try:
            result = rce.execute_command(answers["command"])
            if result:
                console.print(f"[green]Command executed successfully: {result}[/]")
            else:
                console.print("[red]Command execution failed or blocked[/]")
        except Exception as e:
            console.print(f"[red]RCE test failed: {e}[/]")

    def _run_business_logic_test(self):
        try:
            business_logic.run_business_logic_tests()
            console.print("[green]Business logic tests completed.[/]")
        except Exception as e:
            console.print(f"[red]Business logic tests failed: {e}[/]")

    def _run_file_upload_test(self):
        questions = [{"type": "input", "name": "file_path", "message": "Enter file path to upload:"}]
        answers = prompt(questions)
        try:
            file_upload.test_file_upload(answers["file_path"])
            console.print("[green]File upload test completed.[/]")
        except Exception as e:
            console.print(f"[red]File upload test failed: {e}[/]")

    def _run_session_hijacking_test(self):
        try:
            session_hijacking.test_session_hijacking()
            console.print("[green]Session hijacking test completed.[/]")
        except Exception as e:
            console.print(f"[red]Session hijacking test failed: {e}[/]")

    clear_parser = cmd2.Cmd2ArgumentParser()
    clear_parser.add_argument('target', nargs='?', help="Target to clear session data for (optional)")

    @with_argparser(clear_parser)
    def do_clear(self, args):
        """Clear session data or screen."""
        if args.target:
            if args.target in self.session_data['scan_results']:
                del self.session_data['scan_results'][args.target]
                console.print(f"[green]Cleared session data for {args.target}[/]")
            else:
                console.print(f"[yellow]No session data found for {args.target}[/]")
        else:
            clear_screen()
            console.print("[green]Screen cleared.[/]")

    def do_exit(self, _):
        """Exit the console."""
        if self.webdriver:
            try:
                self.webdriver.quit()
            except Exception:
                pass
        console.print("[cyan]Goodbye![/]")
        return True

def main():
    SecCQLConsole().cmdloop()

if __name__ == "__main__":
    main()