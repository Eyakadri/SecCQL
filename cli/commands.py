import click
from InquirerPy import prompt
from auditor import core as auditor_core
from scanner import brute_force, utils as scanner_utils
from reporter import report_generator
# Fix the import for the crawler module
from crawler.crawler import run_crawler
from scanner import rce
from rich.console import Console
from rich.table import Table
from reporter.report_generator import ReportGenerator

console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """SecCQL CLI - A Security Testing Framework"""
    if not ctx.invoked_subcommand:
        # Display a banner
        console.print("""
[bold cyan]
███████╗███████╗ ██████╗ ██████╗ ██████╗ ██╗
██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██║
███████╗█████╗  ██║     ██║     ██║   ██║██║
╚════██║██╔══╝  ██║     ██║     ██║▄▄ ██║██║
███████║███████╗╚██████╗╚██████╗╚██████╔╝███████╗
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚══▀▀═╝ ╚══════╝

SecCQL - Advanced Security Testing Framework
[/bold cyan]
""")

        # Display available commands in a table
        table = Table(
            title="Available Commands",
            show_header=True,
            header_style="bold magenta")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="green")

        for command, cmd_obj in cli.commands.items():
            table.add_row(command, cmd_obj.help)

        console.print(table)
        console.print(
            "\n[bold yellow]Usage:[/bold yellow] SecCQL <command> [options]\n")


@cli.command()
@click.argument("url")
def scan(url):
    """Run a security scan on the provided URL."""
    try:
        questions = [
            {
                "type": "list",
                "name": "scan_type",
                "message": "Select the type of scan to perform:",
                "choices": [
                    "SQL Injection", "XSS", "CSRF", "Command Injection", "SSRF", "IDOR",
                    "Brute Force", "Remote Code Execution (RCE)", "Business Logic", "File Upload", "Session Hijacking"
                ],
            }
        ]
        answers = prompt(questions)
        scan_type = answers["scan_type"]
        console.print(f"[cyan]Running {scan_type} scan on {url}...[/]")
        scanner_utils.run_scan(scan_type, url)
    except ValueError as e:
        console.print(f"[red]Error during scan: {e}[/]")
    except Exception as e:
        console.print(f"[red]Unexpected error during scan: {e}[/]")


@cli.command()
def audit():
    """Perform an audit."""
    questions = [
        {
            "type": "list",
            "name": "audit_type",
            "message": "Select the type of audit to perform:",
            "choices": ["GDPR Compliance", "HTTP Headers", "SSL/TLS"],
        }
    ]
    answers = prompt(questions)
    audit_type = answers["audit_type"]
    click.echo(f"Performing {audit_type} audit...")
    auditor_core.run_audit(audit_type)


@cli.command()
@click.argument("format", type=click.Choice(["text", "json", "csv"], case_sensitive=False))
@click.argument("output_file")
def report(format, output_file):
    """Generate a vulnerability report in the specified format."""
    vulnerabilities = [
        {"type": "XSS", "description": "Cross-site scripting detected.", "severity": "High", "recommendation": "Sanitize inputs."},
        {"type": "SQL Injection", "description": "SQLi vulnerability found.", "severity": "Critical", "recommendation": "Use parameterized queries."},
    ]

    generator = ReportGenerator()
    if format == "text":
        generator.generate_text_report(vulnerabilities, output_file)
    elif format == "json":
        generator.generate_json_report(vulnerabilities, output_file)
    elif format == "csv":
        generator.generate_csv_report(vulnerabilities, output_file)

    console.print(f"Report generated: {output_file}")


@cli.command()
def crawl():
    """Start the web crawler."""
    try:
        questions = [
            {
                "type": "input",
                "name": "start_url",
                "message": "Enter the starting URL for the crawler:",
            },
            {
                "type": "confirm",
                "name": "save_to_db",
                "message": "Save crawled data to the database?",
                "default": True,
            },
        ]
        answers = prompt(questions)
        start_url = answers["start_url"]
        save_to_db = answers["save_to_db"]
        console.print(f"[cyan]Starting crawler at {start_url}...[/]")
        run_crawler(start_url, save_to_db)
    except Exception as e:
        console.print(f"[red]Error during crawling: {e}[/]")


if __name__ == "__main__":
    cli()
