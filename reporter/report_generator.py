from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import matplotlib.pyplot as plt
import json

class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader("reporter/templates"))

    def generate_pdf(self, vulnerabilities, output_path):
        template = self.env.get_template("vulnerability_report.html")
        html = template.render(vulnerabilities=vulnerabilities)
        HTML(string=html).write_pdf(output_path)

    def generate_chart(self, vulnerabilities, output_path):
        """
        Generate a chart showing vulnerabilities by severity.

        Args:
            vulnerabilities (list): List of vulnerability dictionaries.
            output_path (str): Path to save the chart image.
        """
        severities = [v["severity"] for v in vulnerabilities]
        severity_counts = {severity: severities.count(severity) for severity in set(severities)}

        plt.bar(severity_counts.keys(), severity_counts.values(), color='skyblue')
        plt.title("Vulnerabilities by Severity")
        plt.xlabel("Severity")
        plt.ylabel("Count")
        plt.savefig(output_path)
        plt.close()

    def generate_html(self, vulnerabilities, output_path):
        """
        Generate an HTML report.

        Args:
            vulnerabilities (list): List of vulnerability dictionaries.
            output_path (str): Path to save the HTML report.
        """
        template = self.env.get_template("vulnerability_report.html")
        html = template.render(vulnerabilities=vulnerabilities, generated_on="Today")
        with open(output_path, "w") as f:
            f.write(html)

    def generate_json(self, vulnerabilities, output_path):
        """
        Generate a JSON report.

        Args:
            vulnerabilities (list): List of vulnerability dictionaries.
            output_path (str): Path to save the JSON report.
        """
        with open(output_path, "w") as f:
            json.dump(vulnerabilities, f, indent=4)