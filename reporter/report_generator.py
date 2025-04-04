from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader("reporter/templates"))

    def generate_pdf(self, vulnerabilities, output_path):
        template = self.env.get_template("vulnerability_report.html")
        html = template.render(vulnerabilities=vulnerabilities)
        HTML(string=html).write_pdf(output_path)