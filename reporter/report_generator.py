import logging
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from matplotlib import pyplot as plt
from jinja2 import Template

class ReportGenerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    def generate_text_report(self, vulnerabilities: List[Dict[str, Any]], output_file: str) -> None:
        """Generate a plain text report"""
        try:
            with open(output_file, "w", encoding='utf-8') as f:
                for vuln in vulnerabilities:
                    f.write(f"Type: {vuln.get('type', 'N/A')}\n")
                    f.write(f"Severity: {vuln.get('severity', 'Medium')}\n")
                    f.write(f"Location: {vuln.get('location', 'N/A')}\n")
                    f.write(f"Description: {vuln.get('description', '')}\n")
                    f.write(f"Recommendation: {vuln.get('recommendation', '')}\n")
                    f.write("-" * 40 + "\n")
            self.logger.info(f"Text report generated: {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate text report: {str(e)}")
            raise

    def generate_json_report(self, data: Dict[str, Any], output_file: str) -> None:
        """Generate a JSON report"""
        try:
            with open(output_file, "w", encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"JSON report generated: {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {str(e)}")
            raise

    def generate_csv_report(self, vulnerabilities: List[Dict[str, Any]], output_file: str) -> None:
        """Generate a CSV report with dynamic field handling"""
        try:
            # Get all field names from data plus standard fields
            fieldnames = set()
            for vuln in vulnerabilities:
                fieldnames.update(vuln.keys())
            standard_fields = ['type', 'severity', 'location', 'description', 'recommendation']
            fieldnames = sorted(fieldnames.union(standard_fields))
            
            with open(output_file, "w", newline="", encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for vuln in vulnerabilities:
                    # Ensure all fields are present with empty string as default
                    row = {field: vuln.get(field, '') for field in fieldnames}
                    writer.writerow(row)
            self.logger.info(f"CSV report generated: {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {str(e)}")
            raise

    def generate_chart(self, vulnerabilities: List[Dict[str, Any]], output_path: str) -> None:
        """Generate a severity distribution chart"""
        try:
            severities = [v.get('severity', 'Unknown') for v in vulnerabilities]
            severity_counts = {severity: severities.count(severity) for severity in set(severities)}
            
            plt.figure(figsize=(10, 6))
            colors = {
                'Critical': 'red',
                'High': 'orange',
                'Medium': 'yellow',
                'Low': 'green',
                'Unknown': 'gray'
            }
            plt.bar(
                severity_counts.keys(),
                severity_counts.values(),
                color=[colors.get(s, 'gray') for s in severity_counts.keys()]
            )
            plt.title("Vulnerabilities by Severity")
            plt.xlabel("Severity Level")
            plt.ylabel("Count")
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()
            self.logger.info(f"Chart generated: {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to generate chart: {str(e)}")
            raise

    def generate_audit_report(self, audit_results: List[Dict[str, Any]], output_file: str) -> None:
        """
        Generate comprehensive audit reports in multiple formats
        Args:
            audit_results: List of audit findings
            output_file: Base path for output files (extensions will be added)
        """
        try:
            # Ensure output directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Standardize report data structure
            standardized_results = []
            for result in audit_results:
                standardized = {
                    'type': result.get('type', result.get('finding', 'Unknown')),
                    'severity': result.get('severity', 'Medium'),
                    'location': result.get('location', result.get('details', 'N/A')),
                    'description': result.get('description', ''),
                    'recommendation': result.get('recommendation', 'Investigate further')
                }
                # Preserve any additional fields
                for k, v in result.items():
                    if k not in standardized:
                        standardized[k] = v
                standardized_results.append(standardized)

            report_data = {
                "metadata": {
                    "report_type": "security_audit",
                    "generated_at": datetime.now().isoformat(),
                    "total_findings": len(standardized_results)
                },
                "findings": standardized_results
            }

            # Generate all report formats
            base_path = str(output_path.with_suffix(''))
            success = True
            
            try:
                self._generate_html_report(report_data, f"{base_path}.html")
            except Exception as e:
                self.logger.error(f"HTML report failed: {str(e)}")
                success = False
                
            try:
                self.generate_csv_report(standardized_results, f"{base_path}.csv")
            except Exception as e:
                self.logger.error(f"CSV report failed: {str(e)}")
                success = False
                
            try:
                self.generate_json_report(report_data, f"{base_path}.json")
            except Exception as e:
                self.logger.error(f"JSON report failed: {str(e)}")
                success = False
                
            try:
                self.generate_chart(standardized_results, f"{base_path}_chart.png")
            except Exception as e:
                self.logger.error(f"Chart generation failed: {str(e)}")
                success = False

            if not success:
                raise ValueError("Some report formats failed to generate (check logs)")
                
            self.logger.info(f"Audit reports successfully generated with base: {base_path}")

        except Exception as e:
            self.logger.error(f"Critical failure in audit report generation: {str(e)}")
            raise

    def _generate_html_report(self, data: Dict[str, Any], output_file: str) -> None:
        """Generate HTML version of the report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Audit Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 2em; }
                .critical { color: #d9534f; font-weight: bold; }
                .high { color: #f0ad4e; }
                .medium { color: #5bc0de; }
                .low { color: #5cb85c; }
                .unknown { color: #777; }
                table { border-collapse: collapse; width: 100%; margin-top: 1em; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f8f9fa; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .header { display: flex; justify-content: space-between; }
                .summary-card {
                    background: #f8f9fa;
                    padding: 1em;
                    border-radius: 5px;
                    margin-bottom: 1em;
                }
                .severity-counts {
                    display: flex;
                    gap: 1em;
                    margin: 1em 0;
                }
                .severity-badge {
                    padding: 0.5em 1em;
                    border-radius: 20px;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Audit Report</h1>
                <div class="summary-card">
                    <strong>Generated:</strong> {{ metadata.generated_at }}<br>
                    <strong>Total Findings:</strong> {{ metadata.total_findings }}
                </div>
            </div>
            
            <div class="severity-counts">
                {% for sev, count in severity_counts.items() %}
                <div class="severity-badge {{ sev|lower }}" 
                     style="background-color: {{ severity_colors[sev] }};">
                    {{ sev }}: {{ count }}
                </div>
                {% endfor %}
            </div>
            
            <table>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Location</th>
                    <th>Description</th>
                    <th>Recommendation</th>
                </tr>
                {% for finding in findings %}
                <tr>
                    <td>{{ finding.type }}</td>
                    <td class="{{ finding.severity|lower }}">{{ finding.severity }}</td>
                    <td>{{ finding.location }}</td>
                    <td>{{ finding.description }}</td>
                    <td>{{ finding.recommendation }}</td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        
        try:
            # Calculate severity counts for the summary
            severity_counts = {}
            severity_colors = {
                'Critical': '#d9534f',
                'High': '#f0ad4e',
                'Medium': '#5bc0de',
                'Low': '#5cb85c',
                'Unknown': '#777777'
            }
            for finding in data['findings']:
                sev = finding.get('severity', 'Unknown')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(Template(html_template).render(
                    **data,
                    severity_counts=severity_counts,
                    severity_colors=severity_colors
                ))
            self.logger.info(f"HTML report generated: {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise