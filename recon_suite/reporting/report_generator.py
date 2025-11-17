"""Report generation in multiple formats (HTML, JSON, PDF, CSV)."""

import json
import csv
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import logging

from ..core.scanner_base import ScanResult


class ReportGenerator:
    """Multi-format report generator."""

    def __init__(self, config):
        """Initialize report generator."""
        self.config = config
        self.logger = logging.getLogger("ReportGenerator")

    def generate(self, scan_result: ScanResult, output_format: str = 'html',
                 output_file: Optional[str] = None) -> str:
        """
        Generate report in specified format.

        Args:
            scan_result: Scan results to report
            output_format: Output format (html, json, pdf, csv)
            output_file: Output file path

        Returns:
            Report content or file path
        """
        # Auto-generate output filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"report_{timestamp}.{output_format}"

        # Generate based on format
        if output_format == 'html':
            return self.generate_html(scan_result, output_file)
        elif output_format == 'json':
            return self.generate_json(scan_result, output_file)
        elif output_format == 'pdf':
            return self.generate_pdf(scan_result, output_file)
        elif output_format == 'csv':
            return self.generate_csv(scan_result, output_file)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def generate_html(self, scan_result: ScanResult, output_file: str) -> str:
        """Generate HTML report."""
        from jinja2 import Template

        # HTML template
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Reconnaissance Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 30px; text-align: center; border-radius: 5px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .severity-critical { background-color: #e74c3c; color: white; padding: 5px 10px; border-radius: 3px; }
        .severity-high { background-color: #e67e22; color: white; padding: 5px 10px; border-radius: 3px; }
        .severity-medium { background-color: #f39c12; color: white; padding: 5px 10px; border-radius: 3px; }
        .severity-low { background-color: #3498db; color: white; padding: 5px 10px; border-radius: 3px; }
        .summary-box { display: inline-block; background: #ecf0f1; padding: 15px 25px; margin: 10px; border-radius: 5px; }
        .summary-box h3 { color: #2c3e50; font-size: 32px; margin-bottom: 5px; }
        .summary-box p { color: #7f8c8d; }
        .footer { text-align: center; padding: 20px; color: #7f8c8d; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Reconnaissance Report</h1>
            <p>Target: <strong>{{ target }}</strong></p>
            <p>Scan Type: {{ scan_type }} | Date: {{ timestamp }}</p>
        </div>

        <!-- Executive Summary -->
        <div class="card">
            <h2>📊 Executive Summary</h2>
            <div style="text-align: center;">
                <div class="summary-box">
                    <h3>{{ stats.total_hosts }}</h3>
                    <p>Hosts Discovered</p>
                </div>
                <div class="summary-box">
                    <h3>{{ stats.total_ports }}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="summary-box">
                    <h3>{{ stats.total_services }}</h3>
                    <p>Services Detected</p>
                </div>
                <div class="summary-box">
                    <h3>{{ stats.total_vulnerabilities }}</h3>
                    <p>Vulnerabilities Found</p>
                </div>
            </div>
        </div>

        <!-- Hosts -->
        {% if hosts %}
        <div class="card">
            <h2>💻 Discovered Hosts</h2>
            <table>
                <tr>
                    <th>Host</th>
                    <th>Hostname</th>
                    <th>State</th>
                    <th>Open Ports</th>
                </tr>
                {% for host in hosts %}
                <tr>
                    <td>{{ host.host or host.get('ip', 'N/A') }}</td>
                    <td>{{ host.hostname or 'N/A' }}</td>
                    <td>{{ host.state or 'unknown' }}</td>
                    <td>{{ host.ports | length if host.ports else 0 }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        <!-- Services -->
        {% if services %}
        <div class="card">
            <h2>🔌 Detected Services</h2>
            <table>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Banner</th>
                </tr>
                {% for service in services %}
                <tr>
                    <td>{{ service.host }}</td>
                    <td>{{ service.port }}</td>
                    <td>{{ service.service }}</td>
                    <td>{{ service.version or 'N/A' }}</td>
                    <td>{{ service.banner[:50] if service.banner else 'N/A' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        <!-- Technologies -->
        {% if technologies %}
        <div class="card">
            <h2>🛠️ Detected Technologies</h2>
            <table>
                <tr>
                    <th>Technology</th>
                    <th>Version</th>
                    <th>Category</th>
                    <th>Confidence</th>
                </tr>
                {% for tech in technologies %}
                <tr>
                    <td>{{ tech.name }}</td>
                    <td>{{ tech.version or 'N/A' }}</td>
                    <td>{{ tech.category or 'N/A' }}</td>
                    <td>{{ tech.confidence or 'medium' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        <!-- Vulnerabilities -->
        {% if vulnerabilities %}
        <div class="card">
            <h2>⚠️ Vulnerabilities</h2>
            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>Service</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>CVSS Score</th>
                </tr>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td>{{ vuln.cve_id or 'N/A' }}</td>
                    <td>{{ vuln.service }}</td>
                    <td><span class="severity-{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></td>
                    <td>{{ vuln.description[:100] }}...</td>
                    <td>{{ vuln.cvss_score or 'N/A' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        <div class="footer">
            <p>Generated by Network Reconnaissance Suite v1.0</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
        """

        # Prepare data
        template_data = {
            'target': scan_result.target,
            'scan_type': scan_result.scan_type,
            'timestamp': scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'hosts': scan_result.hosts,
            'services': scan_result.services,
            'technologies': scan_result.technologies,
            'vulnerabilities': scan_result.vulnerabilities,
            'stats': scan_result.metadata.get('statistics', {}),
        }

        # Render template
        template = Template(template_str)
        html_content = template.render(**template_data)

        # Write to file
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(html_content)

        self.logger.info(f"HTML report generated: {output_file}")
        return output_file

    def generate_json(self, scan_result: ScanResult, output_file: str) -> str:
        """Generate JSON report."""
        # Convert scan result to dictionary
        report_data = scan_result.to_dict()

        # Write to file
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        self.logger.info(f"JSON report generated: {output_file}")
        return output_file

    def generate_pdf(self, scan_result: ScanResult, output_file: str) -> str:
        """Generate PDF report."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib import colors

            # Create PDF
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            doc = SimpleDocTemplate(output_file, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2c3e50'),
                spaceAfter=30,
            )
            story.append(Paragraph("Network Reconnaissance Report", title_style))
            story.append(Spacer(1, 0.2 * inch))

            # Metadata
            story.append(Paragraph(f"<b>Target:</b> {scan_result.target}", styles['Normal']))
            story.append(Paragraph(f"<b>Scan Type:</b> {scan_result.scan_type}", styles['Normal']))
            story.append(Paragraph(f"<b>Date:</b> {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 0.3 * inch))

            # Statistics
            stats = scan_result.metadata.get('statistics', {})
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            summary_data = [
                ['Metric', 'Count'],
                ['Hosts Discovered', str(stats.get('total_hosts', 0))],
                ['Open Ports', str(stats.get('total_ports', 0))],
                ['Services Detected', str(stats.get('total_services', 0))],
                ['Vulnerabilities Found', str(stats.get('total_vulnerabilities', 0))],
            ]
            summary_table = Table(summary_data)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.3 * inch))

            # Vulnerabilities
            if scan_result.vulnerabilities:
                story.append(Paragraph("Vulnerabilities", styles['Heading2']))
                vuln_data = [['CVE ID', 'Severity', 'Service', 'CVSS']]
                for vuln in scan_result.vulnerabilities[:20]:  # Limit to 20
                    vuln_data.append([
                        vuln.get('cve_id', 'N/A'),
                        vuln.get('severity', 'N/A'),
                        vuln.get('service', 'N/A'),
                        str(vuln.get('cvss_score', 'N/A')),
                    ])
                vuln_table = Table(vuln_data)
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                story.append(vuln_table)

            # Build PDF
            doc.build(story)
            self.logger.info(f"PDF report generated: {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            # Fallback to HTML
            html_file = output_file.replace('.pdf', '.html')
            self.logger.info("Falling back to HTML report")
            return self.generate_html(scan_result, html_file)

    def generate_csv(self, scan_result: ScanResult, output_file: str) -> str:
        """Generate CSV report."""
        # Create CSV with vulnerabilities
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # Write metadata
            writer.writerow(['Network Reconnaissance Report'])
            writer.writerow(['Target', scan_result.target])
            writer.writerow(['Scan Type', scan_result.scan_type])
            writer.writerow(['Timestamp', scan_result.timestamp.isoformat()])
            writer.writerow([])

            # Write services
            writer.writerow(['Services'])
            writer.writerow(['Host', 'Port', 'Service', 'Version', 'Banner'])
            for service in scan_result.services:
                writer.writerow([
                    service.get('host', ''),
                    service.get('port', ''),
                    service.get('service', ''),
                    service.get('version', ''),
                    service.get('banner', '')[:100],
                ])
            writer.writerow([])

            # Write vulnerabilities
            writer.writerow(['Vulnerabilities'])
            writer.writerow(['CVE ID', 'Severity', 'Service', 'CVSS Score', 'Description'])
            for vuln in scan_result.vulnerabilities:
                writer.writerow([
                    vuln.get('cve_id', ''),
                    vuln.get('severity', ''),
                    vuln.get('service', ''),
                    vuln.get('cvss_score', ''),
                    vuln.get('description', '')[:200],
                ])

        self.logger.info(f"CSV report generated: {output_file}")
        return output_file
