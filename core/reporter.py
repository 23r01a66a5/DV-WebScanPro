"""
Report Generator for DV-WebScanPro
Creates comprehensive HTML reports of all vulnerabilities found
"""

from datetime import datetime
from utils.helpers import ensure_dir, print_info, print_success
import json
import os

class ReportGenerator:
    """Generates HTML security reports"""
    
    def __init__(self, target_url, scan_id):
        self.target_url = target_url
        self.scan_id = scan_id
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.vulnerabilities = []
        
    def add_vulnerabilities(self, vuln_list):
        """Add vulnerabilities to the report"""
        self.vulnerabilities.extend(vuln_list)
    
    def count_by_risk(self):
        """Count vulnerabilities by risk level"""
        counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.vulnerabilities:
            risk = vuln.get('risk', 'Low')
            if risk in counts:
                counts[risk] += 1
        return counts
    
    def count_by_type(self):
        """Count vulnerabilities by type"""
        types = {}
        for vuln in self.vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            types[vtype] = types.get(vtype, 0) + 1
        return types
    
    def generate_html(self):
        """Generate HTML report"""
        risk_counts = self.count_by_risk()
        type_counts = self.count_by_type()
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DV-WebScanPro Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 15px;
            color: #555;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 10px;
        }}
        .stat {{
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
            padding: 10px;
            border-radius: 5px;
        }}
        .stat.high {{ background-color: #fee; }}
        .stat.medium {{ background-color: #fff3e0; }}
        .stat.low {{ background-color: #e8f5e8; }}
        .risk-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            color: white;
        }}
        .risk-high {{ background-color: #dc3545; }}
        .risk-medium {{ background-color: #ffc107; color: #333; }}
        .risk-low {{ background-color: #28a745; }}
        .vulnerability {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 5px solid #ddd;
        }}
        .vulnerability.high {{ border-left-color: #dc3545; }}
        .vulnerability.medium {{ border-left-color: #ffc107; }}
        .vulnerability.low {{ border-left-color: #28a745; }}
        .vuln-title {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .vuln-title h3 {{
            margin: 0;
            color: #333;
        }}
        .vuln-detail {{
            margin: 10px 0;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }}
        .vuln-detail strong {{
            color: #555;
            display: inline-block;
            width: 120px;
        }}
        .remediation {{
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }}
        .remediation h4 {{
            margin: 0 0 10px;
            color: #1976d2;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #777;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DV-WebScanPro Security Report</h1>
        <p>Target: {self.target_url}</p>
        <p>Scan ID: {self.scan_id}</p>
        <p>Date: {self.timestamp}</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Risk Summary</h3>
            <div class="stat high">
                <span>High Risk:</span>
                <strong>{risk_counts['High']}</strong>
            </div>
            <div class="stat medium">
                <span>Medium Risk:</span>
                <strong>{risk_counts['Medium']}</strong>
            </div>
            <div class="stat low">
                <span>Low Risk:</span>
                <strong>{risk_counts['Low']}</strong>
            </div>
            <div class="stat" style="background-color: #e9ecef;">
                <span>Total:</span>
                <strong>{len(self.vulnerabilities)}</strong>
            </div>
        </div>

        <div class="summary-card">
            <h3>Vulnerability Types</h3>
"""
        
        for vtype, count in type_counts.items():
            html += f"""
            <div class="stat">
                <span>{vtype}:</span>
                <strong>{count}</strong>
            </div>
"""
        
        html += """
        </div>
    </div>

    <h2>Detailed Findings</h2>
"""
        
        if not self.vulnerabilities:
            html += """
    <div class="summary-card" style="text-align: center; padding: 40px;">
        <h3>✅ No Vulnerabilities Found</h3>
        <p>The target appears to be secure against the tested vectors.</p>
    </div>
"""
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                risk = vuln.get('risk', 'Low').lower()
                risk_class = vuln.get('risk', 'Low').lower()
                html += f"""
    <div class="vulnerability {risk_class}">
        <div class="vuln-title">
            <h3>{i}. {vuln.get('type', 'Unknown Vulnerability')}</h3>
            <span class="risk-badge risk-{risk_class}">{vuln.get('risk', 'Low')}</span>
        </div>
        
        <div class="vuln-detail">
            <strong>URL:</strong> {vuln.get('url', 'N/A')}<br>
"""
                if 'parameter' in vuln:
                    html += f'            <strong>Parameter:</strong> {vuln.get("parameter", "N/A")}<br>\n'
                if 'input_name' in vuln:
                    html += f'            <strong>Input:</strong> {vuln.get("input_name", "N/A")}<br>\n'
                if 'payload' in vuln:
                    html += f'            <strong>Payload:</strong> <code>{vuln.get("payload", "N/A")}</code><br>\n'
                if 'credentials' in vuln:
                    html += f'            <strong>Credentials:</strong> {vuln.get("credentials", "N/A")}<br>\n'
                if 'evidence' in vuln:
                    html += f'            <strong>Evidence:</strong> {vuln.get("evidence", "N/A")}<br>\n'
                
                html += f"""
        </div>
        
        <div class="remediation">
            <h4>📝 Remediation</h4>
            <p>{vuln.get('remediation', 'No remediation provided.')}</p>
        </div>
    </div>
"""
        
        html += f"""
    <div class="footer">
        <p>Generated by DV-WebScanPro on {self.timestamp}</p>
        <p>This report is for educational purposes only.</p>
    </div>
</body>
</html>
"""
        return html
    
    def save_report(self):
        """Save HTML report to file"""
        ensure_dir("reports")
        
        # Generate HTML
        html_content = self.generate_html()
        
        # Save HTML report
        report_file = f"reports/scan_report_{self.scan_id}.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Also save JSON data
        json_file = f"reports/scan_data_{self.scan_id}.json"
        report_data = {
            'target': self.target_url,
            'scan_id': self.scan_id,
            'timestamp': self.timestamp,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'by_risk': self.count_by_risk(),
                'by_type': self.count_by_type()
            }
        }
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print_success(f"HTML report saved to: {report_file}")
        print_success(f"JSON data saved to: {json_file}")
        
        return report_file