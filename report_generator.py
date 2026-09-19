import json
import os
from datetime import datetime


REPORT_PATH = "reports/audit_report.json"
OUTPUT_PATH = "reports/security_audit_report.html"


def load_report():
    with open(REPORT_PATH, "r") as file:
        return json.load(file)


def severity_class(severity):
    return severity.lower().replace(" ", "-")


def generate_html(report):
    metadata = report.get("scan_metadata", {})
    summary = report.get("risk_summary", {})
    findings = report.get("findings", [])

    rows = ""

    for finding in findings:
        severity = finding.get("severity", "INFO")
        status = finding.get("status", "UNKNOWN")

        rows += f"""
        <tr>
            <td>{finding.get("finding_id", "-")}</td>
            <td>{finding.get("name", "-")}</td>
            <td>
                <span class="severity {severity_class(severity)}">
                    {severity}
                </span>
            </td>
            <td>{status}</td>
            <td>{finding.get("description", "-")}</td>
            <td>{finding.get("recommendation", "-")}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cloud Security Audit Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f4f6f8;
            color: #222;
        }}

        .header {{
            background: #1f2937;
            color: white;
            padding: 30px;
            border-radius: 10px;
        }}

        .header h1 {{
            margin: 0;
        }}

        .metadata {{
            margin-top: 15px;
            font-size: 14px;
        }}

        .cards {{
            display: flex;
            gap: 15px;
            margin: 25px 0;
            flex-wrap: wrap;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            min-width: 150px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}

        .score {{
            font-size: 32px;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        th, td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #1f2937;
            color: white;
        }}

        .severity {{
            padding: 5px 9px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 12px;
        }}

        .critical {{
            background: #7f1d1d;
            color: white;
        }}

        .high {{
            background: #dc2626;
            color: white;
        }}

        .medium {{
            background: #f59e0b;
            color: black;
        }}

        .low {{
            background: #facc15;
            color: black;
        }}

        .info {{
            background: #93c5fd;
            color: black;
        }}

        .pass {{
            background: #86efac;
            color: black;
        }}

        .footer {{
            margin-top: 30px;
            font-size: 13px;
            color: #666;
        }}
    </style>
</head>

<body>

<div class="header">
    <h1>Cloud Security Audit Report</h1>

    <div class="metadata">
        <strong>Scanner:</strong>
        {metadata.get("scanner", "Unknown")}<br>

        <strong>Version:</strong>
        {metadata.get("scanner_version", "Unknown")}<br>

        <strong>Scan Time (UTC):</strong>
        {metadata.get("scan_time_utc", "Unknown")}<br>

        <strong>AWS Account:</strong>
        {metadata.get("account_id", "Unknown")}
    </div>
</div>

<div class="cards">

    <div class="card">
        <div>Security Score</div>
        <div class="score">
            {report.get("security_score", 0)}
        </div>
    </div>

    <div class="card">
         <div>Compliance Score</div>
         <div class="score">
             {report.get("compliance_score", 0)}%
         </div>
    </div>

    <div class="card">
        <div>Total Findings</div>
        <div class="score">
            {report.get("total_findings", 0)}
        </div>
    </div>

    <div class="card">
        <div>Critical</div>
        <div class="score">
            {summary.get("critical", 0)}
        </div>
    </div>

    <div class="card">
        <div>High</div>
        <div class="score">
            {summary.get("high", 0)}
        </div>
    </div>

    <div class="card">
        <div>Medium</div>
        <div class="score">
            {summary.get("medium", 0)}
        </div>
    </div>

    <div class="card">
        <div>Passed</div>
        <div class="score">
            {summary.get("pass", 0)}
        </div>
    </div>

</div>

<h2>Security Findings</h2>

<table>
    <thead>
        <tr>
            <th>Finding ID</th>
            <th>Name</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Description</th>
            <th>Recommendation</th>
        </tr>
    </thead>

    <tbody>
        {rows}
    </tbody>
</table>

<div class="footer">
    Generated by Cloud Security Configuration & Hardening Auditor
</div>

</body>
</html>
"""

    return html


def main():
    os.makedirs("reports", exist_ok=True)

    report = load_report()
    html = generate_html(report)

    with open(OUTPUT_PATH, "w") as file:
        file.write(html)

    print(f"HTML report generated: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
