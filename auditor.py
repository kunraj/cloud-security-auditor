from aws_checks import (
    check_s3_buckets,
    check_security_groups,
    check_iam_users,
    check_iam_privileges,
    check_iam_groups,
    check_iam_roles,
    check_cloudtrail,
    check_s3_encryption,
    check_ec2_instances
)




import json
import csv



from checks import (
    check_firewall,
    check_ssh,
    check_users,
    check_ports,
    check_file_permissions
)


# ==========================================
# RISK ENGINE
# ==========================================


def calculate_score(findings):
    score = 100

    for finding in findings:

        severity = finding.get("severity")

        if severity == "CRITICAL":
            score -= 30

        elif severity == "HIGH":
            score -= 20

        elif severity == "MEDIUM":
            score -= 10

        elif severity == "LOW":
            score -= 5

    if score < 0:
        score = 0

    return score

def generate_risk_summary(findings):

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "pass": 0,
        "info": 0,
        "error": 0
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            ""
        ).upper()

        status = finding.get(
            "status",
            ""
        ).upper()

        if status == "ERROR":
            summary["error"] += 1

        elif status == "PASS":
            summary["pass"] += 1

        elif severity == "CRITICAL":
            summary["critical"] += 1

        elif severity == "HIGH":
            summary["high"] += 1

        elif severity == "MEDIUM":
            summary["medium"] += 1

        elif severity == "LOW":
            summary["low"] += 1

        elif status == "INFO":
            summary["info"] += 1

    return summary


def get_top_risks(findings, limit=5):

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "NONE": 0
    }

    risks = []

    for finding in findings:

        severity = finding.get(
            "severity",
            "NONE"
        )

        if severity == "NONE":
            continue

        if finding.get("status") == "ERROR":
            continue

        risks.append(finding)

    risks.sort(
        key=lambda finding:
            severity_order.get(
                finding.get("severity", "NONE"),
                0
            ),
        reverse=True
    )

    return risks[:limit]


# ==========================================
# REPORT GENERATOR
# ==========================================

def save_report(findings, score):

    summary = generate_risk_summary(findings)
    top_risks = get_top_risks(findings)

    report = {
        "security_score": score,
        "total_findings": len(findings),

        "risk_summary": summary,

        "top_risks": top_risks,

        "findings": findings
    }

    with open(
        "reports/audit_report.json",
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        "Report saved to reports/audit_report.json"
    )

# ==========================================
# CSV REPORT GENERATOR
# ==========================================

def save_csv_report(findings):

    with open(
        "reports/audit_report.csv",
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
    "name",
    "status",
    "severity",
    "description",
    "control",
    "reference",
    "recommendation",
    "remediation"
]
        )

        writer.writeheader()

        writer.writerows(findings)

        print("CSV report saved to reports/audit_report.csv")


# ==========================================
# MAIN PROGRAM
# ==========================================

print("========================================")
print("      SECURITY CONFIGURATION AUDIT")
print("========================================")


findings = []

findings.append(check_firewall())
findings.append(check_ssh())
findings.append(check_users())
findings.append(check_file_permissions())

port_findings = check_ports()

findings.extend(port_findings)

print("\nAWS SECURITY CHECKS")
print("----------------------------------------")

aws_findings = check_s3_buckets()
findings.extend(aws_findings)

security_group_findings = check_security_groups()
findings.extend(security_group_findings)

iam_findings = check_iam_users()
findings.extend(iam_findings)


iam_privilege_findings = check_iam_privileges()
findings.extend(iam_privilege_findings)

iam_group_findings = check_iam_groups()
findings.extend(iam_group_findings)

iam_role_findings = check_iam_roles()
findings.extend(iam_role_findings)

cloudtrail_findings = check_cloudtrail()
findings.extend(cloudtrail_findings)

s3_encryption_findings = check_s3_encryption()
findings.extend(s3_encryption_findings)


ec2_findings = check_ec2_instances()
findings.extend(ec2_findings)






# ==========================================
# DISPLAY RESULTS
# ==========================================

print("\nAUDIT RESULTS")
print("----------------------------------------")


for finding in findings:

    print(
        "[{}] {}".format(
            finding["status"],
            finding["name"]
        )
    )

    print("Severity:", finding["severity"])
    print("Recommendation:", finding["recommendation"])
    print("Remediation:", finding["remediation"])
    print()



# ==========================================
# SECURITY SCORE
# ==========================================

score = calculate_score(findings)

summary = generate_risk_summary(findings)
top_risks = get_top_risks(findings)

print("----------------------------------------")
print("SECURITY SCORE:", score, "/ 100")
print("----------------------------------------")

print("\nRISK SUMMARY")
print("----------------------------------------")

print("CRITICAL:", summary["critical"])
print("HIGH:    ", summary["high"])
print("MEDIUM:  ", summary["medium"])
print("LOW:     ", summary["low"])
print("PASS:    ", summary["pass"])
print("ERROR:   ", summary["error"])

print("\nTOP RISKS")
print("----------------------------------------")

for number, finding in enumerate(
    top_risks,
    start=1
):

    print(
        f"{number}. "
        f"[{finding['severity']}] "
        f"{finding['name']}"
    )

save_report(findings, score)
save_csv_report(findings)
