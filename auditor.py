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



import os
import json
import csv
from datetime import datetime, timezone


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
        status = finding.get("status", "").upper()
        severity = finding.get("severity", "").upper()

        # Errors mean the check could not be completed.
        # They should not reduce the security score.
        if status == "ERROR":
            continue

        # Passed checks should not reduce the score.
        if status == "PASS":
            continue

        if severity == "CRITICAL":
            score -= 30
        elif severity == "HIGH":
            score -= 20
        elif severity == "MEDIUM":
            score -= 10
        elif severity == "LOW":
            score -= 5

    return max(score, 0)

#=======================================
#Calculate Compliance
#======================================
def calculate_compliance(findings):
    """
    Calculate compliance percentage based on PASS/FAIL findings.
    ERROR findings are excluded because they could not be evaluated.
    """

    evaluated = [
        f for f in findings
        if f.get("status") in ["PASS", "FAIL"]
    ]

    if not evaluated:
        return 0

    passed = sum(
        1 for f in evaluated
        if f.get("status") == "PASS"
    )

    return round((passed / len(evaluated)) * 100, 2)

#========================================
# AWS Account Info
#========================================
def get_aws_account_info():

    try:
        import boto3

        sts = boto3.client("sts")

        identity = sts.get_caller_identity()

        return {
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId")
        }

    except Exception as error:

        return {
            "account_id": "Unavailable",
            "arn": "Unavailable",
            "user_id": "Unavailable",
            "error": str(error)
        }

#===========================================
#History Scan
#==========================================
def save_scan_history(findings, score):
    os.makedirs("reports/history", exist_ok=True)

    metadata = get_aws_account_info()
    summary = generate_risk_summary(findings)

    timestamp = datetime.now(timezone.utc)
    filename = timestamp.strftime("%Y%m%d_%H%M%S") + ".json"

    history_data = {
        "scan_time_utc": timestamp.isoformat(),
        "account_id": metadata.get("account_id", "Unknown"),
        "security_score": score,
	"compliance_score": calculate_compliance(findings),
        "total_findings": len(findings),
        "risk_summary": summary
    }

    history_path = os.path.join("reports", "history", filename)

    with open(history_path, "w") as file:
        json.dump(history_data, file, indent=4)

    print(f"Scan history saved: {history_path}")
# ==========================================
# REPORT GENERATOR
# ==========================================

def save_report(findings, score):

    summary = generate_risk_summary(findings)
    top_risks = get_top_risks(findings)

    aws_account = get_aws_account_info()

    scan_time = datetime.now(
        timezone.utc
    ).isoformat()

    report = {

        "scan_metadata": {
            "scan_time_utc": scan_time,
            "account_id":
                aws_account.get(
                    "account_id",
                    "Unavailable"
                ),
            "scanner":
                "Cloud Security Configuration & Hardening Auditor",
            "scanner_version": "1.0",
            "sources": [
                "Linux",
                "AWS"
            ]
        },

        "security_score": score,

	"compliance_score": calculate_compliance(findings),

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
    "finding_id",
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
        severity = finding.get("severity", "").upper()
        status = finding.get("status", "").upper()

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
        "LOW": 1
    }

    risks = []

    for finding in findings:
        status = finding.get("status", "").upper()
        severity = finding.get("severity", "").upper()

        # Only include actual security findings
        if status in ["PASS", "ERROR"]:
            continue

        if severity not in severity_order:
            continue

        risks.append(finding)

    risks.sort(
        key=lambda x: severity_order.get(
            x.get("severity", "").upper(), 0
        ),
        reverse=True
    )

    return risks[:limit]


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
compliance_score = calculate_compliance(findings)
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
save_scan_history(findings, score)
