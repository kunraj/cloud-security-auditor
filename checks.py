import subprocess


# ==========================================
# CHECK 1: FIREWALL
# ==========================================

def check_firewall():
    result = subprocess.run(
        ["sudo", "ufw", "status"],
        capture_output=True,
        text=True
    )

    if "Status: active" in result.stdout:
        return {
	    "finding_id": "LINUX-001",
            "name": "Firewall",
            "status": "PASS",
            "severity": "NONE",
            "description": "The host firewall is enabled and active.",
            "control": "Network Security",
            "reference": "CIS Linux Benchmark / NIST SP 800-53 SC-7",
            "recommendation": "No action required",
	    "remediation": "No remediation required"
        }

    else:
        return {
	    "finding_id": "LINUX-001",
            "name": "Firewall",
            "status": "FAIL",
            "severity": "HIGH",
            "description": "The host firewall is disabled.",
            "control": "Network Security",
            "reference": "CIS Linux Benchmark / NIST SP 800-53 SC-7",
            "recommendation": "Enable the firewall and configure appropriate inbound rules",
	    "remediation": "Run 'sudo ufw enable' and configure only required inbound ports"
        }

# ==========================================
# CHECK 2: SSH ROOT LOGIN
# ==========================================

def check_ssh():
    ssh_config = subprocess.run(
        ["sudo", "grep", "-i", "^PermitRootLogin", "/etc/ssh/sshd_config"],
        capture_output=True,
        text=True
    )

    if "PermitRootLogin no" in ssh_config.stdout:
        return {
	    "finding_id": "LINUX-002",
            "name": "SSH Root Login",
            "status": "PASS",
            "severity": "NONE",
            "description": "Direct SSH login for the root account is disabled.",
            "control": "Access Control",
            "reference": "CIS Linux Benchmark / NIST SP 800-53 AC-6",
            "recommendation": "No action required",
	    "remediation": "No remediation required"
        }

    else:
        return {
	    "finding_id": "LINUX-002",
            "name": "SSH Root Login",
            "status": "WARNING",
            "severity": "MEDIUM",
            "description": "Direct SSH root login may be permitted.",
            "control": "Access Control",
            "reference": "CIS Linux Benchmark / NIST SP 800-53 AC-6",
            "recommendation": "Disable direct SSH root login",
	    "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart SSH"
        }


# ==========================================
# CHECK 3: PRIVILEGED USERS
# ==========================================

def check_users():
    users = subprocess.run(
        ["awk", "-F:", "$3 == 0 {print $1}", "/etc/passwd"],
        capture_output=True,
        text=True
    )

    privileged_users = users.stdout.strip().splitlines()

    if privileged_users == ["root"]:
        return {
	    "finding_id": "LINUX-003",
            "name": "Privileged Users",
            "status": "PASS",
            "severity": "NONE",
            "description": "Only the root account has UID 0.",
            "control": "Least Privilege",
            "reference": "CIS Linux Benchmark / NIST SP 800-53 AC-6",
            "recommendation": "No action required",
	    "remediation": "No remediation required"
        }

    else:
        return {
	    "finding_id": "LINUX-003",
            "name": "Privileged Users",
            "status": "WARNING",
            "severity": "HIGH",
            "description": "Additional accounts have UID 0 privileges.",
            "control": "Least Privilege",
            "reference": "CIS Linux Benchmark / NIST SP 800-53 AC-6",
            "recommendation": "Review all accounts with UID 0 and remove unnecessary privileged accounts",
	    "remediation": "Review UID 0 accounts and remove unnecessary privileged accounts"
        }


# ==========================================
# CHECK 4: OPEN PORTS
# ==========================================

def check_ports():

    result = subprocess.run(
        ["ss", "-tuln"],
        capture_output=True,
        text=True
    )

    findings = []

    for line in result.stdout.splitlines():

        if "LISTEN" not in line:
            continue

        if ":22" in line:

            if "0.0.0.0:22" in line:

                findings.append({
		    "finding_id": "LINUX-004",
                    "name": "SSH exposed on all interfaces",
                    "status": "WARNING",
                    "severity": "HIGH",
                    "recommendation": "Restrict SSH access to trusted networks",
		    "remediation": "No remediation required"
                })

            else:

                findings.append({
		    "finding_id": "LINUX-004",
                    "name": "SSH listening",
                    "status": "INFO",
                    "severity": "LOW",
                    "recommendation": "Verify that SSH exposure is required"
                })

    return findings


# ==========================================
# CHECK 5: FILE PERMISSIONS
# ==========================================

def check_file_permissions():
    result = subprocess.run(
        ["stat", "-c", "%A", "/etc/shadow"],
        capture_output=True,
        text=True
    )

    permissions = result.stdout.strip()

    if not permissions:
        return {
	    "finding_id": "LINUX-005",
            "name": "Shadow File Permissions",
            "status": "ERROR",
            "severity": "HIGH",
            "description": "The permissions of /etc/shadow could not be determined.",
            "control": "File Permissions",
            "reference": "CIS Linux Benchmark",
            "recommendation": "Verify that /etc/shadow is protected from unauthorized access",
	    "remediation": "No remediation required"
        }

    if permissions[-3:] == "---":
        return {
	    "finding_id": "LINUX-005",
            "name": "Shadow File Permissions",
            "status": "PASS",
            "severity": "NONE",
            "description": "The /etc/shadow file is protected from other users.",
            "control": "File Permissions",
            "reference": "CIS Linux Benchmark",
            "recommendation": "No action required",
	    "remediation": "No remediation required"
        }

    else:
        return {
	    "finding_id": "LINUX-005",
            "name": "Shadow File Permissions",
            "status": "FAIL",
            "severity": "HIGH",
            "description": "The /etc/shadow file may have excessive permissions.",
            "control": "File Permissions",
            "reference": "CIS Linux Benchmark",
            "recommendation": "Restrict access to /etc/shadow",
	    "remediation": "Restrict /etc/shadow permissions using chmod and verify ownership"
        }
