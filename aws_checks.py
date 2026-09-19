import boto3


# ============================================================
# S3 PUBLIC ACCESS AUDIT
# ============================================================

def check_s3_buckets():
    s3 = boto3.client("s3")
    findings = []

    try:
        response = s3.list_buckets()

        for bucket in response.get("Buckets", []):

            bucket_name = bucket["Name"]

            try:
                public_access = s3.get_public_access_block(
                    Bucket=bucket_name
                )

                config = public_access[
                    "PublicAccessBlockConfiguration"
                ]

                all_blocked = (
                    config.get("BlockPublicAcls", False)
                    and config.get("IgnorePublicAcls", False)
                    and config.get("BlockPublicPolicy", False)
                    and config.get("RestrictPublicBuckets", False)
                )

                if all_blocked:
                    findings.append({
                        "finding_id": "AWS-S3-001",
                        "name": f"S3 Public Access - {bucket_name}",
                        "status": "PASS",
                        "severity": "NONE",
                        "description":
                            "All four S3 Block Public Access "
                            "settings are enabled.",
                        "control": "Data Protection",
                        "reference":
                            "AWS S3 Security Best Practices",
                        "recommendation":
                            "No action required",
                        "remediation":
                            "No remediation required"
                    })

                else:
                    findings.append({
                        "finding_id": "AWS-S3-001",
                        "name": f"S3 Public Access - {bucket_name}",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "description":
                            "One or more S3 Block Public Access "
                            "settings are disabled.",
                        "control": "Data Protection",
                        "reference":
                            "AWS S3 Security Best Practices",
                        "recommendation":
                            "Enable S3 Block Public Access unless "
                            "public access is explicitly required.",
                        "remediation":
                            "Enable all four S3 Block Public Access "
                            "settings where appropriate."
                    })

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:

                findings.append({
                    "finding_id": "AWS-S3-001",
                    "name": f"S3 Public Access - {bucket_name}",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description":
                        "No S3 Block Public Access configuration "
                        "was found.",
                    "control": "Data Protection",
                    "reference":
                        "AWS S3 Security Best Practices",
                    "recommendation":
                        "Configure S3 Block Public Access.",
                    "remediation":
                        "Enable all four S3 Block Public Access "
                        "settings where appropriate."
                })

            except Exception as error:

                findings.append({
                    "finding_id": "AWS-S3-001",
                    "name": f"S3 Public Access - {bucket_name}",
                    "status": "ERROR",
                    "severity": "HIGH",
                    "description":
                        f"Unable to check S3 public access: {error}",
                    "control": "Data Protection",
                    "reference":
                        "AWS S3 Security Best Practices",
                    "recommendation":
                        "Verify S3 permissions.",
                    "remediation":
                        "Ensure the auditor can inspect "
                        "S3 public access settings."
                })

    except Exception as error:

        findings.append({
            "finding_id": "AWS-S3-001",
            "name": "S3 Public Access Audit",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to list S3 buckets: {error}",
            "control": "Data Protection",
            "reference":
                "AWS S3 Security Best Practices",
            "recommendation":
                "Verify S3 permissions.",
            "remediation":
                "Ensure the auditor has permission to list buckets."
        })

    return findings


# ============================================================
# S3 ENCRYPTION AUDIT
# ============================================================

def check_s3_encryption():
    s3 = boto3.client("s3")
    findings = []

    try:
        response = s3.list_buckets()

        for bucket in response.get("Buckets", []):

            bucket_name = bucket["Name"]

            try:

                encryption = s3.get_bucket_encryption(
                    Bucket=bucket_name
                )

                rules = encryption[
                    "ServerSideEncryptionConfiguration"
                ].get("Rules", [])

                if rules:

                    findings.append({
                        "finding_id": "AWS-S3-002",
                        "name":
                            f"S3 Encryption - {bucket_name}",
                        "status": "PASS",
                        "severity": "NONE",
                        "description":
                            "Server-side encryption is configured "
                            "for the S3 bucket.",
                        "control": "Data Protection",
                        "reference":
                            "AWS S3 Security Best Practices",
                        "recommendation":
                            "No action required",
                        "remediation":
                            "No remediation required"
                    })

                else:

                    findings.append({
                        "finding_id": "AWS-S3-002",
                        "name":
                            f"S3 Encryption - {bucket_name}",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "description":
                            "No server-side encryption rule "
                            "was found.",
                        "control": "Data Protection",
                        "reference":
                            "AWS S3 Security Best Practices",
                        "recommendation":
                            "Enable server-side encryption.",
                        "remediation":
                            "Configure SSE-S3 or SSE-KMS encryption."
                    })

            except s3.exceptions.ClientError as error:

                error_code = error.response.get(
                    "Error", {}
                ).get("Code", "")

                if error_code == (
                    "ServerSideEncryptionConfigurationNotFoundError"
                ):

                    findings.append({
                        "finding_id": "AWS-S3-002",
                        "name":
                            f"S3 Encryption - {bucket_name}",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "description":
                            "Server-side encryption is not "
                            "configured.",
                        "control": "Data Protection",
                        "reference":
                            "AWS S3 Security Best Practices",
                        "recommendation":
                            "Enable server-side encryption.",
                        "remediation":
                            "Configure SSE-S3 or SSE-KMS encryption."
                    })

                else:

                    findings.append({
                        "finding_id": "AWS-S3-002",
                        "name":
                            f"S3 Encryption - {bucket_name}",
                        "status": "ERROR",
                        "severity": "HIGH",
                        "description":
                            f"Unable to check encryption: {error}",
                        "control": "Data Protection",
                        "reference":
                            "AWS S3 Security Best Practices",
                        "recommendation":
                            "Verify S3 permissions.",
                        "remediation":
                            "Ensure the auditor can inspect "
                            "bucket encryption."
                    })

    except Exception as error:

        findings.append({
            "finding_id": "AWS-S3-002",
            "name": "S3 Encryption Audit",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to list S3 buckets: {error}",
            "control": "Data Protection",
            "reference":
                "AWS S3 Security Best Practices",
            "recommendation":
                "Verify S3 permissions.",
            "remediation":
                "Ensure the auditor can list S3 buckets."
        })

    return findings


# ============================================================
# SECURITY GROUP AUDIT
# ============================================================

def check_security_groups():

    findings = []

    try:

        ec2 = boto3.client("ec2")

        regions_response = ec2.describe_regions(
            AllRegions=False
        )

        regions = [
            region["RegionName"]
            for region in regions_response["Regions"]
        ]

    except Exception as error:

        return [{
            "finding_id": "AWS-SG-000",
            "name": "Security Group Region Discovery",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to retrieve AWS regions: {error}",
            "control": "Network Security",
            "reference":
                "AWS Security Best Practices",
            "recommendation":
                "Verify EC2 region permissions.",
            "remediation":
                "Ensure ec2:DescribeRegions is allowed."
        }]

    for region_name in regions:

        print(
            f"Scanning security groups in {region_name}..."
        )

        try:

            regional_ec2 = boto3.client(
                "ec2",
                region_name=region_name
            )

            response = regional_ec2.describe_security_groups()

            for security_group in response["SecurityGroups"]:

                group_name = security_group["GroupName"]
                group_id = security_group["GroupId"]

                for permission in security_group.get(
                    "IpPermissions", []
                ):

                    protocol = permission.get("IpProtocol")
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")

                    for ip_range in permission.get(
                        "IpRanges", []
                    ):

                        cidr = ip_range.get("CidrIp")

                        if cidr != "0.0.0.0/0":
                            continue

                        if protocol == "-1":

                            findings.append({
                                "finding_id": "AWS-SG-001",
                                "name":
                                    f"Unrestricted Traffic - "
                                    f"{group_name}",
                                "status": "FAIL",
                                "severity": "CRITICAL",
                                "description":
                                    f"Security group {group_id} "
                                    f"in {region_name} allows "
                                    "all traffic from the Internet.",
                                "control": "Network Security",
                                "reference":
                                    "AWS Security Best Practices",
                                "recommendation":
                                    "Remove unrestricted "
                                    "Internet access.",
                                "remediation":
                                    "Restrict the security group "
                                    "rule to trusted CIDR ranges."
                            })

                        elif (
                            from_port == 22
                            or to_port == 22
                        ):

                            findings.append({
                                "finding_id": "AWS-SG-002",
                                "name":
                                    f"SSH Exposed - {group_name}",
                                "status": "FAIL",
                                "severity": "HIGH",
                                "description":
                                    f"SSH port 22 in "
                                    f"{region_name} is accessible "
                                    "from 0.0.0.0/0.",
                                "control": "Network Security",
                                "reference":
                                    "AWS Security Best Practices",
                                "recommendation":
                                    "Restrict SSH access to "
                                    "trusted IP addresses.",
                                "remediation":
                                    "Replace 0.0.0.0/0 with a "
                                    "trusted IP/CIDR range."
                            })

                        elif (
                            from_port == 3389
                            or to_port == 3389
                        ):

                            findings.append({
                                "finding_id": "AWS-SG-003",
                                "name":
                                    f"RDP Exposed - {group_name}",
                                "status": "FAIL",
                                "severity": "HIGH",
                                "description":
                                    f"RDP port 3389 in "
                                    f"{region_name} is accessible "
                                    "from 0.0.0.0/0.",
                                "control": "Network Security",
                                "reference":
                                    "AWS Security Best Practices",
                                "recommendation":
                                    "Restrict RDP access to "
                                    "trusted networks.",
                                "remediation":
                                    "Replace 0.0.0.0/0 with a "
                                    "trusted IP/CIDR range."
                            })

        except Exception as error:

            findings.append({
                "finding_id": "AWS-SG-000",
                "name":
                    f"Security Group Audit - {region_name}",
                "status": "ERROR",
                "severity": "HIGH",
                "description":
                    f"Unable to audit security groups: {error}",
                "control": "Network Security",
                "reference":
                    "AWS Security Best Practices",
                "recommendation":
                    "Verify EC2 permissions.",
                "remediation":
                    "Ensure ec2:DescribeSecurityGroups "
                    "is allowed."
            })

    if not findings:

        findings.append({
            "finding_id": "AWS-SG-000",
            "name": "AWS Security Groups",
            "status": "PASS",
            "severity": "NONE",
            "description":
                "No unrestricted SSH, RDP, or all-traffic "
                "security group rules were detected.",
            "control": "Network Security",
            "reference":
                "AWS Security Best Practices",
            "recommendation":
                "No action required",
            "remediation":
                "No remediation required"
        })

    return findings


# ============================================================
# IAM USER AUDIT
# ============================================================

def check_iam_users():

    iam = boto3.client("iam")

    findings = []

    try:

        response = iam.list_users()

        for user in response["Users"]:

            username = user["UserName"]

            # MFA
            try:

                mfa_response = iam.list_mfa_devices(
                    UserName=username
                )

                if not mfa_response["MFADevices"]:

                    findings.append({
                        "finding_id": "AWS-IAM-001",
                        "name":
                            f"IAM MFA - {username}",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "description":
                            f"IAM user {username} does not "
                            "have MFA enabled.",
                        "control":
                            "Identity and Access Management",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "Enable MFA for the IAM user.",
                        "remediation":
                            "Configure a virtual or hardware "
                            "MFA device."
                    })

                else:

                    findings.append({
                        "finding_id": "AWS-IAM-001",
                        "name":
                            f"IAM MFA - {username}",
                        "status": "PASS",
                        "severity": "NONE",
                        "description":
                            f"IAM user {username} has MFA configured.",
                        "control":
                            "Identity and Access Management",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "No action required",
                        "remediation":
                            "No remediation required"
                    })

            except Exception as error:

                findings.append({
                    "finding_id": "AWS-IAM-001",
                    "name":
                        f"IAM MFA Audit - {username}",
                    "status": "ERROR",
                    "severity": "HIGH",
                    "description":
                        f"Unable to inspect MFA: {error}",
                    "control":
                        "Identity and Access Management",
                    "reference":
                        "AWS IAM Security Best Practices",
                    "recommendation":
                        "Verify IAM permissions.",
                    "remediation":
                        "Ensure iam:ListMFADevices is allowed."
                })

            # Access keys
            try:

                keys_response = iam.list_access_keys(
                    UserName=username
                )

                for key in keys_response[
                    "AccessKeyMetadata"
                ]:

                    if key["Status"] == "Active":

                        findings.append({
                            "finding_id": "AWS-IAM-002",
                            "name":
                                f"Active Access Key - {username}",
                            "status": "WARNING",
                            "severity": "MEDIUM",
                            "description":
                                f"IAM user {username} has an "
                                "active access key.",
                            "control":
                                "Identity and Access Management",
                            "reference":
                                "AWS IAM Security Best Practices",
                            "recommendation":
                                "Review whether the access key "
                                "is still required.",
                            "remediation":
                                "Remove unused keys and prefer "
                                "temporary credentials where possible."
                        })

            except Exception as error:

                findings.append({
                    "finding_id": "AWS-IAM-002",
                    "name":
                        f"Access Key Audit - {username}",
                    "status": "ERROR",
                    "severity": "HIGH",
                    "description":
                        f"Unable to inspect access keys: {error}",
                    "control":
                        "Identity and Access Management",
                    "reference":
                        "AWS IAM Security Best Practices",
                    "recommendation":
                        "Verify IAM permissions.",
                    "remediation":
                        "Ensure iam:ListAccessKeys is allowed."
                })

    except Exception as error:

        findings.append({
            "finding_id": "AWS-IAM-001",
            "name": "IAM User Audit",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to list IAM users: {error}",
            "control":
                "Identity and Access Management",
            "reference":
                "AWS IAM Security Best Practices",
            "recommendation":
                "Verify IAM permissions.",
            "remediation":
                "Ensure iam:ListUsers is allowed."
        })

    return findings


# ============================================================
# IAM DIRECT POLICY / LEAST PRIVILEGE AUDIT
# ============================================================

def check_iam_privileges():

    iam = boto3.client("iam")
    findings = []

    try:

        response = iam.list_users()

        for user in response["Users"]:

            username = user["UserName"]

            attached_response = iam.list_attached_user_policies(
                UserName=username
            )

            for policy in attached_response[
                "AttachedPolicies"
            ]:

                policy_name = policy["PolicyName"]
                policy_arn = policy["PolicyArn"]

                if policy_name == "AdministratorAccess":

                    findings.append({
                        "finding_id": "AWS-IAM-003",
                        "name":
                            f"AdministratorAccess - {username}",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "description":
                            f"IAM user {username} has "
                            "AdministratorAccess.",
                        "control": "Least Privilege",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "Remove AdministratorAccess unless "
                            "administrative access is explicitly required.",
                        "remediation":
                            "Replace it with a least-privilege policy."
                    })

                    continue

                try:

                    policy_response = iam.get_policy(
                        PolicyArn=policy_arn
                    )

                    default_version = policy_response[
                        "Policy"
                    ]["DefaultVersionId"]

                    version_response = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )

                    document = version_response[
                        "PolicyVersion"
                    ]["Document"]

                    statements = document.get(
                        "Statement",
                        []
                    )

                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:

                        actions = statement.get(
                            "Action",
                            []
                        )

                        if isinstance(actions, str):
                            actions = [actions]

                        if "*" in actions:

                            findings.append({
                                "finding_id": "AWS-IAM-004",
                                "name":
                                    f"Wildcard Permissions - "
                                    f"{username}",
                                "status": "FAIL",
                                "severity": "CRITICAL",
                                "description":
                                    f"Policy {policy_name} "
                                    "contains Action:*.",
                                "control": "Least Privilege",
                                "reference":
                                    "AWS IAM Security Best Practices",
                                "recommendation":
                                    "Replace wildcard permissions "
                                    "with required actions only.",
                                "remediation":
                                    "Review the policy and remove "
                                    "unnecessary Action:* permissions."
                            })

                            break

                except Exception as error:

                    findings.append({
                        "finding_id": "AWS-IAM-004",
                        "name":
                            f"Policy Audit - {username}",
                        "status": "ERROR",
                        "severity": "HIGH",
                        "description":
                            f"Unable to inspect policy "
                            f"{policy_name}: {error}",
                        "control": "Least Privilege",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "Verify IAM policy permissions.",
                        "remediation":
                            "Ensure the auditor can inspect "
                            "IAM policy versions."
                    })

    except Exception as error:

        findings.append({
            "finding_id": "AWS-IAM-004",
            "name": "IAM Privilege Audit",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to audit IAM privileges: {error}",
            "control": "Least Privilege",
            "reference":
                "AWS IAM Security Best Practices",
            "recommendation":
                "Verify IAM permissions.",
            "remediation":
                "Ensure IAM policy inspection permissions exist."
        })

    return findings


# ============================================================
# IAM GROUP AUDIT
# ============================================================

def check_iam_groups():

    iam = boto3.client("iam")
    findings = []

    try:

        response = iam.list_groups()

        for group in response["Groups"]:

            group_name = group["GroupName"]

            attached_response = iam.list_attached_group_policies(
                GroupName=group_name
            )

            for policy in attached_response[
                "AttachedPolicies"
            ]:

                policy_name = policy["PolicyName"]
                policy_arn = policy["PolicyArn"]

                if policy_name == "AdministratorAccess":

                    findings.append({
                        "finding_id": "AWS-IAM-005",
                        "name":
                            f"AdministratorAccess Group - "
                            f"{group_name}",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "description":
                            f"IAM group {group_name} has "
                            "AdministratorAccess.",
                        "control": "Least Privilege",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "Remove AdministratorAccess unless "
                            "explicitly required.",
                        "remediation":
                            "Replace it with least-privilege access."
                    })

                    continue

                try:

                    policy_response = iam.get_policy(
                        PolicyArn=policy_arn
                    )

                    version_id = policy_response[
                        "Policy"
                    ]["DefaultVersionId"]

                    version_response = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )

                    document = version_response[
                        "PolicyVersion"
                    ]["Document"]

                    statements = document.get(
                        "Statement",
                        []
                    )

                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:

                        actions = statement.get(
                            "Action",
                            []
                        )

                        if isinstance(actions, str):
                            actions = [actions]

                        if "*" in actions:

                            findings.append({
                                "finding_id": "AWS-IAM-006",
                                "name":
                                    f"Wildcard Group Policy - "
                                    f"{group_name}",
                                "status": "FAIL",
                                "severity": "CRITICAL",
                                "description":
                                    f"Group {group_name} has "
                                    f"policy {policy_name} with "
                                    "Action:*.",
                                "control": "Least Privilege",
                                "reference":
                                    "AWS IAM Security Best Practices",
                                "recommendation":
                                    "Replace wildcard permissions "
                                    "with required actions only.",
                                "remediation":
                                    "Review and restrict the "
                                    "group policy."
                            })

                            break

                except Exception as error:

                    findings.append({
                        "finding_id": "AWS-IAM-006",
                        "name":
                            f"Group Policy Audit - {group_name}",
                        "status": "ERROR",
                        "severity": "HIGH",
                        "description":
                            f"Unable to inspect policy: {error}",
                        "control": "Least Privilege",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "Verify IAM policy permissions.",
                        "remediation":
                            "Ensure policy versions can be inspected."
                    })

    except Exception as error:

        findings.append({
            "finding_id": "AWS-IAM-005",
            "name": "IAM Group Audit",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to audit IAM groups: {error}",
            "control":
                "Identity and Access Management",
            "reference":
                "AWS IAM Security Best Practices",
            "recommendation":
                "Verify IAM group permissions.",
            "remediation":
                "Ensure IAM group inspection permissions exist."
        })

    return findings


# ============================================================
# IAM ROLE AUDIT
# ============================================================

def check_iam_roles():

    iam = boto3.client("iam")
    findings = []

    try:

        response = iam.list_roles()

        for role in response["Roles"]:

            role_name = role["RoleName"]

            # -----------------------------
            # Trust policy
            # -----------------------------

            try:

                role_response = iam.get_role(
                    RoleName=role_name
                )

                trust_policy = role_response[
                    "Role"
                ]["AssumeRolePolicyDocument"]

                statements = trust_policy.get(
                    "Statement",
                    []
                )

                if isinstance(statements, dict):
                    statements = [statements]

                wildcard_trust = False

                for statement in statements:

                    principal = statement.get(
                        "Principal"
                    )

                    if principal == "*":
                        wildcard_trust = True

                    elif isinstance(principal, dict):

                        for value in principal.values():

                            if value == "*":
                                wildcard_trust = True

                            elif isinstance(
                                value,
                                list
                            ) and "*" in value:

                                wildcard_trust = True

                if wildcard_trust:

                    findings.append({
                        "finding_id": "AWS-IAM-007",
                        "name":
                            f"Wildcard Trust Policy - {role_name}",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "description":
                            f"IAM role {role_name} has a "
                            "wildcard trust principal.",
                        "control":
                            "Identity and Access Management",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "Restrict the trust policy to "
                            "explicitly trusted principals.",
                        "remediation":
                            "Review the trust policy and remove "
                            "unnecessary wildcard principals."
                    })

                else:

                    findings.append({
                        "finding_id": "AWS-IAM-007",
                        "name":
                            f"Role Trust Policy - {role_name}",
                        "status": "PASS",
                        "severity": "NONE",
                        "description":
                            f"No obvious wildcard principal was "
                            f"detected in {role_name}.",
                        "control":
                            "Identity and Access Management",
                        "reference":
                            "AWS IAM Security Best Practices",
                        "recommendation":
                            "No action required",
                        "remediation":
                            "No remediation required"
                    })

            except Exception as error:

                findings.append({
                    "finding_id": "AWS-IAM-007",
                    "name":
                        f"Role Trust Audit - {role_name}",
                    "status": "ERROR",
                    "severity": "HIGH",
                    "description":
                        f"Unable to inspect trust policy: {error}",
                    "control":
                        "Identity and Access Management",
                    "reference":
                        "AWS IAM Security Best Practices",
                    "recommendation":
                        "Verify IAM role permissions.",
                    "remediation":
                        "Ensure iam:GetRole is allowed."
                })

            # -----------------------------
            # Attached policies
            # -----------------------------

            try:

                attached_response = (
                    iam.list_attached_role_policies(
                        RoleName=role_name
                    )
                )

                for policy in attached_response[
                    "AttachedPolicies"
                ]:

                    if policy["PolicyName"] == "AdministratorAccess":

                        findings.append({
                            "finding_id": "AWS-IAM-008",
                            "name":
                                f"AdministratorAccess Role - "
                                f"{role_name}",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "description":
                                f"IAM role {role_name} has "
                                "AdministratorAccess.",
                            "control":
                                "Least Privilege",
                            "reference":
                                "AWS IAM Security Best Practices",
                            "recommendation":
                                "Remove AdministratorAccess unless "
                                "administrative access is required.",
                            "remediation":
                                "Replace it with a least-privilege policy."
                        })

            except Exception as error:

                findings.append({
                    "finding_id": "AWS-IAM-008",
                    "name":
                        f"Role Policy Audit - {role_name}",
                    "status": "ERROR",
                    "severity": "HIGH",
                    "description":
                        f"Unable to inspect role policies: {error}",
                    "control":
                        "Least Privilege",
                    "reference":
                        "AWS IAM Security Best Practices",
                    "recommendation":
                        "Verify IAM role policy permissions.",
                    "remediation":
                        "Ensure role policies can be inspected."
                })

    except Exception as error:

        findings.append({
            "finding_id": "AWS-IAM-007",
            "name": "IAM Role Audit",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to list IAM roles: {error}",
            "control":
                "Identity and Access Management",
            "reference":
                "AWS IAM Security Best Practices",
            "recommendation":
                "Verify IAM role permissions.",
            "remediation":
                "Ensure iam:ListRoles is allowed."
        })

    return findings


# ============================================================
# CLOUDTRAIL AUDIT
# ============================================================

def check_cloudtrail():

    cloudtrail = boto3.client("cloudtrail")
    findings = []

    try:

        response = cloudtrail.describe_trails(
            includeShadowTrails=False
        )

        trails = response.get(
            "trailList",
            []
        )

        if not trails:

            findings.append({
                "finding_id": "AWS-CT-001",
                "name": "CloudTrail",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description":
                    "No CloudTrail trail was configured.",
                "control":
                    "Logging and Monitoring",
                "reference":
                    "AWS CloudTrail Security Best Practices",
                "recommendation":
                    "Configure CloudTrail.",
                "remediation":
                    "Create and enable an appropriate CloudTrail trail."
            })

            return findings

        active_trail_found = False

        for trail in trails:

            trail_name = trail["Name"]

            try:

                status_response = cloudtrail.get_trail_status(
                    Name=trail["TrailARN"]
                )

                is_logging = status_response.get(
                    "IsLogging",
                    False
                )

                multi_region = trail.get(
                    "IsMultiRegionTrail",
                    False
                )

                if not is_logging:

                    findings.append({
                        "finding_id": "AWS-CT-002",
                        "name":
                            f"CloudTrail Logging - {trail_name}",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "description":
                            f"CloudTrail trail {trail_name} "
                            "is not actively logging.",
                        "control":
                            "Logging and Monitoring",
                        "reference":
                            "AWS CloudTrail Security Best Practices",
                        "recommendation":
                            "Enable CloudTrail logging.",
                        "remediation":
                            "Start logging for the CloudTrail trail."
                    })

                else:

                    active_trail_found = True

                    if multi_region:

                        findings.append({
                            "finding_id": "AWS-CT-003",
                            "name":
                                f"CloudTrail - {trail_name}",
                            "status": "PASS",
                            "severity": "NONE",
                            "description":
                                f"CloudTrail trail {trail_name} "
                                "is actively logging and is "
                                "multi-region.",
                            "control":
                                "Logging and Monitoring",
                            "reference":
                                "AWS CloudTrail Security Best Practices",
                            "recommendation":
                                "No action required",
                            "remediation":
                                "No remediation required"
                        })

                    else:

                        findings.append({
                            "finding_id": "AWS-CT-003",
                            "name":
                                f"CloudTrail Region Coverage - "
                                f"{trail_name}",
                            "status": "WARNING",
                            "severity": "MEDIUM",
                            "description":
                                f"CloudTrail trail {trail_name} "
                                "is logging but is not "
                                "multi-region.",
                            "control":
                                "Logging and Monitoring",
                            "reference":
                                "AWS CloudTrail Security Best Practices",
                            "recommendation":
                                "Consider multi-region logging.",
                            "remediation":
                                "Configure the trail as multi-region."
                        })

            except Exception as error:

                findings.append({
                    "finding_id": "AWS-CT-002",
                    "name":
                        f"CloudTrail Audit - {trail_name}",
                    "status": "ERROR",
                    "severity": "HIGH",
                    "description":
                        f"Unable to inspect trail: {error}",
                    "control":
                        "Logging and Monitoring",
                    "reference":
                        "AWS CloudTrail Security Best Practices",
                    "recommendation":
                        "Verify CloudTrail permissions.",
                    "remediation":
                        "Ensure cloudtrail:GetTrailStatus is allowed."
                })

        if not active_trail_found:

            findings.append({
                "finding_id": "AWS-CT-002",
                "name": "CloudTrail Active Logging",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description":
                    "No CloudTrail trail is actively logging.",
                "control":
                    "Logging and Monitoring",
                "reference":
                    "AWS CloudTrail Security Best Practices",
                "recommendation":
                    "Enable CloudTrail logging.",
                "remediation":
                    "Start logging on an appropriate trail."
            })

    except Exception as error:

        findings.append({
            "finding_id": "AWS-CT-001",
            "name": "CloudTrail Audit",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to audit CloudTrail: {error}",
            "control":
                "Logging and Monitoring",
            "reference":
                "AWS CloudTrail Security Best Practices",
            "recommendation":
                "Verify CloudTrail permissions.",
            "remediation":
                "Ensure CloudTrail inspection permissions exist."
        })

    return findings


# ============================================================
# EC2 AUDIT
# ============================================================

def check_ec2_instances():

    findings = []

    try:

        ec2 = boto3.client("ec2")

        regions_response = ec2.describe_regions(
            AllRegions=False
        )

        regions = [
            region["RegionName"]
            for region in regions_response["Regions"]
        ]

    except Exception as error:

        return [{
            "finding_id": "AWS-EC2-000",
            "name": "EC2 Region Discovery",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to retrieve AWS regions: {error}",
            "control":
                "Cloud Security Management",
            "reference":
                "AWS EC2 Security Best Practices",
            "recommendation":
                "Verify EC2 region permissions.",
            "remediation":
                "Ensure ec2:DescribeRegions is allowed."
        }]

    for region_name in regions:

        print(
            f"Scanning EC2 instances in {region_name}..."
        )

        try:

            regional_ec2 = boto3.client(
                "ec2",
                region_name=region_name
            )

            response = regional_ec2.describe_instances()

            for reservation in response["Reservations"]:

                for instance in reservation["Instances"]:

                    instance_id = instance["InstanceId"]
                    state = instance["State"]["Name"]

                    if state == "terminated":
                        continue

                    # Public IP
                    public_ip = instance.get(
                        "PublicIpAddress"
                    )

                    if public_ip:

                        findings.append({
                            "finding_id": "AWS-EC2-001",
                            "name":
                                f"EC2 Public IP - {instance_id}",
                            "status": "WARNING",
                            "severity": "MEDIUM",
                            "description":
                                f"EC2 instance {instance_id} "
                                f"in {region_name} has public "
                                f"IP {public_ip}.",
                            "control":
                                "Network Security",
                            "reference":
                                "AWS EC2 Security Best Practices",
                            "recommendation":
                                "Verify that Internet exposure "
                                "is required.",
                            "remediation":
                                "Use private networking where "
                                "public exposure is unnecessary."
                        })

                    # IMDSv2
                    metadata_options = instance.get(
                        "MetadataOptions",
                        {}
                    )

                    http_tokens = metadata_options.get(
                        "HttpTokens"
                    )

                    if http_tokens != "required":

                        findings.append({
                            "finding_id": "AWS-EC2-002",
                            "name":
                                f"EC2 IMDSv2 - {instance_id}",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "description":
                                f"EC2 instance {instance_id} "
                                f"in {region_name} does not "
                                "require IMDSv2.",
                            "control":
                                "Instance Security",
                            "reference":
                                "AWS EC2 Security Best Practices",
                            "recommendation":
                                "Require IMDSv2.",
                            "remediation":
                                "Configure the instance metadata "
                                "service to require IMDSv2."
                        })

                    else:

                        findings.append({
                            "finding_id": "AWS-EC2-002",
                            "name":
                                f"EC2 IMDSv2 - {instance_id}",
                            "status": "PASS",
                            "severity": "NONE",
                            "description":
                                f"EC2 instance {instance_id} "
                                "requires IMDSv2.",
                            "control":
                                "Instance Security",
                            "reference":
                                "AWS EC2 Security Best Practices",
                            "recommendation":
                                "No action required",
                            "remediation":
                                "No remediation required"
                        })

        except Exception as error:

            findings.append({
                "finding_id": "AWS-EC2-000",
                "name":
                    f"EC2 Audit - {region_name}",
                "status": "ERROR",
                "severity": "HIGH",
                "description":
                    f"Unable to audit EC2 in "
                    f"{region_name}: {error}",
                "control":
                    "Cloud Security Management",
                "reference":
                    "AWS EC2 Security Best Practices",
                "recommendation":
                    "Verify EC2 permissions.",
                "remediation":
                    "Ensure ec2:DescribeInstances is allowed."
            })

    if not findings:

        findings.append({
            "finding_id": "AWS-EC2-000",
            "name": "EC2 Security",
            "status": "PASS",
            "severity": "NONE",
            "description":
                "No EC2 security findings were detected.",
            "control":
                "Instance Security",
            "reference":
                "AWS EC2 Security Best Practices",
            "recommendation":
                "No action required",
            "remediation":
                "No remediation required"
        })

    return findings
