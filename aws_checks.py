import boto3
from botocore.exceptions import ClientError

def check_s3_buckets():
    s3 = boto3.client("s3")

    findings = []

    response = s3.list_buckets()

    for bucket in response["Buckets"]:
        bucket_name = bucket["Name"]

        try:
            public_access = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = public_access["PublicAccessBlockConfiguration"]

            if (
                config["BlockPublicAcls"]
                and config["IgnorePublicAcls"]
                and config["BlockPublicPolicy"]
                and config["RestrictPublicBuckets"]
            ):
                findings.append({
                    "name": f"S3 Public Access - {bucket_name}",
                    "status": "PASS",
                    "severity": "NONE",
                    "description": "All S3 public access block settings are enabled.",
                    "control": "Data Protection",
                    "reference": "AWS S3 Security Best Practices",
                    "recommendation": "No action required",
                    "remediation": "No remediation required"
                })

            else:
                findings.append({
                    "name": f"S3 Public Access - {bucket_name}",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description": "The S3 bucket may allow public access.",
                    "control": "Data Protection",
                    "reference": "AWS S3 Security Best Practices",
                    "recommendation": "Enable S3 Block Public Access unless public access is explicitly required",
                    "remediation": "Enable all four S3 Block Public Access settings"
                })

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "name": f"S3 Public Access - {bucket_name}",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "No S3 Block Public Access configuration was found.",
                "control": "Data Protection",
                "reference": "AWS S3 Security Best Practices",
                "recommendation": "Configure S3 Block Public Access",
                "remediation": "Enable all four S3 Block Public Access settings"
            })

    return findings



def check_iam_users():

    iam = boto3.client("iam")

    findings = []

    try:
        response = iam.list_users()

    except ClientError as error:

        if error.response["Error"]["Code"] == "AccessDenied":

            findings.append({
                "name": "IAM User Audit",
                "status": "ERROR",
                "severity": "HIGH",
                "description":
                    "The auditing identity does not have permission "
                    "to list IAM users.",
                "control":
                    "Identity and Access Management",
                "reference":
                    "AWS IAM Security Best Practices",
                "recommendation":
                    "Grant the auditing identity the required "
                    "read-only IAM permissions.",
                "remediation":
                    "Allow iam:ListUsers, iam:ListMFADevices, "
                    "and iam:ListAccessKeys."
            })

            return findings

        raise

    for user in response["Users"]:

        username = user["UserName"]

        # Check MFA
        mfa_response = iam.list_mfa_devices(
            UserName=username
        )

        mfa_devices = mfa_response["MFADevices"]

        if len(mfa_devices) == 0:

            findings.append({
                "name": f"IAM MFA - {username}",
                "status": "FAIL",
                "severity": "HIGH",
                "description":
                    f"IAM user {username} does not have MFA enabled.",
                "control": "Identity and Access Management",
                "reference":
                    "AWS IAM Security Best Practices",
                "recommendation":
                    "Enable MFA for the IAM user.",
                "remediation":
                    "Configure a virtual or hardware MFA device "
                    "for the IAM user."
            })

        else:

            findings.append({
                "name": f"IAM MFA - {username}",
                "status": "PASS",
                "severity": "NONE",
                "description":
                    f"IAM user {username} has MFA configured.",
                "control": "Identity and Access Management",
                "reference":
                    "AWS IAM Security Best Practices",
                "recommendation":
                    "No action required",
                "remediation":
                    "No remediation required"
            })

        # Check access keys
        keys_response = iam.list_access_keys(
            UserName=username
        )

        access_keys = keys_response["AccessKeyMetadata"]

        for key in access_keys:

            key_id = key["AccessKeyId"]
            key_status = key["Status"]

            if key_status == "Active":

                findings.append({
                    "name":
                        f"Active Access Key - {username}",
                    "status": "WARNING",
                    "severity": "MEDIUM",
                    "description":
                        f"IAM user {username} has an active "
                        f"access key ({key_id}).",
                    "control":
                        "Identity and Access Management",
                    "reference":
                        "AWS IAM Security Best Practices",
                    "recommendation":
                        "Review whether the access key is required.",
                    "remediation":
                        "Remove unused access keys and prefer "
                        "temporary credentials where possible."
                })

    if not findings:

        findings.append({
            "name": "IAM Users",
            "status": "PASS",
            "severity": "NONE",
            "description":
                "No IAM user security findings were detected.",
            "control":
                "Identity and Access Management",
            "reference":
                "AWS IAM Security Best Practices",
            "recommendation":
                "No action required",
            "remediation":
                "No remediation required"
        })

    return findings




def check_iam_users():
    iam = boto3.client("iam")
    findings = []

    # Check whether we are allowed to list IAM users
    try:
        response = iam.list_users()
    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "AccessDenied":
            return [{
                "name": "IAM User Audit",
                "status": "ERROR",
                "severity": "HIGH",
                "description": "The auditor does not have permission to list IAM users.",
                "control": "Identity and Access Management",
                "reference": "AWS IAM Security Best Practices",
                "recommendation": "Grant read-only IAM permissions to the auditing identity.",
                "remediation": "Allow iam:ListUsers, iam:ListMFADevices and iam:ListAccessKeys."
            }]

        raise

    # Analyze each IAM user
    for user in response["Users"]:
        username = user["UserName"]

        # ------------------------------
        # MFA CHECK
        # ------------------------------

        try:
            mfa_response = iam.list_mfa_devices(
                UserName=username
            )

            if len(mfa_response["MFADevices"]) == 0:
                findings.append({
                    "name": f"IAM MFA - {username}",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description": f"IAM user {username} does not have MFA enabled.",
                    "control": "Identity and Access Management",
                    "reference": "AWS IAM Security Best Practices",
                    "recommendation": "Enable MFA for the IAM user.",
                    "remediation": "Configure a virtual or hardware MFA device."
                })
            else:
                findings.append({
                    "name": f"IAM MFA - {username}",
                    "status": "PASS",
                    "severity": "NONE",
                    "description": f"IAM user {username} has MFA configured.",
                    "control": "Identity and Access Management",
                    "reference": "AWS IAM Security Best Practices",
                    "recommendation": "No action required",
                    "remediation": "No remediation required"
                })

        except ClientError:
            findings.append({
                "name": f"IAM MFA - {username}",
                "status": "ERROR",
                "severity": "MEDIUM",
                "description": "The auditor could not check MFA status.",
                "control": "Identity and Access Management",
                "reference": "AWS IAM Security Best Practices",
                "recommendation": "Grant permission to list MFA devices.",
                "remediation": "Allow iam:ListMFADevices."
            })

        # ------------------------------
        # ACCESS KEY CHECK
        # ------------------------------

        try:
            keys_response = iam.list_access_keys(
                UserName=username
            )

            for key in keys_response["AccessKeyMetadata"]:

                if key["Status"] == "Active":
                    findings.append({
                        "name": f"Active Access Key - {username}",
                        "status": "WARNING",
                        "severity": "MEDIUM",
                        "description": f"IAM user {username} has an active access key.",
                        "control": "Identity and Access Management",
                        "reference": "AWS IAM Security Best Practices",
                        "recommendation": "Review whether the access key is required.",
                        "remediation": "Remove unused access keys and prefer temporary credentials where possible."
                    })

        except ClientError:
            findings.append({
                "name": f"Access Key Audit - {username}",
                "status": "ERROR",
                "severity": "MEDIUM",
                "description": "The auditor could not check IAM access keys.",
                "control": "Identity and Access Management",
                "reference": "AWS IAM Security Best Practices",
                "recommendation": "Grant permission to list access keys.",
                "remediation": "Allow iam:ListAccessKeys."
            })

    return findings



def check_security_groups():
    ec2 = boto3.client("ec2")

    findings = []

    # Get all enabled AWS regions
    regions_response = ec2.describe_regions(
        AllRegions=False
    )

    regions = [
        region["RegionName"]
        for region in regions_response["Regions"]
    ]

    for region_name in regions:

        print(f"Scanning security groups in {region_name}...")

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

                    # All traffic exposed
                    if protocol == "-1":

                        findings.append({
                            "name": f"Security Group - {group_name}",
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
                                "Remove unrestricted Internet access.",
                            "remediation":
                                "Restrict the security group "
                                "rule to trusted IP ranges."
                        })

                    # SSH exposed
                    elif (
                        from_port == 22
                        or to_port == 22
                    ):

                        findings.append({
                            "name":
                                f"SSH exposed - {group_name}",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "description":
                                f"SSH port 22 in "
                                f"{region_name} is accessible "
                                "from the Internet.",
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

                    # RDP exposed
                    elif (
                        from_port == 3389
                        or to_port == 3389
                    ):

                        findings.append({
                            "name":
                                f"RDP exposed - {group_name}",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "description":
                                f"RDP port 3389 in "
                                f"{region_name} is accessible "
                                "from the Internet.",
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

    if not findings:

        findings.append({
            "name": "AWS Security Groups",
            "status": "PASS",
            "severity": "NONE",
            "description":
                "No unrestricted SSH, RDP, or "
                "all-traffic security group rules "
                "were detected across enabled regions.",
            "control": "Network Security",
            "reference":
                "AWS Security Best Practices",
            "recommendation":
                "No action required",
            "remediation":
                "No remediation required"
        })

    return findings



def check_security_groups():
    ec2 = boto3.client("ec2")

    findings = []

    response = ec2.describe_security_groups()

    for security_group in response["SecurityGroups"]:

        group_name = security_group["GroupName"]
        group_id = security_group["GroupId"]

        for permission in security_group.get("IpPermissions", []):

            protocol = permission.get("IpProtocol")
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            for ip_range in permission.get("IpRanges", []):

                cidr = ip_range.get("CidrIp")

                if cidr != "0.0.0.0/0":
                    continue

                if protocol == "-1":
                    findings.append({
                        "name": f"Security Group - {group_name}",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "description": f"Security group {group_id} allows all traffic from the Internet.",
                        "control": "Network Security",
                        "reference": "AWS Security Best Practices",
                        "recommendation": "Remove unrestricted Internet access.",
                        "remediation": "Restrict the security group rule to trusted IP ranges."
                    })

                elif from_port == 22 or to_port == 22:
                    findings.append({
                        "name": f"SSH exposed - {group_name}",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "description": f"SSH port 22 is accessible from the Internet.",
                        "control": "Network Security",
                        "reference": "AWS Security Best Practices",
                        "recommendation": "Restrict SSH access to trusted IP addresses.",
                        "remediation": "Replace 0.0.0.0/0 with a trusted IP/CIDR range."
                    })

                elif from_port == 3389 or to_port == 3389:
                    findings.append({
                        "name": f"RDP exposed - {group_name}",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "description": f"RDP port 3389 is accessible from the Internet.",
                        "control": "Network Security",
                        "reference": "AWS Security Best Practices",
                        "recommendation": "Restrict RDP access to trusted networks.",
                        "remediation": "Replace 0.0.0.0/0 with a trusted IP/CIDR range."
                    })

    if not findings:
        findings.append({
            "name": "AWS Security Groups",
            "status": "PASS",
            "severity": "NONE",
            "description": "No unrestricted SSH, RDP, or all-traffic security group rules were detected.",
            "control": "Network Security",
            "reference": "AWS Security Best Practices",
            "recommendation": "No action required",
            "remediation": "No remediation required"
        })

    return findings


def check_iam_privileges():
    iam = boto3.client("iam")

    findings = []

    response = iam.list_users()

    for user in response["Users"]:

        username = user["UserName"]

        # ----------------------------------------
        # Check attached managed policies
        # ----------------------------------------

        attached_response = iam.list_attached_user_policies(
            UserName=username
        )

        for policy in attached_response["AttachedPolicies"]:

            policy_name = policy["PolicyName"]
            policy_arn = policy["PolicyArn"]

            # Check for AdministratorAccess
            if policy_name == "AdministratorAccess":

                findings.append({
                    "name":
                        f"AdministratorAccess - {username}",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description":
                        f"IAM user {username} has the "
                        "AdministratorAccess managed policy.",
                    "control":
                        "Least Privilege",
                    "reference":
                        "AWS IAM Security Best Practices",
                    "recommendation":
                        "Remove AdministratorAccess unless "
                        "administrative access is explicitly required.",
                    "remediation":
                        f"Review and replace {policy_name} "
                        "with a least-privilege policy."
                })

                continue

            # Get policy metadata
            policy_response = iam.get_policy(
                PolicyArn=policy_arn
            )

            default_version = policy_response[
                "Policy"
            ]["DefaultVersionId"]

            # Get actual policy document
            version_response = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version
            )

            document = version_response[
                "PolicyVersion"
            ]["Document"]

            # Check for Action: *
            statements = document.get("Statement", [])

            if isinstance(statements, dict):
                statements = [statements]

            wildcard_action = False

            for statement in statements:

                actions = statement.get("Action", [])

                if isinstance(actions, str):
                    actions = [actions]

                if "*" in actions:
                    wildcard_action = True

            if wildcard_action:

                findings.append({
                    "name":
                        f"Wildcard Permissions - {username}",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description":
                        f"Policy {policy_name} grants "
                        "wildcard Action permissions.",
                    "control":
                        "Least Privilege",
                    "reference":
                        "AWS IAM Security Best Practices",
                    "recommendation":
                        "Replace wildcard permissions "
                        "with only required actions.",
                    "remediation":
                        "Review the policy and remove "
                        "unnecessary Action:* permissions."
                })

    if not findings:

        findings.append({
            "name": "IAM Least Privilege",
            "status": "PASS",
            "severity": "NONE",
            "description":
                "No direct IAM user policies with "
                "obvious excessive privileges were detected.",
            "control":
                "Least Privilege",
            "reference":
                "AWS IAM Security Best Practices",
            "recommendation":
                "No action required",
            "remediation":
                "No remediation required"
        })

    return findings


def check_cloudtrail():
    cloudtrail = boto3.client("cloudtrail")

    findings = []

    try:
        response = cloudtrail.describe_trails(
            includeShadowTrails=False
        )

        trails = response.get("trailList", [])

        if not trails:
            findings.append({
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
                    "Configure CloudTrail to record AWS API activity.",
                "remediation":
                    "Create and enable a CloudTrail trail."
            })

            return findings

        active_trail_found = False

        for trail in trails:

            trail_name = trail["Name"]

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
                    "name":
                        f"CloudTrail Logging - {trail_name}",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description":
                        f"CloudTrail trail {trail_name} "
                        "is configured but is not actively logging.",
                    "control":
                        "Logging and Monitoring",
                    "reference":
                        "AWS CloudTrail Security Best Practices",
                    "recommendation":
                        "Enable logging for the CloudTrail trail.",
                    "remediation":
                        f"Enable logging for trail {trail_name}."
                })

            else:

                active_trail_found = True

                if multi_region:

                    findings.append({
                        "name":
                            f"CloudTrail - {trail_name}",
                        "status": "PASS",
                        "severity": "NONE",
                        "description":
                            f"CloudTrail trail {trail_name} "
                            "is actively logging and configured "
                            "as a multi-region trail.",
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
                        "name":
                            f"CloudTrail Region Coverage - {trail_name}",
                        "status": "WARNING",
                        "severity": "MEDIUM",
                        "description":
                            f"CloudTrail trail {trail_name} "
                            "is logging but is not configured "
                            "as a multi-region trail.",
                        "control":
                            "Logging and Monitoring",
                        "reference":
                            "AWS CloudTrail Security Best Practices",
                        "recommendation":
                            "Use a multi-region CloudTrail trail "
                            "for broader visibility.",
                        "remediation":
                            "Configure the trail as multi-region."
                    })

        if not active_trail_found:

            findings.append({
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
                    "Start logging on an appropriate CloudTrail trail."
            })

    except Exception as error:

        findings.append({
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
                "Verify CloudTrail permissions and configuration.",
            "remediation":
                "Ensure the auditor has permission to inspect CloudTrail."
        })

    return findings



def check_s3_encryption():
    s3 = boto3.client("s3")

    findings = []

    response = s3.list_buckets()

    for bucket in response["Buckets"]:

        bucket_name = bucket["Name"]

        try:
            encryption = s3.get_bucket_encryption(
                Bucket=bucket_name
            )

            rules = encryption[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]

            if rules:

                findings.append({
                    "name":
                        f"S3 Encryption - {bucket_name}",
                    "status": "PASS",
                    "severity": "NONE",
                    "description":
                        "Server-side encryption is configured "
                        "for the S3 bucket.",
                    "control":
                        "Data Protection",
                    "reference":
                        "AWS S3 Security Best Practices",
                    "recommendation":
                        "No action required",
                    "remediation":
                        "No remediation required"
                })

        except s3.exceptions.ClientError as error:

            error_code = error.response[
                "Error"
            ]["Code"]

            if error_code == "ServerSideEncryptionConfigurationNotFoundError":

                findings.append({
                    "name":
                        f"S3 Encryption - {bucket_name}",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description":
                        "Server-side encryption is not "
                        "configured for the S3 bucket.",
                    "control":
                        "Data Protection",
                    "reference":
                        "AWS S3 Security Best Practices",
                    "recommendation":
                        "Enable server-side encryption.",
                    "remediation":
                        "Configure SSE-S3 or SSE-KMS encryption "
                        "for the bucket."
                })

            else:

                findings.append({
                    "name":
                        f"S3 Encryption - {bucket_name}",
                    "status": "ERROR",
                    "severity": "HIGH",
                    "description":
                        f"Unable to check encryption: {error}",
                    "control":
                        "Data Protection",
                    "reference":
                        "AWS S3 Security Best Practices",
                    "recommendation":
                        "Verify S3 permissions and configuration.",
                    "remediation":
                        "Ensure the auditor can read the bucket "
                        "encryption configuration."
                })

    if not findings:

        findings.append({
            "name": "S3 Encryption",
            "status": "PASS",
            "severity": "NONE",
            "description":
                "No S3 encryption findings were detected.",
            "control":
                "Data Protection",
            "reference":
                "AWS S3 Security Best Practices",
            "recommendation":
                "No action required",
            "remediation":
                "No remediation required"
        })

    return findings



def check_ec2_instances():
    ec2 = boto3.client("ec2")

    findings = []

    try:
        regions_response = ec2.describe_regions(
            AllRegions=False
        )

        regions = [
            region["RegionName"]
            for region in regions_response["Regions"]
        ]

    except Exception as error:

        findings.append({
            "name": "AWS Region Discovery",
            "status": "ERROR",
            "severity": "HIGH",
            "description":
                f"Unable to retrieve AWS regions: {error}",
            "control": "Cloud Security Management",
            "reference": "AWS Security Best Practices",
            "recommendation":
                "Verify that the auditor has permission "
                "to describe AWS regions.",
            "remediation":
                "Grant ec2:DescribeRegions permission."
        })

        return findings

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

                    # -------------------------------
                    # Public IPv4 check
                    # -------------------------------

                    public_ip = instance.get(
                        "PublicIpAddress"
                    )

                    if public_ip:

                        findings.append({
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
                                "Verify that direct Internet "
                                "exposure is required.",
                            "remediation":
                                "Remove unnecessary public "
                                "exposure and use private "
                                "networking where possible."
                        })

                    # -------------------------------
                    # IMDSv2 check
                    # -------------------------------

                    metadata_options = instance.get(
                        "MetadataOptions",
                        {}
                    )

                    http_tokens = metadata_options.get(
                        "HttpTokens"
                    )

                    if http_tokens != "required":

                        findings.append({
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
                                "Require IMDSv2 for the instance.",
                            "remediation":
                                "Configure the instance metadata "
                                "service to require IMDSv2."
                        })

                    else:

                        findings.append({
                            "name":
                                f"EC2 IMDSv2 - {instance_id}",
                            "status": "PASS",
                            "severity": "NONE",
                            "description":
                                f"EC2 instance {instance_id} "
                                f"in {region_name} requires IMDSv2.",
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
                "name":
                    f"EC2 Audit - {region_name}",
                "status": "ERROR",
                "severity": "HIGH",
                "description":
                    f"Unable to audit EC2 instances in "
                    f"{region_name}: {error}",
                "control":
                    "Cloud Security Management",
                "reference":
                    "AWS Security Best Practices",
                "recommendation":
                    "Verify EC2 permissions for this region.",
                "remediation":
                    "Ensure the auditor has "
                    "ec2:DescribeInstances permission."
            })

    if not findings:

        findings.append({
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
