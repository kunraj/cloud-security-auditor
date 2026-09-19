CIS_CONTROLS = {
    "LINUX-001": {
        "framework": "CIS",
        "control": "Network Security",
        "title": "Host Firewall Configuration",
        "description": "Ensure a host-based firewall is enabled and configured."
    },

    "LINUX-002": {
        "framework": "CIS",
        "control": "SSH Hardening",
        "title": "Disable Direct Root SSH Login",
        "description": "Prevent direct remote login using the root account."
    },

    "LINUX-003": {
        "framework": "CIS",
        "control": "Account Management",
        "title": "Privileged Account Review",
        "description": "Review accounts with privileged UID 0 access."
    },

    "LINUX-004": {
        "framework": "CIS",
        "control": "File Permissions",
        "title": "Protect Sensitive Authentication Files",
        "description": "Ensure sensitive authentication files have restrictive permissions."
    },

    "LINUX-005": {
        "framework": "CIS",
        "control": "Network Services",
        "title": "Minimize Unnecessary Listening Services",
        "description": "Identify unnecessary network services exposed on the host."
    },

    "AWS-S3-001": {
        "framework": "CIS AWS Foundations",
        "control": "S3 Public Access",
        "title": "S3 Public Access Protection",
        "description": "Ensure S3 buckets have appropriate public-access restrictions."
    },

    "AWS-S3-002": {
        "framework": "CIS AWS Foundations",
        "control": "S3 Data Protection",
        "title": "S3 Server-Side Encryption",
        "description": "Protect stored S3 data using server-side encryption."
    },

    "AWS-SG-001": {
        "framework": "CIS AWS Foundations",
        "control": "Network Security",
        "title": "Restrict Unrestricted Security Groups",
        "description": "Avoid unrestricted inbound access to security groups."
    },

    "AWS-SG-002": {
        "framework": "CIS AWS Foundations",
        "control": "Network Security",
        "title": "Restrict SSH Access",
        "description": "Avoid unrestricted SSH access from the public internet."
    },

    "AWS-SG-003": {
        "framework": "CIS AWS Foundations",
        "control": "Network Security",
        "title": "Restrict RDP Access",
        "description": "Avoid unrestricted RDP access from the public internet."
    },

    "AWS-IAM-001": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Authentication",
        "title": "Multi-Factor Authentication",
        "description": "Require MFA for IAM users where applicable."
    },

    "AWS-IAM-002": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Credentials",
        "title": "Access Key Management",
        "description": "Review and manage active IAM access keys."
    },

    "AWS-IAM-003": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Privileges",
        "title": "Avoid Excessive Administrator Privileges",
        "description": "Review unnecessary AdministratorAccess permissions."
    },

    "AWS-IAM-004": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Privileges",
        "title": "Avoid Wildcard IAM Permissions",
        "description": "Review policies granting unrestricted actions."
    },

    "AWS-IAM-005": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Groups",
        "title": "Review Administrative Group Permissions",
        "description": "Review administrator permissions attached to IAM groups."
    },

    "AWS-IAM-006": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Groups",
        "title": "Review Wildcard Group Permissions",
        "description": "Review wildcard permissions attached through IAM groups."
    },

    "AWS-IAM-007": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Trust Policies",
        "title": "Review Broad Role Trust Policies",
        "description": "Review IAM roles with broad or wildcard trust relationships."
    },

    "AWS-IAM-008": {
        "framework": "CIS AWS Foundations",
        "control": "IAM Roles",
        "title": "Review Administrative Role Permissions",
        "description": "Review IAM roles with AdministratorAccess."
    },

    "AWS-CT-001": {
        "framework": "CIS AWS Foundations",
        "control": "Logging and Monitoring",
        "title": "CloudTrail Configuration",
        "description": "Ensure AWS CloudTrail is configured."
    },

    "AWS-CT-002": {
        "framework": "CIS AWS Foundations",
        "control": "Logging and Monitoring",
        "title": "CloudTrail Logging",
        "description": "Ensure CloudTrail is actively recording API activity."
    },

    "AWS-CT-003": {
        "framework": "CIS AWS Foundations",
        "control": "Logging and Monitoring",
        "title": "Multi-Region CloudTrail",
        "description": "Review CloudTrail coverage across AWS regions."
    },

    "AWS-EC2-001": {
        "framework": "CIS AWS Foundations",
        "control": "EC2 Network Exposure",
        "title": "Public EC2 Exposure",
        "description": "Identify EC2 instances with public IP addresses."
    },

    "AWS-EC2-002": {
        "framework": "CIS AWS Foundations",
        "control": "EC2 Instance Metadata",
        "title": "Require IMDSv2",
        "description": "Require Instance Metadata Service Version 2 where supported."
    }
}
