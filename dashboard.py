import json
import pandas as pd
import streamlit as st


# ----------------------------------------
# Page configuration
# ----------------------------------------

st.set_page_config(
    page_title="Cloud Security Auditor",
    page_icon="🔐",
    layout="wide"
)


# ----------------------------------------
# Load report
# ----------------------------------------

REPORT_FILE = "reports/audit_report.json"


def load_report():

    try:

        with open(REPORT_FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:

        return None


report = load_report()


# ----------------------------------------
# Header
# ----------------------------------------

st.title("🔐 Cloud Security Auditor")

st.write(
    "Linux and AWS Security Configuration "
    "Assessment Dashboard"
)


# ----------------------------------------
# Check report
# ----------------------------------------

if report is None:

    st.error(
        "Audit report not found. "
        "Run auditor.py first."
    )

    st.stop()


# ----------------------------------------
# Extract data
# ----------------------------------------

score = report.get(
    "security_score",
    0
)

total_findings = report.get(
    "total_findings",
    0
)

summary = report.get(
    "risk_summary",
    {}
)

findings = report.get(
    "findings",
    []
)


# ----------------------------------------
# Security score
# ----------------------------------------

st.subheader("Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:

    st.metric(
        "Security Score",
        f"{score}/100"
    )

with col2:

    st.metric(
        "Critical",
        summary.get("critical", 0)
    )

with col3:

    st.metric(
        "High",
        summary.get("high", 0)
    )

with col4:

    st.metric(
        "Medium",
        summary.get("medium", 0)
    )

with col5:

    st.metric(
        "Passed",
        summary.get("pass", 0)
    )


# ----------------------------------------
# Progress bar
# ----------------------------------------

st.progress(
    score / 100
)


# ----------------------------------------
# Findings dataframe
# ----------------------------------------

st.subheader("Security Findings")

if findings:

    dataframe = pd.DataFrame(findings)

    columns = [
        "name",
        "status",
        "severity",
        "control",
        "recommendation"
    ]

    available_columns = [
        column
        for column in columns
        if column in dataframe.columns
    ]

    st.dataframe(
        dataframe[available_columns],
        use_container_width=True
    )

else:

    st.success(
        "No security findings detected."
    )


# ----------------------------------------
# Top risks
# ----------------------------------------

st.subheader("Top Security Risks")

top_risks = report.get(
    "top_risks",
    []
)

if top_risks:

    for number, finding in enumerate(
        top_risks,
        start=1
    ):

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        name = finding.get(
            "name",
            "Unknown finding"
        )

        recommendation = finding.get(
            "recommendation",
            "No recommendation available"
        )

        st.write(
            f"**{number}. [{severity}] {name}**"
        )

        st.caption(
            recommendation
        )

else:

    st.success(
        "No significant risks detected."
    )


# ----------------------------------------
# Detailed findings
# ----------------------------------------

st.subheader("Detailed Findings")

for finding in findings:

    with st.expander(
        f"{finding.get('severity', 'UNKNOWN')} — "
        f"{finding.get('name', 'Unknown')}"
    ):

        st.write(
            "**Status:**",
            finding.get("status", "UNKNOWN")
        )

        st.write(
            "**Description:**",
            finding.get(
                "description",
                "No description available"
            )
        )

        st.write(
            "**Control:**",
            finding.get(
                "control",
                "Not specified"
            )
        )

        st.write(
            "**Reference:**",
            finding.get(
                "reference",
                "Not specified"
            )
        )

        st.write(
            "**Recommendation:**",
            finding.get(
                "recommendation",
                "No recommendation available"
            )
        )

        st.write(
            "**Remediation:**",
            finding.get(
                "remediation",
                "No remediation available"
            )
        )

