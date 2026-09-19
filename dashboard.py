import json
import os

import pandas as pd
import streamlit as st


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cloud Security Auditor",
    page_icon="🔐",
    layout="wide"
)


REPORT_FILE = "reports/audit_report.json"


# ============================================================
# LOAD REPORT
# ============================================================

def load_report():

    if not os.path.exists(REPORT_FILE):
        return None

    try:

        with open(REPORT_FILE, "r") as file:
            return json.load(file)

    except json.JSONDecodeError:

        return None


report = load_report()


# ============================================================
# HEADER
# ============================================================

st.title("🔐 Cloud Security Auditor")

st.caption(
    "Linux and AWS Security Configuration "
    "Assessment Dashboard"
)


# ============================================================
# REPORT VALIDATION
# ============================================================

if report is None:

    st.error(
        "Audit report not found or is invalid."
    )

    st.info(
        "Run the auditor first:"
    )

    st.code(
        "python3 auditor.py"
    )

    st.stop()


# ============================================================
# REPORT DATA
# ============================================================

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


# ============================================================
# SECURITY OVERVIEW
# ============================================================

st.header("Security Overview")

col1, col2, col3, col4, col5, col6 = st.columns(6)

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

with col6:

    st.metric(
        "Errors",
        summary.get("error", 0)
    )


st.progress(
    max(0, min(score, 100)) / 100
)


st.caption(
    f"Total findings: {total_findings}"
)


# ============================================================
# FINDINGS DATAFRAME
# ============================================================

st.header("Security Findings")


if findings:

    dataframe = pd.DataFrame(findings)

    # Make sure expected columns exist
    expected_columns = [
        "finding_id",
        "name",
        "status",
        "severity",
        "control",
        "reference",
        "description",
        "recommendation",
        "remediation"
    ]

    for column in expected_columns:

        if column not in dataframe.columns:
            dataframe[column] = ""

    # --------------------------------------------------------
    # Filters
    # --------------------------------------------------------

    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:

        severity_options = [
            "ALL",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "NONE"
        ]

        selected_severity = st.selectbox(
            "Filter by Severity",
            severity_options
        )

    with filter_col2:

        status_options = [
            "ALL"
        ] + sorted(
            dataframe["status"].dropna().unique().tolist()
        )

        selected_status = st.selectbox(
            "Filter by Status",
            status_options
        )

    with filter_col3:

        control_options = [
            "ALL"
        ] + sorted(
            dataframe["control"].dropna().unique().tolist()
        )

        selected_control = st.selectbox(
            "Filter by Control",
            control_options
        )

    # --------------------------------------------------------
    # Apply filters
    # --------------------------------------------------------

    filtered_df = dataframe.copy()

    if selected_severity != "ALL":

        filtered_df = filtered_df[
            filtered_df["severity"]
            == selected_severity
        ]

    if selected_status != "ALL":

        filtered_df = filtered_df[
            filtered_df["status"]
            == selected_status
        ]

    if selected_control != "ALL":

        filtered_df = filtered_df[
            filtered_df["control"]
            == selected_control
        ]

    # --------------------------------------------------------
    # Display table
    # --------------------------------------------------------

    display_columns = [
        "finding_id",
        "name",
        "status",
        "severity",
        "control",
        "recommendation"
    ]

    st.dataframe(
        filtered_df[display_columns],
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        f"Showing {len(filtered_df)} of "
        f"{len(dataframe)} findings"
    )

else:

    st.success(
        "No security findings detected."
    )


# ============================================================
# SEVERITY ANALYSIS
# ============================================================

st.header("Severity Analysis")

severity_data = {
    "Critical": summary.get("critical", 0),
    "High": summary.get("high", 0),
    "Medium": summary.get("medium", 0),
    "Low": summary.get("low", 0),
    "Passed": summary.get("pass", 0)
}

severity_df = pd.DataFrame(
    {
        "Severity": severity_data.keys(),
        "Count": severity_data.values()
    }
)

st.bar_chart(
    severity_df.set_index("Severity")
)


# ============================================================
# CONTROL ANALYSIS
# ============================================================

if findings:

    st.header("Findings by Security Control")

    control_counts = (
        dataframe["control"]
        .value_counts()
    )

    st.bar_chart(
        control_counts
    )


# ============================================================
# TOP RISKS
# ============================================================

st.header("Top Security Risks")

top_risks = report.get(
    "top_risks",
    []
)

if top_risks:

    for number, finding in enumerate(
        top_risks,
        start=1
    ):

        finding_id = finding.get(
            "finding_id",
            "UNKNOWN"
        )

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
            f"**{number}. "
            f"[{severity}] "
            f"{finding_id} — {name}**"
        )

        st.caption(
            recommendation
        )

else:

    st.success(
        "No significant risks detected."
    )


# ============================================================
# DETAILED FINDINGS
# ============================================================

st.header("Detailed Findings")

if findings:

    for finding in findings:

        finding_id = finding.get(
            "finding_id",
            "UNKNOWN"
        )

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        name = finding.get(
            "name",
            "Unknown finding"
        )

        with st.expander(
            f"[{severity}] "
            f"{finding_id} — {name}"
        ):

            st.write(
                "**Status:**",
                finding.get(
                    "status",
                    "UNKNOWN"
                )
            )

            st.write(
                "**Description:**",
                finding.get(
                    "description",
                    "No description available"
                )
            )

            st.write(
                "**Security Control:**",
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

else:

    st.success(
        "No detailed findings available."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Cloud Security Auditor | "
    "Read-only security configuration assessment"
)
