import os
import json
import subprocess

import pandas as pd
import streamlit as st


# ========================================
# PAGE CONFIGURATION
# ========================================

st.set_page_config(
    page_title="Cloud Security Auditor",
    page_icon="🔐",
    layout="wide"
)


REPORT_FILE = "reports/audit_report.json"


# ========================================
# LOAD REPORT
# ========================================

def load_report():

    try:
        with open(REPORT_FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:
        return None

    except json.JSONDecodeError:
        return None


# ========================================
# LOAD SCAN HISTORY
# ========================================

def load_scan_history():

    history_dir = "reports/history"

    if not os.path.exists(history_dir):
        return []

    history = []

    for filename in os.listdir(history_dir):

        if not filename.endswith(".json"):
            continue

        filepath = os.path.join(
            history_dir,
            filename
        )

        try:

            with open(filepath, "r") as file:
                data = json.load(file)

            history.append(data)

        except (json.JSONDecodeError, OSError):
            continue

    history.sort(
        key=lambda x: x.get(
            "scan_time_utc",
            ""
        )
    )

    return history


# ========================================
# LOAD DATA
# ========================================

report = load_report()

if report is None:

    st.error(
        "Audit report not found. "
        "Run auditor.py first."
    )

    st.stop()


metadata = report.get(
    "scan_metadata",
    {}
)

summary = report.get(
    "risk_summary",
    {}
)

findings = report.get(
    "findings",
    []
)

score = report.get(
    "security_score",
    0
)

compliance_score = report.get(
    "compliance_score",
    0
)

history = load_scan_history()


# ========================================
# HEADER
# ========================================

st.title("🔐 Cloud Security Auditor")

st.write(
    "Linux and AWS Security Configuration "
    "Assessment Dashboard"
)

st.caption(
    f"Scan Time (UTC): "
    f"{metadata.get('scan_time_utc', 'Unknown')}"
)

st.caption(
    f"AWS Account: "
    f"{metadata.get('account_id', 'Unknown')}"
)

st.caption(
    f"Scanner Version: "
    f"{metadata.get('scanner_version', 'Unknown')}"
)


# ========================================
# RUN NEW SCAN
# ========================================

st.subheader("Security Scan")

if st.button("🔄 Run New Security Scan"):

    with st.spinner("Running security audit..."):

        result = subprocess.run(
            ["python3", "auditor.py"],
            capture_output=True,
            text=True
        )

    if result.returncode == 0:

        st.success(
            "Security scan completed successfully."
        )

        st.rerun()

    else:

        st.error(
            "Security scan failed."
        )

        if result.stderr:
            st.code(result.stderr)


# ========================================
# SECURITY OVERVIEW
# ========================================

st.subheader("Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:

    st.metric(
        "Security Score",
        f"{score}/100"
    )

with col2:

    st.metric(
        "Compliance",
        f"{compliance_score}%"
    )

with col3:

    st.metric(
        "Critical",
        summary.get(
            "critical",
            0
        )
    )

with col4:

    st.metric(
        "High",
        summary.get(
            "high",
            0
        )
    )

with col5:

    st.metric(
        "Passed",
        summary.get(
            "pass",
            0
        )
    )


st.progress(
    max(
        0,
        min(score, 100)
    ) / 100
)


# ========================================
# SCAN HISTORY
# ========================================

st.subheader("📈 Security Score History")

if history:

    history_df = pd.DataFrame(history)

    history_df["scan_time_utc"] = pd.to_datetime(
        history_df["scan_time_utc"]
    )

    history_df = history_df.sort_values(
        "scan_time_utc"
    )

    st.line_chart(
        history_df.set_index(
            "scan_time_utc"
        )["security_score"]
    )

    if len(history_df) >= 2:

        previous_score = history_df.iloc[-2][
            "security_score"
        ]

        current_score = history_df.iloc[-1][
            "security_score"
        ]

        score_change = (
            current_score -
            previous_score
        )

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Previous Score",
            previous_score
        )

        col2.metric(
            "Current Score",
            current_score
        )

        col3.metric(
            "Score Change",
            f"{score_change:+.0f}"
        )

else:

    st.info(
        "No scan history available yet."
    )


# ========================================
# DATAFRAME
# ========================================

if findings:

    df = pd.DataFrame(findings)

else:

    df = pd.DataFrame()


# ========================================
# ADD SOURCE
# ========================================

if not df.empty:

    if "finding_id" in df.columns:

        sources = []

        for finding_id in df[
            "finding_id"
        ]:

            finding_id = str(
                finding_id
            )

            if finding_id.startswith("AWS"):

                sources.append("AWS")

            elif finding_id.startswith("LINUX"):

                sources.append("Linux")

            else:

                sources.append("Other")

        df["source"] = sources


# ========================================
# SIDEBAR FILTERS
# ========================================

st.sidebar.header("🔎 Filters")


if not df.empty:

    if "severity" in df.columns:

        severities = sorted(
            df["severity"]
            .dropna()
            .unique()
            .tolist()
        )

    else:

        severities = []

    selected_severities = st.sidebar.multiselect(
        "Severity",
        severities,
        default=severities
    )


    if "source" in df.columns:

        sources = sorted(
            df["source"]
            .dropna()
            .unique()
            .tolist()
        )

    else:

        sources = []

    selected_sources = st.sidebar.multiselect(
        "Source",
        sources,
        default=sources
    )


    if "control" in df.columns:

        controls = sorted(
            df["control"]
            .dropna()
            .unique()
            .tolist()
        )

    else:

        controls = []

    selected_controls = st.sidebar.multiselect(
        "Security Control",
        controls,
        default=controls
    )


    filtered_df = df.copy()


    if "severity" in filtered_df.columns:

        filtered_df = filtered_df[
            filtered_df["severity"].isin(
                selected_severities
            )
        ]


    if "source" in filtered_df.columns:

        filtered_df = filtered_df[
            filtered_df["source"].isin(
                selected_sources
            )
        ]


    if "control" in filtered_df.columns:

        filtered_df = filtered_df[
            filtered_df["control"].isin(
                selected_controls
            )
        ]

else:

    filtered_df = df


# ========================================
# ANALYTICS
# ========================================

st.subheader("📊 Security Analytics")

if not filtered_df.empty:

    col1, col2 = st.columns(2)

    with col1:

        st.write(
            "### Findings by Severity"
        )

        if "severity" in filtered_df.columns:

            severity_counts = (
                filtered_df[
                    "severity"
                ].value_counts()
            )

            st.bar_chart(
                severity_counts
            )


    with col2:

        st.write(
            "### Findings by Source"
        )

        if "source" in filtered_df.columns:

            source_counts = (
                filtered_df[
                    "source"
                ].value_counts()
            )

            st.bar_chart(
                source_counts
            )

else:

    st.info(
        "No findings match the selected filters."
    )


# ========================================
# FINDINGS TABLE
# ========================================

st.subheader(
    f"Security Findings "
    f"({len(filtered_df)})"
)


if not filtered_df.empty:

    display_columns = [

        "finding_id",

        "name",

        "severity",

        "status",

        "source",

        "framework",

        "control_title",

        "recommendation"
    ]


    available_columns = [

        column

        for column in display_columns

        if column in filtered_df.columns
    ]


    st.dataframe(
        filtered_df[
            available_columns
        ],
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No findings match the current filters."
    )


# ========================================
# TOP RISKS
# ========================================

st.subheader(
    "🚨 Top Security Risks"
)

top_risks = report.get(
    "top_risks",
    []
)


if top_risks:

    for number, finding in enumerate(
        top_risks,
        start=1
    ):

        st.write(
            f"**{number}. "
            f"[{finding.get('severity', 'UNKNOWN')}] "
            f"{finding.get('name', 'Unknown')}**"
        )

        st.caption(
            finding.get(
                "recommendation",
                "No recommendation available"
            )
        )

else:

    st.success(
        "No significant risks detected."
    )


# ========================================
# DETAILED FINDINGS
# ========================================

st.subheader(
    "📋 Detailed Findings"
)


if not filtered_df.empty:

    for _, finding in filtered_df.iterrows():

        finding_id = finding.get(
            "finding_id",
            "UNKNOWN"
        )

        name = finding.get(
            "name",
            "Unknown"
        )

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )


        with st.expander(
            f"{finding_id} — "
            f"[{severity}] {name}"
        ):

            st.write(
                "**Status:**",
                finding.get(
                    "status",
                    "UNKNOWN"
                )
            )

            st.write(
                "**Severity:**",
                finding.get(
                    "severity",
                    "UNKNOWN"
                )
            )

            st.divider()

            st.write(
                "**Framework:**",
                finding.get(
                    "framework",
                    "Not mapped"
                )
            )

            st.write(
                "**Control:**",
                finding.get(
                    "control_title",
                    finding.get(
                        "control",
                        "Not mapped"
                    )
                )
            )

            st.write(
                "**Control Description:**",
                finding.get(
                    "control_description",
                    "N/A"
                )
            )

            st.write(
                "**Finding Description:**",
                finding.get(
                    "description",
                    "N/A"
                )
            )

            st.write(
                "**Reference:**",
                finding.get(
                    "reference",
                    "N/A"
                )
            )

            st.write(
                "**Recommendation:**",
                finding.get(
                    "recommendation",
                    "N/A"
                )
            )

            st.write(
                "**Remediation:**",
                finding.get(
                    "remediation",
                    "N/A"
                )
            )


# ========================================
# EXPORT REPORTS
# ========================================

st.subheader(
    "📥 Export Audit Report"
)

col1, col2 = st.columns(2)


try:

    with open(
        "reports/audit_report.json",
        "rb"
    ) as file:

        json_data = file.read()

    col1.download_button(
        label="Download JSON Report",
        data=json_data,
        file_name="audit_report.json",
        mime="application/json"
    )

except FileNotFoundError:

    col1.warning(
        "JSON report not found."
    )


try:

    with open(
        "reports/audit_report.csv",
        "rb"
    ) as file:

        csv_data = file.read()

    col2.download_button(
        label="Download CSV Report",
        data=csv_data,
        file_name="audit_report.csv",
        mime="text/csv"
    )

except FileNotFoundError:

    col2.warning(
        "CSV report not found."
    )


# ========================================
# HTML REPORT
# ========================================

st.subheader(
    "📄 Professional Audit Report"
)

st.write(
    "Generate a formatted HTML report "
    "from the latest audit."
)


if st.button(
    "Generate HTML Audit Report"
):

    with st.spinner(
        "Generating HTML report..."
    ):

        result = subprocess.run(
            [
                "python3",
                "report_generator.py"
            ],
            capture_output=True,
            text=True
        )


    if result.returncode == 0:

        st.success(
            "HTML report generated successfully."
        )

        try:

            with open(
                "reports/security_audit_report.html",
                "rb"
            ) as file:

                html_report = file.read()


            st.download_button(
                label="Download HTML Audit Report",
                data=html_report,
                file_name="security_audit_report.html",
                mime="text/html"
            )

        except FileNotFoundError:

            st.error(
                "HTML report file was not found."
            )

    else:

        st.error(
            "Failed to generate HTML report."
        )

        if result.stderr:

            st.code(
                result.stderr
            )


