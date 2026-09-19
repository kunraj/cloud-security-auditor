import json
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


# ========================================
# REPORT FILE
# ========================================

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

        st.error("audit_report.json contains invalid JSON.")

        return None


# ========================================
# LOAD DATA
# ========================================

report = load_report()


# ========================================
# HEADER
# ========================================

st.title("🔐 Cloud Security Auditor")

st.write(
    "Linux and AWS Security Configuration Assessment"
)


# ========================================
# CHECK REPORT
# ========================================

if report is None:

    st.error(
        "Audit report not found. "
        "Run 'python3 auditor.py' first."
    )

    st.stop()


# ========================================
# REPORT DATA
# ========================================

score = report.get(
    "security_score",
    0
)

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


# ========================================
# SCAN INFORMATION
# ========================================

st.caption(
    "Scan Time (UTC): "
    + str(
        metadata.get(
            "scan_time_utc",
            "Not available"
        )
    )
)

st.caption(
    "AWS Account: "
    + str(
        metadata.get(
            "account_id",
            "Not available"
        )
    )
)

st.caption(
    "Scanner Version: "
    + str(
        metadata.get(
            "scanner_version",
            "1.0"
        )
    )
)


# ========================================
# DATAFRAME
# ========================================

df = pd.DataFrame(findings)


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
        "Critical",
        summary.get(
            "critical",
            0
        )
    )


with col3:

    st.metric(
        "High",
        summary.get(
            "high",
            0
        )
    )


with col4:

    st.metric(
        "Medium",
        summary.get(
            "medium",
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
        min(
            int(score),
            100
        )
    ) / 100
)


# ========================================
# SIDEBAR FILTERS
# ========================================

st.sidebar.header("🔎 Filters")


if not df.empty:

    # ------------------------------------
    # Make sure required columns exist
    # ------------------------------------

    if "severity" not in df.columns:
        df["severity"] = "UNKNOWN"

    if "control" not in df.columns:
        df["control"] = "Unknown"

    if "finding_id" not in df.columns:
        df["finding_id"] = "UNKNOWN"


    # ------------------------------------
    # Determine source
    # ------------------------------------

    sources = []

    for finding_id in df["finding_id"]:

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


    # ------------------------------------
    # Severity filter
    # ------------------------------------

    severities = sorted(
        df["severity"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    selected_severities = st.sidebar.multiselect(
        "Severity",
        severities,
        default=severities
    )


    # ------------------------------------
    # Source filter
    # ------------------------------------

    available_sources = sorted(
        df["source"]
        .unique()
        .tolist()
    )

    selected_sources = st.sidebar.multiselect(
        "Source",
        available_sources,
        default=available_sources
    )


    # ------------------------------------
    # Control filter
    # ------------------------------------

    controls = sorted(
        df["control"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    selected_controls = st.sidebar.multiselect(
        "Security Control",
        controls,
        default=controls
    )


    # ------------------------------------
    # Apply filters
    # ------------------------------------

    filtered_df = df[
        df["severity"]
        .astype(str)
        .isin(selected_severities)
        &
        df["source"]
        .isin(selected_sources)
        &
        df["control"]
        .astype(str)
        .isin(selected_controls)
    ]

else:

    filtered_df = df


# ========================================
# SECURITY ANALYTICS
# ========================================

st.subheader("Security Analytics")


if not filtered_df.empty:

    col1, col2 = st.columns(2)


    with col1:

        st.write(
            "### Findings by Severity"
        )

        severity_counts = (
            filtered_df[
                "severity"
            ]
            .value_counts()
        )

        st.bar_chart(
            severity_counts
        )


    with col2:

        st.write(
            "### Findings by Source"
        )

        source_counts = (
            filtered_df[
                "source"
            ]
            .value_counts()
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
    f"Security Findings ({len(filtered_df)})"
)


if not filtered_df.empty:

    columns = [
        "finding_id",
        "name",
        "source",
        "status",
        "severity",
        "control",
        "recommendation"
    ]

    available_columns = [
        column
        for column in columns
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
            f"{finding_id} "
            f"[{severity}] "
            f"{name}**"
        )

        st.caption(
            recommendation
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
