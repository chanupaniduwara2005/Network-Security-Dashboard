"""SentinelSOC - Mini SOC Alert Dashboard
Educational Security Operations Center (SOC) dashboard.

Phase 6: Alert Investigation, Checklist Triage & State Persistence.
"""

import json
from pathlib import Path
from typing import Optional

import pandas as pd
import plotly.express as px
import streamlit as st

from src.detection_engine import Alert, DetectionConfig, DetectionEngine
from src.log_parser import LogParserResult, parse_log_file
from src.triage_manager import DEFAULT_CHECKLIST, TriageManager, TriageRecord, VALID_STATUSES
from src.dashboard_utils import (
    PALETTE,
    apply_dark_theme,
    compare_time_periods,
    create_alert_status_distribution_chart,
    create_alerts_severity_donut,
    create_detection_rule_frequency_chart,
    create_events_by_type_bar,
    create_events_timeline_chart,
    create_failed_logins_trend_chart,
    create_repeated_failure_ips_chart,
    create_top_failed_ips_bar,
    create_top_targeted_users_chart,
    generate_dataset_summary,
)
from src.report_generator import (
    export_alerts_to_csv,
    export_events_to_csv,
    generate_structured_json_report,
    sanitize_source_name,
)

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="SentinelSOC | SOC Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# Session State & Persistence Initialization
# ---------------------------------------------------------
if "triage_manager" not in st.session_state:
    st.session_state["triage_manager"] = TriageManager()

if "parser_result" not in st.session_state:
    st.session_state["parser_result"] = None

if "source_name" not in st.session_state:
    st.session_state["source_name"] = "None"

if "alerts" not in st.session_state:
    st.session_state["alerts"] = []

if "detection_engine" not in st.session_state:
    st.session_state["detection_engine"] = DetectionEngine()

if "nav_page" not in st.session_state:
    st.session_state["nav_page"] = "Overview"

if "selected_investigate_alert_id" not in st.session_state:
    st.session_state["selected_investigate_alert_id"] = None


def run_detections_on_current_logs():
    """Run detection engine on active valid events, sync with persistent triage state, and save."""
    parser_res: Optional[LogParserResult] = st.session_state.get("parser_result")
    if parser_res and parser_res.has_data:
        engine: DetectionEngine = st.session_state["detection_engine"]
        alerts = engine.detect_all(parser_res.valid_df)
        # Synchronize with persistent triage records (notes, status, checklists)
        triage_mgr: TriageManager = st.session_state["triage_manager"]
        triage_mgr.sync_alerts(alerts)
        st.session_state["alerts"] = alerts
    else:
        st.session_state["alerts"] = []


# ---------------------------------------------------------
# Sidebar: Navigation & Data Ingestion
# ---------------------------------------------------------
st.sidebar.title("🛡️ SentinelSOC")
st.sidebar.caption("Security Operations Center Dashboard")

nav_options = ["Overview", "Security Events", "Alerts", "Analytics", "Reports"]
selected_page = st.sidebar.radio(
    "Navigation",
    options=nav_options,
    index=nav_options.index(st.session_state.get("nav_page", "Overview")),
    key="nav_selection_radio",
)
st.session_state["nav_page"] = selected_page

st.sidebar.divider()
st.sidebar.subheader("📥 Log Ingestion")

sample_file_path = Path(__file__).resolve().parent / "data" / "sample_security_logs.csv"

# Button to load the built-in synthetic dataset
if sample_file_path.exists():
    if st.sidebar.button("📂 Load Built-in Sample Logs", use_container_width=True):
        with st.spinner("Parsing logs & evaluating correlation rules..."):
            result = parse_log_file(sample_file_path)
            st.session_state["parser_result"] = result
            st.session_state["source_name"] = "sample_security_logs.csv (Built-in)"
            run_detections_on_current_logs()
        st.sidebar.success(f"Loaded {result.accepted_count} events!")
        st.rerun()

# File uploader widget for user-supplied logs
uploaded_file = st.sidebar.file_uploader(
    "Upload Log File (CSV or JSON)",
    type=["csv", "json", "ndjson"],
    help="Upload authentication logs in CSV, JSON array, or JSON Lines format.",
)

if uploaded_file is not None:
    if st.sidebar.button("⚡ Ingest Uploaded File", use_container_width=True):
        with st.spinner("Validating, normalizing, and analyzing events..."):
            result = parse_log_file(uploaded_file, filename=uploaded_file.name)
            st.session_state["parser_result"] = result
            st.session_state["source_name"] = uploaded_file.name
            run_detections_on_current_logs()
        st.sidebar.success(f"Parsed {result.accepted_count} valid events!")
        st.rerun()

st.sidebar.divider()
st.sidebar.markdown(f"**Source:** `{st.session_state['source_name']}`")
if st.session_state["alerts"]:
    st.sidebar.markdown(f"**Triggered Alerts:** `{len(st.session_state['alerts'])}`")

if st.session_state["source_name"] != "None":
    if st.sidebar.button("🗑️ Clear Active Data", use_container_width=True):
        st.session_state["parser_result"] = None
        st.session_state["source_name"] = "None"
        st.session_state["alerts"] = []
        st.session_state["selected_investigate_alert_id"] = None
        st.rerun()

# ---------------------------------------------------------
# Helper Rendering Functions
# ---------------------------------------------------------
def render_empty_state(page_title: str):
    """Render a helpful empty state when no dataset is loaded."""
    st.subheader(f"📌 {page_title}")
    with st.container(border=True):
        st.info("ℹ️ **No security log dataset is currently active.**")
        st.markdown(
            """
            To populate this view with live security operations metrics:
            1. Click **'📂 Load Built-in Sample Logs'** in the left sidebar to analyze 55 synthetic events.
            2. Or upload your own **CSV**, **JSON**, or **JSON Lines (NDJSON)** security logs.
            """
        )


parser_result: Optional[LogParserResult] = st.session_state.get("parser_result")
events_df: pd.DataFrame = parser_result.valid_df if (parser_result and parser_result.has_data) else pd.DataFrame()
alerts_list: list[Alert] = st.session_state.get("alerts", [])
triage_mgr: TriageManager = st.session_state["triage_manager"]


# =========================================================
# PAGE 1: OVERVIEW
# =========================================================
if selected_page == "Overview":
    st.title("🛡️ SentinelSOC — Security Operations Center")
    st.caption("Live security monitoring, alert correlation, and incident triage.")

    if events_df.empty:
        render_empty_state("Operations Center Overview")
    else:
        # Calculate Live Metrics
        total_events = len(events_df)
        failed_logins = len(events_df[(events_df["status"] == "FAILED") & (events_df["event_type"].str.contains("LOGIN", na=False))])
        successful_logins = len(events_df[(events_df["status"] == "SUCCESS") & (events_df["event_type"].str.contains("LOGIN", na=False))])
        total_alerts = len(alerts_list)
        open_alerts = sum(1 for a in alerts_list if a.status in {"Open", "Investigating", "NEW", "UNDER_INVESTIGATION"})
        crit_high_alerts = sum(1 for a in alerts_list if a.severity in {"CRITICAL", "HIGH"})

        # Top Live KPI Metric Cards
        kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)
        kpi1.metric("Total Events", f"{total_events:,}")
        kpi2.metric("Failed Logins", f"{failed_logins:,}", delta=f"{failed_logins} failed" if failed_logins > 0 else None, delta_color="inverse")
        kpi3.metric("Successful Logins", f"{successful_logins:,}")
        kpi4.metric("Generated Alerts", f"{total_alerts}")
        kpi5.metric("Open Alerts", f"{open_alerts}", delta="Pending Triage" if open_alerts > 0 else "All Resolved", delta_color="inverse" if open_alerts > 0 else "normal")
        kpi6.metric("Critical / High", f"{crit_high_alerts}", delta="Urgent" if crit_high_alerts > 0 else "Normal", delta_color="inverse" if crit_high_alerts > 0 else "normal")

        st.divider()

        # Evidence-Based Dataset Synthesis
        st.subheader("📋 Dataset Threat Synthesis")
        st.markdown(generate_dataset_summary(events_df, alerts_list))

        st.divider()

        # Visual Charts Row 1: Timeline & Severity Donut
        c1, c2 = st.columns([2, 1])
        with c1:
            timeline_fig = create_events_timeline_chart(events_df)
            if timeline_fig:
                st.plotly_chart(timeline_fig, use_container_width=True)
        with c2:
            donut_fig = create_alerts_severity_donut(alerts_list)
            if donut_fig:
                st.plotly_chart(donut_fig, use_container_width=True)
            else:
                st.info("No active alerts triggered in current dataset.")

        # Visual Charts Row 2: Event Types & Top Offending IPs
        c3, c4 = st.columns(2)
        with c3:
            event_type_fig = create_events_by_type_bar(events_df)
            if event_type_fig:
                st.plotly_chart(event_type_fig, use_container_width=True)
        with c4:
            top_ips_fig = create_top_failed_ips_bar(events_df)
            if top_ips_fig:
                st.plotly_chart(top_ips_fig, use_container_width=True)
            else:
                st.info("Zero failed logins recorded.")

        st.divider()

        # Recent Alerts Section
        st.subheader("🚨 Recent Correlated Alerts")
        if alerts_list:
            recent_alerts_df = pd.DataFrame([
                {
                    "Alert ID": a.alert_id,
                    "Severity": a.severity,
                    "Rule Name": a.rule_name,
                    "Target User": a.username or "N/A",
                    "Origin IP(s)": ", ".join(a.source_ips),
                    "Events": a.event_count,
                    "Observed Time": a.first_seen,
                    "Status": a.status,
                }
                for a in alerts_list[:5]
            ])
            st.dataframe(recent_alerts_df, use_container_width=True, hide_index=True)
        else:
            st.success("✅ Clean baseline: No active threat alerts detected.")


# =========================================================
# PAGE 2: SECURITY EVENTS
# =========================================================
elif selected_page == "Security Events":
    st.title("📋 Security Events Log Explorer")
    st.caption("Normalized authentication, host, and perimeter security records.")

    if events_df.empty:
        render_empty_state("Security Events Log Explorer")
    else:
        # Ingestion Quality & Quarantine Banner
        if parser_result and (parser_result.warnings or parser_result.rejected_records):
            with st.expander(f"⚠️ Ingestion Health & Quarantined Records ({parser_result.rejected_count} rejected)"):
                for w in parser_result.warnings:
                    st.warning(w)
                if parser_result.rejected_records:
                    st.dataframe(
                        pd.DataFrame([
                            {
                                "Row": r.get("row_index", "N/A"),
                                "Event ID": r.get("event_id", "Missing"),
                                "Reason": r.get("reason", "Validation failure"),
                                "Raw": str(r.get("raw", ""))[:120] + "...",
                            }
                            for r in parser_result.rejected_records
                        ]),
                        use_container_width=True,
                        hide_index=True,
                    )

        # Filters Bar
        st.subheader("🔍 Search & Filter Records")
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            all_statuses = sorted(events_df["status"].unique().tolist())
            status_filter = st.multiselect("Status", options=all_statuses, default=[])
        with col_f2:
            all_types = sorted(events_df["event_type"].unique().tolist())
            type_filter = st.multiselect("Event Type", options=all_types, default=[])
        with col_f3:
            search_query = st.text_input("Search Username, IP, or Message", placeholder="e.g. admin, 198.51.100, failed")

        # Date range filter
        min_ts = events_df["timestamp"].min().date()
        max_ts = events_df["timestamp"].max().date()
        date_col1, date_col2 = st.columns([2, 1])
        with date_col1:
            date_range = st.date_input(
                "Filter Date Range (UTC)",
                value=(min_ts, max_ts),
                min_value=min_ts,
                max_value=max_ts,
            )
        with date_col2:
            st.write("")
            st.write("")
            reset_button = st.button("🔄 Reset All Filters")

        if reset_button:
            status_filter = []
            type_filter = []
            search_query = ""
            st.rerun()

        # Apply Filters to events
        filtered_df = events_df.copy()
        if status_filter:
            filtered_df = filtered_df[filtered_df["status"].isin(status_filter)]
        if type_filter:
            filtered_df = filtered_df[filtered_df["event_type"].isin(type_filter)]
        if isinstance(date_range, tuple) and len(date_range) == 2:
            start_date, end_date = date_range
            filtered_df = filtered_df[
                (filtered_df["timestamp"].dt.date >= start_date)
                & (filtered_df["timestamp"].dt.date <= end_date)
            ]
        if search_query:
            q = search_query.strip().lower()
            filtered_df = filtered_df[
                filtered_df["username"].str.lower().str.contains(q, na=False)
                | filtered_df["source_ip"].str.lower().str.contains(q, na=False)
                | filtered_df["destination_ip"].str.lower().str.contains(q, na=False)
                | filtered_df["message"].str.lower().str.contains(q, na=False)
                | filtered_df["event_id"].str.lower().str.contains(q, na=False)
            ]

        st.caption(f"Showing **{len(filtered_df):,}** of **{len(events_df):,}** accepted events")

        # Interactive Table
        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss"),
                "event_id": st.column_config.TextColumn("Event ID"),
                "status": st.column_config.TextColumn("Status"),
                "source_ip": st.column_config.TextColumn("Source IP"),
                "destination_ip": st.column_config.TextColumn("Dest IP"),
                "event_type": st.column_config.TextColumn("Event Type"),
                "username": st.column_config.TextColumn("Username"),
                "hostname": st.column_config.TextColumn("Host"),
                "message": st.column_config.TextColumn("Details"),
            },
        )

        st.divider()

        # Expandable Event Deep Inspector
        st.subheader("🔬 Single Event Inspector")
        event_options = filtered_df["event_id"].tolist()
        if event_options:
            selected_event_id = st.selectbox("Select Event ID to Inspect:", options=event_options[:100])
            matched_event = filtered_df[filtered_df["event_id"] == selected_event_id].iloc[0]

            linked_alerts = [
                a.alert_id for a in alerts_list
                if selected_event_id in a.related_event_ids
            ]

            with st.container(border=True):
                insp1, insp2, insp3 = st.columns(3)
                insp1.markdown(f"**Event ID:** `{matched_event['event_id']}`")
                insp1.markdown(f"**Timestamp (UTC):** `{matched_event['timestamp']}`")
                insp1.markdown(f"**Event Type:** `{matched_event['event_type']}`")

                insp2.markdown(f"**User Account:** `{matched_event['username']}`")
                insp2.markdown(f"**Source IP:** `{matched_event['source_ip']}`")
                insp2.markdown(f"**Destination IP:** `{matched_event['destination_ip'] or 'N/A'}`")

                insp3.markdown(f"**Status:** `{matched_event['status']}`")
                insp3.markdown(f"**Hostname:** `{matched_event['hostname']}`")
                if linked_alerts:
                    insp3.markdown(f"**⚠️ Linked Alert(s):** `{', '.join(linked_alerts)}`")
                else:
                    insp3.markdown("**Linked Alerts:** `None (Benign / Uncorrelated)`")

                st.markdown(f"**Description / Message:** `{matched_event['message']}`")


# =========================================================
# PAGE 3: ALERTS & INVESTIGATION WORKFLOW
# =========================================================
elif selected_page == "Alerts":
    st.title("🚨 Incident Alerts Triage Queue & Investigation")
    st.caption("Correlated security incidents categorized by severity, with analyst investigation and checklist workflows.")

    if not alerts_list:
        if events_df.empty:
            render_empty_state("Incident Alerts Triage")
        else:
            st.success("✅ Clean baseline: No suspicious activity detected in the active log dataset.")
    else:
        # Severity Metric Counters
        s1, s2, s3, s4, s5 = st.columns(5)
        s1.metric("🔴 Critical", sum(1 for a in alerts_list if a.severity == "CRITICAL"))
        s2.metric("🟠 High", sum(1 for a in alerts_list if a.severity == "HIGH"))
        s3.metric("🟡 Medium", sum(1 for a in alerts_list if a.severity == "MEDIUM"))
        s4.metric("🔵 Low", sum(1 for a in alerts_list if a.severity == "LOW"))
        s5.metric("⚪ Info", sum(1 for a in alerts_list if a.severity == "INFORMATIONAL"))

        st.divider()

        # Dedicated Detailed Investigation Panel
        st.subheader("🔎 Detailed Alert Investigation Workspace")

        # Dropdown to choose which alert to investigate in detail
        alert_choice_map = {
            f"{a.alert_id} | [{a.severity}] {a.rule_name} (User: {a.username or 'N/A'})": a.alert_id
            for a in alerts_list
        }
        choice_keys = list(alert_choice_map.keys())

        # If a specific alert was chosen previously, find its index
        default_idx = 0
        current_investigate_id = st.session_state.get("selected_investigate_alert_id")
        if current_investigate_id:
            for idx, key_str in enumerate(choice_keys):
                if current_investigate_id in key_str:
                    default_idx = idx
                    break

        selected_label = st.selectbox(
            "Select Alert to Investigate:",
            options=choice_keys,
            index=default_idx,
            help="Select an alert to view its underlying chronological log evidence and update investigation state.",
        )
        active_alert_id = alert_choice_map[selected_label]
        st.session_state["selected_investigate_alert_id"] = active_alert_id
        active_alert = next((a for a in alerts_list if a.alert_id == active_alert_id), alerts_list[0])
        active_triage_rec = triage_mgr.get_record(active_alert.alert_id)

        # Investigation Workspace Container
        with st.container(border=True):
            inv_col1, inv_col2 = st.columns([2, 1])
            with inv_col1:
                st.markdown(f"### 🛡️ Investigating: `{active_alert.rule_name}`")
                st.caption(
                    f"**Alert ID:** `{active_alert.alert_id}` | "
                    f"**Severity:** `{active_alert.severity}` | "
                    f"**Confidence:** `{active_alert.confidence}` | "
                    f"**Target Account:** `{active_alert.username or 'N/A'}` | "
                    f"**Origin IP(s):** `{', '.join(active_alert.source_ips)}`"
                )
            with inv_col2:
                # Active Status Badge
                status_color = {
                    "Open": "🔴",
                    "Investigating": "🟡",
                    "Resolved": "🟢",
                    "False Positive": "⚪",
                }.get(active_triage_rec.status, "🔵")
                st.markdown(f"**Current Triage Status:** {status_color} `{active_triage_rec.status}`")
                st.caption(f"Last updated: {active_triage_rec.updated_at}")

            # Distinction between Recorded Facts and Suggested Explanations
            tab_evidence, tab_hypothesis, tab_workflow = st.tabs([
                "📊 Chronological Evidence (Recorded Facts)",
                "🧠 Detection Analysis (Suggested Explanation)",
                "📝 Analyst Checklist & Notes",
            ])

            # TAB 1: RECORDED FACTS (Log Events & Sequence)
            with tab_evidence:
                st.markdown("> **Verified Log Facts:** The table and timeline below represent unedited log records extracted from the ingested security stream.")

                evidence_events = events_df[events_df["event_id"].isin(active_alert.related_event_ids)].sort_values("timestamp")
                if not evidence_events.empty:
                    # Chronological event sequence table
                    st.dataframe(
                        evidence_events[[
                            "timestamp", "event_id", "status", "username", "source_ip", "destination_ip", "event_type", "message"
                        ]],
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "timestamp": st.column_config.DatetimeColumn("Timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss"),
                        },
                    )

                    # Evidence Timeline visualization
                    if len(evidence_events) > 1:
                        ev_fig = px.scatter(
                            evidence_events,
                            x="timestamp",
                            y="status",
                            color="status",
                            hover_data=["event_id", "username", "source_ip", "message"],
                            title="Chronological Evidence Progression",
                            color_discrete_map={
                                "SUCCESS": PALETTE["success"],
                                "FAILED": PALETTE["failed"],
                                "BLOCKED": PALETTE["blocked"],
                            },
                        )
                        st.plotly_chart(apply_dark_theme(ev_fig), use_container_width=True)
                else:
                    st.info(f"Evidence event IDs: {', '.join(active_alert.related_event_ids)}")

            # TAB 2: SUGGESTED EXPLANATIONS
            with tab_hypothesis:
                st.markdown("> **Detection Rationale:** The following assessment is a rule-based hypothesis to assist triage, not an automatic proof of malicious intent.")
                st.write(active_alert.explanation)

                if active_alert.severity_justification:
                    st.markdown("#### ⚖️ Severity Evaluation Factors:")
                    for j in active_alert.severity_justification:
                        st.markdown(f"- {j}")

                st.markdown("#### 🛡️ Recommended Triage Checklist Guidance:")
                for i, step in enumerate(active_alert.recommended_steps, start=1):
                    st.markdown(f"{i}. {step}")

            # TAB 3: ANALYST WORKFLOW & CHECKLIST
            with tab_workflow:
                st.markdown("#### 📋 Investigation Checklist")
                st.caption("*Investigation suggestions to guide triage, not automatic conclusions.*")

                # Checklist checkboxes
                updated_checklist = {}
                for item in DEFAULT_CHECKLIST:
                    current_checked = active_triage_rec.checklist.get(item, False)
                    chk_val = st.checkbox(
                        item,
                        value=current_checked,
                        key=f"chk_{active_alert.alert_id}_{item}",
                    )
                    updated_checklist[item] = chk_val

                st.divider()

                # Status & Notes Editor
                wf_col1, wf_col2 = st.columns(2)
                with wf_col1:
                    new_status = st.selectbox(
                        "Update Alert Status:",
                        options=VALID_STATUSES,
                        index=VALID_STATUSES.index(active_triage_rec.status),
                        key=f"status_sel_{active_alert.alert_id}",
                    )
                    disposition = st.text_input(
                        "Disposition Reason / Summary:",
                        value=active_triage_rec.disposition_reason,
                        placeholder="e.g. Confirmed employee VPN connection; false alarm.",
                        key=f"disp_{active_alert.alert_id}",
                    )
                with wf_col2:
                    analyst_notes_input = st.text_area(
                        "Editable Analyst Investigation Notes:",
                        value=active_triage_rec.notes,
                        placeholder="Enter investigation observations, user contact notes, or ticket links here...",
                        height=110,
                        key=f"notes_{active_alert.alert_id}",
                    )

                if st.button("💾 Save Triage State & Analyst Notes", use_container_width=True):
                    # Persist record to data/triage_state.json
                    triage_mgr.update_record(
                        alert_id=active_alert.alert_id,
                        status=new_status,
                        notes=analyst_notes_input,
                        disposition_reason=disposition,
                        checklist=updated_checklist,
                    )
                    # Update in-memory alert
                    active_alert.status = new_status
                    active_alert.analyst_notes = analyst_notes_input
                    st.success(f"✅ Triage record for `{active_alert.alert_id}` saved successfully!")
                    st.rerun()

        st.divider()

        # Alert Queue Filters & Table
        st.subheader("📑 Full Alerts Queue")
        af1, af2, af3 = st.columns(3)
        with af1:
            sev_filter = st.multiselect("Filter Severity", options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], default=[])
        with af2:
            unique_rules = sorted(list({a.rule_name for a in alerts_list}))
            r_filter = st.multiselect("Filter Rule Name", options=unique_rules, default=[])
        with af3:
            stat_filter = st.multiselect("Filter Status", options=VALID_STATUSES, default=[])

        af4, af5, af6 = st.columns([1, 1, 1])
        with af4:
            user_kw = st.text_input("Target User Filter", placeholder="e.g. admin")
        with af5:
            ip_kw = st.text_input("Source IP Filter", placeholder="e.g. 198.51.100")
        with af6:
            st.write("")
            st.write("")
            if st.button("🔄 Reset Queue Filters"):
                st.rerun()

        # Filter Alerts
        filtered_alerts = alerts_list
        if sev_filter:
            filtered_alerts = [a for a in filtered_alerts if a.severity in sev_filter]
        if r_filter:
            filtered_alerts = [a for a in filtered_alerts if a.rule_name in r_filter]
        if stat_filter:
            filtered_alerts = [a for a in filtered_alerts if a.status in stat_filter]
        if user_kw:
            uk = user_kw.strip().lower()
            filtered_alerts = [a for a in filtered_alerts if a.username and uk in a.username.lower()]
        if ip_kw:
            ik = ip_kw.strip().lower()
            filtered_alerts = [a for a in filtered_alerts if any(ik in ip.lower() for ip in a.source_ips)]

        st.caption(f"Displaying **{len(filtered_alerts)}** of **{len(alerts_list)}** generated alerts")

        # Render Alert Overview Cards
        for alert in filtered_alerts:
            t_rec = triage_mgr.get_record(alert.alert_id)
            sev_badge = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🔵 LOW",
                "INFORMATIONAL": "⚪ INFO",
            }.get(alert.severity, "⚪ INFO")

            with st.container(border=True):
                head1, head2 = st.columns([3, 1])
                with head1:
                    st.markdown(f"#### {sev_badge} — `{alert.rule_name}`")
                    st.caption(
                        f"**Alert ID:** `{alert.alert_id}` | "
                        f"**Target:** `{alert.username or 'N/A'}` | "
                        f"**IPs:** `{', '.join(alert.source_ips) or 'N/A'}` | "
                        f"**Status:** `{t_rec.status}`"
                    )
                with head2:
                    st.markdown(f"**Events:** `{alert.event_count}`")
                    st.markdown(f"**Time:** `{alert.first_seen}`")

                st.write(alert.explanation)

                if t_rec.notes:
                    st.info(f"📝 **Analyst Notes:** {t_rec.notes}")


# =========================================================
# PAGE 4: ANALYTICS
# =========================================================
elif selected_page == "Analytics":
    st.title("📊 Security Analytics & Threat Intelligence")
    st.caption("Deep-dive behavioral trends, authentication patterns, rule performance, and comparative analytics.")

    if events_df.empty:
        render_empty_state("Threat Analytics")
    else:
        # High-level Analytical KPI Summary
        total_evts = len(events_df)
        total_failed = int((events_df["status"] == "FAILED").sum()) if "status" in events_df.columns else 0
        total_alerts = len(alerts_list)
        crit_high = sum(1 for a in alerts_list if a.severity in {"CRITICAL", "HIGH"})
        targeted_users = events_df[events_df["status"] == "FAILED"]["username"].nunique() if "status" in events_df.columns and "username" in events_df.columns else 0
        repeated_ips = (events_df[events_df["status"] == "FAILED"]["source_ip"].value_counts() >= 2).sum() if "status" in events_df.columns and "source_ip" in events_df.columns else 0

        ak1, ak2, ak3, ak4, ak5, ak6 = st.columns(6)
        ak1.metric("Analyzed Events", f"{total_evts:,}")
        ak2.metric("Failed Logins", f"{total_failed:,}", delta=f"{total_failed} failures" if total_failed > 0 else "0", delta_color="inverse")
        ak3.metric("Total Alerts", f"{total_alerts}")
        ak4.metric("Critical / High", f"{crit_high}", delta="Urgent" if crit_high > 0 else "Normal", delta_color="inverse" if crit_high > 0 else "normal")
        ak5.metric("Targeted Users", f"{targeted_users}")
        ak6.metric("Repeat Failure IPs", f"{repeated_ips}")

        st.divider()

        # Row 1: Security Events Over Time & Failed-Login Trends
        st.subheader("📈 Temporal Activity & Authentication Trends")
        r1_col1, r1_col2 = st.columns(2)

        with r1_col1:
            timeline_fig = create_events_timeline_chart(events_df)
            if timeline_fig:
                st.plotly_chart(timeline_fig, use_container_width=True)
            else:
                st.info("No chronological events found in dataset.")
            st.caption(
                "💡 **Chart Insight (Events Over Time):** Shows overall event ingestion activity chronologically, "
                "separated by status (SUCCESS, FAILED, BLOCKED). Spikes during off-hours or abnormal volume surges "
                "often precede or accompany coordinated attacks."
            )

        with r1_col2:
            failed_trend_fig = create_failed_logins_trend_chart(events_df)
            if failed_trend_fig:
                st.plotly_chart(failed_trend_fig, use_container_width=True)
            else:
                st.info("✅ Zero failed authentication events recorded in this dataset.")
            st.caption(
                "💡 **Chart Insight (Failed-Login Trends):** Tracks the volume of failed logins across time intervals. "
                "Sudden sharp spikes or continuous elevated failure rates strongly indicate automated password-guessing, "
                "brute-force attacks, or credential spraying campaigns."
            )

        st.divider()

        # Row 2: Alert Severity Distribution & Alert Triage Status Distribution
        st.subheader("🚨 Threat Posture & Investigation Lifecycle")
        r2_col1, r2_col2 = st.columns(2)

        with r2_col1:
            sev_donut = create_alerts_severity_donut(alerts_list)
            if sev_donut:
                st.plotly_chart(sev_donut, use_container_width=True)
            else:
                st.info("No active alerts triggered in current dataset.")
            st.caption(
                "💡 **Chart Insight (Severity Distribution):** Breaks down detected threats by risk level (Critical, High, "
                "Medium, Low, Informational). A high concentration of Critical/High alerts warrants immediate incident "
                "response and containment."
            )

        with r2_col2:
            status_donut = create_alert_status_distribution_chart(alerts_list, triage_mgr)
            if status_donut:
                st.plotly_chart(status_donut, use_container_width=True)
            else:
                st.info("No active alerts triggered in current dataset.")
            st.caption(
                "💡 **Chart Insight (Triage Status Distribution):** Shows where alerts currently reside within the analyst "
                "response lifecycle (Open, Investigating, False Positive, Resolved). Helps SOC leads monitor triage velocity "
                "and open case backlog."
            )

        st.divider()

        # Row 3: Most Frequently Affected Usernames & Repeated Failure IPs
        st.subheader("🎯 Threat Targets & Repeat Offending Origins")
        r3_col1, r3_col2 = st.columns(2)

        with r3_col1:
            users_fig = create_top_targeted_users_chart(events_df)
            if users_fig:
                st.plotly_chart(users_fig, use_container_width=True)
            else:
                st.info("No failed authentication events recorded.")
            st.caption(
                "💡 **Chart Insight (Frequently Affected Usernames):** Ranks user accounts by failed login attempts. "
                "Accounts with the highest failure rates are primary targets for account takeover or credential stuffing; "
                "privileged accounts require priority scrutiny."
            )

        with r3_col2:
            ips_fig = create_repeated_failure_ips_chart(events_df)
            if ips_fig:
                st.plotly_chart(ips_fig, use_container_width=True)
            else:
                st.info("No failed authentication events recorded.")
            st.caption(
                "💡 **Chart Insight (Repeated Failure Source IPs):** Identifies origin IP addresses generating repeated "
                "authentication failures. These represent malicious external scanners, compromised bots, or internal rogue "
                "hosts that should be considered for firewall blacklisting."
            )

        st.divider()

        # Row 4: Detection Rule Frequency
        st.subheader("⚙️ Detection Rule Performance & Frequency")
        rule_fig = create_detection_rule_frequency_chart(alerts_list)
        if rule_fig:
            st.plotly_chart(rule_fig, use_container_width=True)
        else:
            st.info("No detection rules triggered in current dataset.")
        st.caption(
            "💡 **Chart Insight (Detection Rule Frequency):** Measures how frequently each correlation rule triggered. "
            "Highlights prevalent threat tactics in your environment (e.g. repeated brute-force attempts versus distributed "
            "spraying), providing guidance on which defensive controls require reinforcement."
        )

        st.divider()

        # Row 5: Period Comparison
        st.subheader("⚖️ Time Period Comparison Analytics")
        has_time = "timestamp" in events_df.columns and not events_df["timestamp"].isna().all()
        min_ts = events_df["timestamp"].min() if has_time else None
        max_ts = events_df["timestamp"].max() if has_time else None
        time_span = (max_ts - min_ts) if (has_time and pd.notna(min_ts) and pd.notna(max_ts)) else pd.Timedelta(seconds=0)

        # Check if enough data exists for comparison
        if not has_time or time_span <= pd.Timedelta(minutes=5):
            st.info(
                "ℹ️ **Temporal Comparison Unavailable:** The loaded dataset spans less than 5 minutes or lacks multiple "
                "distinct timestamps. Load a dataset with a wider observation window to evaluate period-over-period trend deltas."
            )
        else:
            mid_ts = min_ts + (time_span / 2)
            comp_mode = st.radio(
                "Comparison Mode",
                options=["Automatic Half-Split (First Half vs Second Half)", "Custom Date/Time Split"],
                horizontal=True,
                key="period_comp_mode_radio",
            )

            if comp_mode.startswith("Automatic"):
                p1_start, p1_end = min_ts, mid_ts
                p2_start, p2_end = mid_ts, max_ts
                st.caption(
                    f"**Period 1:** `{p1_start.strftime('%Y-%m-%d %H:%M:%S UTC')}` to `{p1_end.strftime('%Y-%m-%d %H:%M:%S UTC')}` | "
                    f"**Period 2:** `{p2_start.strftime('%Y-%m-%d %H:%M:%S UTC')}` to `{p2_end.strftime('%Y-%m-%d %H:%M:%S UTC')}`"
                )
            else:
                pc1, pc2 = st.columns(2)
                with pc1:
                    st.markdown("**Period 1 Range**")
                    p1_dates = st.date_input(
                        "P1 Dates",
                        value=(min_ts.date(), mid_ts.date()),
                        min_value=min_ts.date(),
                        max_value=max_ts.date(),
                        key="p1_date_input",
                    )
                    p1_start = pd.to_datetime(p1_dates[0] if isinstance(p1_dates, (list, tuple)) else p1_dates, utc=True)
                    p1_end = pd.to_datetime(p1_dates[1] if isinstance(p1_dates, (list, tuple)) and len(p1_dates) > 1 else p1_dates, utc=True) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                with pc2:
                    st.markdown("**Period 2 Range**")
                    p2_dates = st.date_input(
                        "P2 Dates",
                        value=(mid_ts.date(), max_ts.date()),
                        min_value=min_ts.date(),
                        max_value=max_ts.date(),
                        key="p2_date_input",
                    )
                    p2_start = pd.to_datetime(p2_dates[0] if isinstance(p2_dates, (list, tuple)) else p2_dates, utc=True)
                    p2_end = pd.to_datetime(p2_dates[1] if isinstance(p2_dates, (list, tuple)) and len(p2_dates) > 1 else p2_dates, utc=True) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)

            # Compute period comparison
            comp_res = compare_time_periods(events_df, alerts_list, p1_start, p1_end, p2_start, p2_end)

            if comp_res.get("has_data"):
                d = comp_res["deltas"]
                s1 = comp_res["period1"]
                s2 = comp_res["period2"]

                cp1, cp2, cp3, cp4 = st.columns(4)
                cp1.metric(
                    "Events Volume",
                    f"{s2['events']:,}",
                    delta=f"{d['events']['abs_delta']:+d} ({d['events']['pct_delta']:+.1f}%)",
                    delta_color="normal",
                )
                cp2.metric(
                    "Failed Logins",
                    f"{s2['failed_logins']:,}",
                    delta=f"{d['failed_logins']['abs_delta']:+d} ({d['failed_logins']['pct_delta']:+.1f}%)",
                    delta_color="inverse",
                )
                cp3.metric(
                    "Generated Alerts",
                    f"{s2['alerts_count']}",
                    delta=f"{d['alerts']['abs_delta']:+d} ({d['alerts']['pct_delta']:+.1f}%)",
                    delta_color="inverse",
                )
                cp4.metric(
                    "Active Source IPs",
                    f"{s2['unique_ips']}",
                    delta=f"{d['unique_ips']['abs_delta']:+d} ({d['unique_ips']['pct_delta']:+.1f}%)",
                    delta_color="inverse",
                )

                # Tabular comparison breakdown
                comp_table = pd.DataFrame([
                    {"Metric": "Event Count", "Period 1 (Earlier)": f"{s1['events']:,}", "Period 2 (Later)": f"{s2['events']:,}", "Delta (%)": f"{d['events']['pct_delta']:+.1f}%"},
                    {"Metric": "Failed Logins", "Period 1 (Earlier)": f"{s1['failed_logins']:,}", "Period 2 (Later)": f"{s2['failed_logins']:,}", "Delta (%)": f"{d['failed_logins']['pct_delta']:+.1f}%"},
                    {"Metric": "Successful Logins", "Period 1 (Earlier)": f"{s1['successful_logins']:,}", "Period 2 (Later)": f"{s2['successful_logins']:,}", "Delta (%)": f"{d['successful_logins']['pct_delta']:+.1f}%"},
                    {"Metric": "Triggered Alerts", "Period 1 (Earlier)": str(s1['alerts_count']), "Period 2 (Later)": str(s2['alerts_count']), "Delta (%)": f"{d['alerts']['pct_delta']:+.1f}%"},
                    {"Metric": "Unique Usernames", "Period 1 (Earlier)": str(s1['unique_users']), "Period 2 (Later)": str(s2['unique_users']), "Delta (%)": f"{d['unique_users']['pct_delta']:+.1f}%"},
                    {"Metric": "Unique Source IPs", "Period 1 (Earlier)": str(s1['unique_ips']), "Period 2 (Later)": str(s2['unique_ips']), "Delta (%)": f"{d['unique_ips']['pct_delta']:+.1f}%"},
                ])
                st.dataframe(comp_table, use_container_width=True, hide_index=True)

                st.caption(
                    "💡 **Comparison Insight:** Compares activity between Period 1 (baseline) and Period 2 (subsequent). "
                    "Positive deltas (+%) show escalating threat volumes or spreading attacks, whereas negative deltas (-%) "
                    "indicate successful containment, credential mitigation, or threat cessation."
                )


# =========================================================
# PAGE 5: REPORTS
# =========================================================
elif selected_page == "Reports":
    st.title("📄 SOC Incident Summary & Report Export")
    st.caption("Generate verifiable incident documentation, review reporting scopes, and export filtered security evidence.")

    if events_df.empty:
        render_empty_state("Incident Reports")
    else:
        # ---------------------------------------------------------
        # Report Scoping & Filtering Controls
        # ---------------------------------------------------------
        with st.expander("🔍 Configure Reporting Scope & Filters", expanded=True):
            f_col1, f_col2, f_col3 = st.columns(3)

            with f_col1:
                available_statuses = sorted(events_df["status"].unique().tolist()) if "status" in events_df.columns else []
                report_status_filter = st.multiselect("Filter by Event Status", options=available_statuses, default=[], key="rep_status_filter")

            with f_col2:
                available_types = sorted(events_df["event_type"].unique().tolist()) if "event_type" in events_df.columns else []
                report_type_filter = st.multiselect("Filter by Event Type", options=available_types, default=[], key="rep_type_filter")

            with f_col3:
                available_sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
                report_sev_filter = st.multiselect("Filter Alerts by Severity", options=available_sevs, default=[], key="rep_sev_filter")

            f_col4, f_col5 = st.columns([2, 1])
            with f_col4:
                report_search = st.text_input("Filter by Keyword (Username or Source IP)", placeholder="e.g. admin, 198.51.100.20", key="rep_search_kw")

            with f_col5:
                # Date range
                min_rep_date = events_df["timestamp"].min().date() if "timestamp" in events_df.columns else None
                max_rep_date = events_df["timestamp"].max().date() if "timestamp" in events_df.columns else None
                if min_rep_date and max_rep_date:
                    report_date_range = st.date_input(
                        "Reporting Date Window (UTC)",
                        value=(min_rep_date, max_rep_date),
                        min_value=min_rep_date,
                        max_value=max_rep_date,
                        key="rep_date_range",
                    )
                else:
                    report_date_range = None

        # Build scoped events dataframe (defensive copy)
        scoped_events_df = events_df.copy(deep=True)
        if report_status_filter:
            scoped_events_df = scoped_events_df[scoped_events_df["status"].isin(report_status_filter)]
        if report_type_filter:
            scoped_events_df = scoped_events_df[scoped_events_df["event_type"].isin(report_type_filter)]
        if report_search:
            kw = report_search.strip().lower()
            u_match = scoped_events_df["username"].astype(str).str.lower().str.contains(kw) if "username" in scoped_events_df.columns else False
            ip_match = scoped_events_df["source_ip"].astype(str).str.lower().str.contains(kw) if "source_ip" in scoped_events_df.columns else False
            scoped_events_df = scoped_events_df[u_match | ip_match]
        if report_date_range and isinstance(report_date_range, (list, tuple)) and len(report_date_range) == 2:
            d_start = pd.to_datetime(report_date_range[0], utc=True)
            d_end = pd.to_datetime(report_date_range[1], utc=True) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
            scoped_events_df = scoped_events_df[(scoped_events_df["timestamp"] >= d_start) & (scoped_events_df["timestamp"] <= d_end)]

        # Build scoped alerts list (defensive copy)
        scoped_alerts = list(alerts_list)
        if report_sev_filter:
            scoped_alerts = [a for a in scoped_alerts if a.severity in report_sev_filter]
        if report_search:
            kw = report_search.strip().lower()
            scoped_alerts = [
                a for a in scoped_alerts
                if (a.username and kw in a.username.lower()) or any(kw in ip.lower() for ip in a.source_ips)
            ]

        # Applied filters dictionary for report metadata
        applied_filters_dict = {
            "status": report_status_filter if report_status_filter else "ALL",
            "event_type": report_type_filter if report_type_filter else "ALL",
            "severity": report_sev_filter if report_sev_filter else "ALL",
            "keyword_search": report_search if report_search else "None",
            "date_range": [str(report_date_range[0]), str(report_date_range[1])] if (report_date_range and isinstance(report_date_range, (list, tuple)) and len(report_date_range) == 2) else "Full Observation Window",
        }

        st.divider()

        # ---------------------------------------------------------
        # Selected Reporting Period Review Summary
        # ---------------------------------------------------------
        st.subheader("📋 Selected Reporting Period Review")
        gen_timestamp = pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d %H:%M:%S UTC")
        clean_source = sanitize_source_name(st.session_state.get("source_name", ""))

        earliest_evt = scoped_events_df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S UTC") if not scoped_events_df.empty else "N/A"
        latest_evt = scoped_events_df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S UTC") if not scoped_events_df.empty else "N/A"

        rep_kpi1, rep_kpi2, rep_kpi3, rep_kpi4, rep_kpi5 = st.columns(5)
        rep_kpi1.metric("Events in Scope", f"{len(scoped_events_df):,} / {len(events_df):,}")
        rep_kpi2.metric("Alerts in Scope", f"{len(scoped_alerts)} / {len(alerts_list)}")
        failed_scoped = int((scoped_events_df["status"] == "FAILED").sum()) if "status" in scoped_events_df.columns else 0
        rep_kpi3.metric("Failed Logins", f"{failed_scoped:,}")
        crit_scoped = sum(1 for a in scoped_alerts if a.severity in {"CRITICAL", "HIGH"})
        rep_kpi4.metric("Critical / High", f"{crit_scoped}")
        open_scoped = sum(1 for a in scoped_alerts if triage_mgr.get_record(a.alert_id).status in {"Open", "Investigating"})
        rep_kpi5.metric("Open / Investigating", f"{open_scoped}")

        st.markdown(
            f"""
            - **Report Generation Timestamp:** `{gen_timestamp}`
            - **Source Dataset:** `{clean_source}` *(Distinguished from raw imported logs)*
            - **Observation Period:** `{earliest_evt}` to `{latest_evt}`
            - **Active Filters:** Status=`{applied_filters_dict['status']}` | Types=`{applied_filters_dict['event_type']}` | Severity=`{applied_filters_dict['severity']}` | Search=`{applied_filters_dict['keyword_search']}`
            """
        )

        with st.container(border=True):
            st.markdown("#### 🛡️ Threat & Evidence Synthesis")
            st.markdown(generate_dataset_summary(scoped_events_df, scoped_alerts))

        st.success(
            "🔒 **Data Integrity & Security Guarantee:** Reports are compiled using spreadsheet formula sanitization (CWE-1236) "
            "and defensive copying. Generating or downloading reports does not alter original in-memory evidence."
        )

        st.divider()

        # ---------------------------------------------------------
        # Report Export Facilities
        # ---------------------------------------------------------
        st.subheader("📥 Export Verifiable Reports")
        st.caption("Export filtered event evidence, correlated alert packages, or complete structured JSON reports.")

        # Generate export payloads safely
        events_csv_payload = export_events_to_csv(scoped_events_df, applied_filters_dict)
        alerts_csv_payload = export_alerts_to_csv(scoped_alerts, triage_mgr, applied_filters_dict)
        structured_json_payload = generate_structured_json_report(
            scoped_events_df,
            scoped_alerts,
            triage_mgr,
            source_name=clean_source,
            filters_applied=applied_filters_dict,
            executive_summary=generate_dataset_summary(scoped_events_df, scoped_alerts),
        )

        # Markdown executive report
        markdown_report_payload = f"""# SentinelSOC Incident Summary & Operations Report

**Report Generation Timestamp:** {gen_timestamp}  
**Source Dataset:** `{clean_source}`  
**Report Type:** Analytically Generated Incident Report *(Distinguished from raw log files)*  
**Observation Window:** {earliest_evt} to {latest_evt}  
**Applied Filters:** {json.dumps(applied_filters_dict)}  

---

## 1. Executive Summary
During the observation window, SentinelSOC evaluated **{len(scoped_events_df):,}** scoped security events and identified **{len(scoped_alerts)}** correlated threat alerts.
- **Critical & High Severity Alerts:** {crit_scoped}
- **Active / Open Investigations:** {open_scoped}
- **Failed Authentication Attempts:** {failed_scoped}

## 2. Evidence-Based Threat Synthesis
{generate_dataset_summary(scoped_events_df, scoped_alerts)}

## 3. Correlated Threat Incidents in Scope
"""
        if scoped_alerts:
            for al in scoped_alerts:
                al_rec = triage_mgr.get_record(al.alert_id)
                markdown_report_payload += f"""
### [{al.severity}] {al.rule_name} (`{al.alert_id}`)
- **Target User:** `{al.username or 'N/A'}`
- **Source IP(s):** `{', '.join(al.source_ips)}`
- **Correlated Event Count:** {al.event_count}
- **Triage Status:** `{al_rec.status}`
- **Analysis:** {al.explanation}
- **Analyst Notes:** {al_rec.notes or 'None recorded'}
- **Disposition Reason:** {al_rec.disposition_reason or 'Pending disposition'}
- **Recommended Actions:**
"""
                for step in al.recommended_steps:
                    markdown_report_payload += f"  - {step}\n"
        else:
            markdown_report_payload += "\n*No security alerts matched the selected reporting criteria.*\n"

        markdown_report_payload += """
---
*Confidential — Educational Security Operations Center Incident Documentation*
*Safety Note: Formula injection sanitized for spreadsheet viewing. Local environment paths omitted.*
"""

        # Export Buttons Row
        exp_col1, exp_col2, exp_col3, exp_col4 = st.columns(4)

        with exp_col1:
            st.download_button(
                label="📊 Export Events (CSV)",
                data=events_csv_payload,
                file_name=f"SentinelSOC_Events_{pd.Timestamp.now(tz='UTC').strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
                help="Download filtered security events in CSV format with formula injection protection.",
            )

        with exp_col2:
            st.download_button(
                label="🚨 Export Alerts (CSV)",
                data=alerts_csv_payload,
                file_name=f"SentinelSOC_Alerts_{pd.Timestamp.now(tz='UTC').strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
                help="Download correlated threat alerts and triage records in CSV format.",
            )

        with exp_col3:
            st.download_button(
                label="💾 Export JSON Report",
                data=structured_json_payload,
                file_name=f"SentinelSOC_Report_{pd.Timestamp.now(tz='UTC').strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
                help="Download structured JSON report with metadata, period metrics, and alert details.",
            )

        with exp_col4:
            st.download_button(
                label="📄 Export Executive (MD)",
                data=markdown_report_payload,
                file_name=f"SentinelSOC_Briefing_{pd.Timestamp.now(tz='UTC').strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                use_container_width=True,
                help="Download the human-readable Markdown incident summary report.",
            )

        st.divider()

        # ---------------------------------------------------------
        # Evidence Preview Tabs
        # ---------------------------------------------------------
        st.subheader("👁️ In-Scope Evidence & Report Preview")
        tab_alerts, tab_events, tab_json = st.tabs([
            f"🚨 Alerts in Scope ({len(scoped_alerts)})",
            f"📋 Events in Scope ({len(scoped_events_df):,})",
            "💾 Structured JSON Preview",
        ])

        with tab_alerts:
            if scoped_alerts:
                rep_alerts_table = pd.DataFrame([
                    {
                        "Alert ID": a.alert_id,
                        "Severity": a.severity,
                        "Rule Name": a.rule_name,
                        "Target User": a.username or "N/A",
                        "Source IP(s)": ", ".join(a.source_ips),
                        "Events": a.event_count,
                        "Triage Status": triage_mgr.get_record(a.alert_id).status,
                        "Analyst Notes": triage_mgr.get_record(a.alert_id).notes or "None",
                        "Disposition": triage_mgr.get_record(a.alert_id).disposition_reason or "Pending",
                    }
                    for a in scoped_alerts
                ])
                st.dataframe(rep_alerts_table, use_container_width=True, hide_index=True)
            else:
                st.info("No alerts match the selected reporting filters.")

        with tab_events:
            if not scoped_events_df.empty:
                st.dataframe(scoped_events_df.head(100), use_container_width=True, hide_index=True)
                if len(scoped_events_df) > 100:
                    st.caption(f"Showing first 100 of **{len(scoped_events_df):,}** events matching current scope.")
            else:
                st.info("No security events match the current filter criteria.")

        with tab_json:
            with st.expander("🔍 View Serialized JSON Report Structure", expanded=False):
                st.code(structured_json_payload[:3000] + ("\n... [TRUNCATED FOR DISPLAY]" if len(structured_json_payload) > 3000 else ""), language="json")
