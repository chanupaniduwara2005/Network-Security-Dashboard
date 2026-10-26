"""SentinelSOC - Dashboard Utilities & Visualization Helpers.

Provides helper functions for Plotly dark-themed charts, summary statistics,
and report generation.
"""

from __future__ import annotations

from typing import Any, List, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from src.detection_engine import Alert

# Cybersecurity color palette
PALETTE = {
    "bg": "#151d2e",
    "paper": "#151d2e",
    "text": "#e2e8f0",
    "grid": "#243048",
    "primary": "#00d4aa",
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#64748b",
    "success": "#10b981",
    "failed": "#f43f5e",
    "blocked": "#a855f7",
}

SEVERITY_COLORS = {
    "CRITICAL": PALETTE["critical"],
    "HIGH": PALETTE["high"],
    "MEDIUM": PALETTE["medium"],
    "LOW": PALETTE["low"],
    "INFORMATIONAL": PALETTE["info"],
}


def apply_dark_theme(fig: go.Figure) -> go.Figure:
    """Apply consistent SOC dark theme formatting to a Plotly figure."""
    fig.update_layout(
        paper_bgcolor=PALETTE["paper"],
        plot_bgcolor=PALETTE["bg"],
        font=dict(color=PALETTE["text"], family="sans-serif", size=12),
        margin=dict(l=20, r=20, t=40, b=20),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color=PALETTE["text"]),
        ),
    )
    fig.update_xaxes(
        gridcolor=PALETTE["grid"],
        zerolinecolor=PALETTE["grid"],
        showgrid=True,
    )
    fig.update_yaxes(
        gridcolor=PALETTE["grid"],
        zerolinecolor=PALETTE["grid"],
        showgrid=True,
    )
    return fig


def create_events_timeline_chart(df: pd.DataFrame) -> Optional[go.Figure]:
    """Generate a chronological bar chart of security events by status."""
    if df.empty or "timestamp" not in df.columns:
        return None

    df_copy = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df_copy["timestamp"]):
        df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"], utc=True, errors="coerce")
    df_copy = df_copy.dropna(subset=["timestamp"])

    if df_copy.empty:
        return None

    # Resample events into intervals (hourly or 15-min depending on span)
    span = df_copy["timestamp"].max() - df_copy["timestamp"].min()
    freq = "15min" if span <= pd.Timedelta(hours=6) else "1h"

    df_copy["time_bucket"] = df_copy["timestamp"].dt.floor(freq)
    grouped = (
        df_copy.groupby(["time_bucket", "status"], observed=True)
        .size()
        .reset_index(name="event_count")
    )

    color_map = {
        "SUCCESS": PALETTE["success"],
        "FAILED": PALETTE["failed"],
        "BLOCKED": PALETTE["blocked"],
        "UNKNOWN": PALETTE["info"],
    }

    fig = px.bar(
        grouped,
        x="time_bucket",
        y="event_count",
        color="status",
        color_discrete_map=color_map,
        title=f"Security Events Timeline ({freq} intervals)",
        labels={"time_bucket": "Time (UTC)", "event_count": "Event Count", "status": "Status"},
        barmode="stack",
    )
    return apply_dark_theme(fig)


def create_alerts_severity_donut(alerts: list[Alert]) -> Optional[go.Figure]:
    """Generate a donut chart showing the breakdown of generated alerts by severity."""
    if not alerts:
        return None

    counts = {}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1

    labels = list(counts.keys())
    values = list(counts.values())
    colors = [SEVERITY_COLORS.get(lvl, PALETTE["info"]) for lvl in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.6,
                marker=dict(colors=colors, line=dict(color="#0b0f19", width=2)),
                textinfo="label+value",
                hoverinfo="label+value+percent",
            )
        ]
    )
    fig.update_layout(title="Alerts by Severity Tier")
    return apply_dark_theme(fig)


def create_events_by_type_bar(df: pd.DataFrame) -> Optional[go.Figure]:
    """Generate a horizontal bar chart of event distribution by event_type."""
    if df.empty or "event_type" not in df.columns:
        return None

    type_counts = (
        df["event_type"]
        .value_counts()
        .reset_index()
        .rename(columns={"index": "event_type", "count": "count"})
    )
    # Support pandas versions with different value_counts column names
    if "event_type" not in type_counts.columns:
        type_counts.columns = ["event_type", "count"]

    fig = px.bar(
        type_counts.head(10),
        x="count",
        y="event_type",
        orientation="h",
        title="Events by Type (Top 10)",
        color_discrete_sequence=[PALETTE["primary"]],
        labels={"count": "Event Count", "event_type": "Event Type"},
    )
    fig.update_layout(yaxis=dict(autorange="reversed"))
    return apply_dark_theme(fig)


def create_top_failed_ips_bar(df: pd.DataFrame) -> Optional[go.Figure]:
    """Generate a bar chart of top origin IPs responsible for failed logins."""
    if df.empty or "status" not in df.columns or "source_ip" not in df.columns:
        return None

    failed_df = df[df["status"] == "FAILED"]
    if failed_df.empty:
        return None

    ip_counts = (
        failed_df["source_ip"]
        .value_counts()
        .reset_index()
    )
    ip_counts.columns = ["source_ip", "failed_count"]

    fig = px.bar(
        ip_counts.head(8),
        x="source_ip",
        y="failed_count",
        title="Top Source IPs by Failed Logins",
        color="failed_count",
        color_continuous_scale=["#f97316", "#ef4444"],
        labels={"source_ip": "Source IP", "failed_count": "Failed Logins"},
    )
    fig.update_layout(coloraxis_showscale=False)
    return apply_dark_theme(fig)


def generate_dataset_summary(df: pd.DataFrame, alerts: list[Alert]) -> str:
    """Produce an evidence-based textual synthesis of the loaded log dataset and alert posture."""
    if df.empty:
        return "No log dataset is currently loaded."

    total_events = len(df)
    earliest = df["timestamp"].min()
    latest = df["timestamp"].max()
    time_str = f"{earliest.strftime('%Y-%m-%d %H:%M UTC')} to {latest.strftime('%Y-%m-%d %H:%M UTC')}"

    # Log analysis
    failed_logins = len(df[(df["status"] == "FAILED") & (df["event_type"].str.contains("LOGIN", na=False))])
    successful_logins = len(df[(df["status"] == "SUCCESS") & (df["event_type"].str.contains("LOGIN", na=False))])
    unique_users = df["username"].nunique()
    unique_ips = df["source_ip"].nunique()

    # Alert analysis
    total_alerts = len(alerts)
    crit_count = sum(1 for a in alerts if a.severity == "CRITICAL")
    high_count = sum(1 for a in alerts if a.severity == "HIGH")
    open_alerts = sum(1 for a in alerts if a.status in {"NEW", "UNDER_INVESTIGATION"})

    # Most targeted user & top attacker IP
    top_failed_user = "None"
    top_failed_ip = "None"
    failed_df = df[df["status"] == "FAILED"]
    if not failed_df.empty:
        top_failed_user = failed_df["username"].mode().iloc[0] if not failed_df["username"].empty else "N/A"
        top_failed_ip = failed_df["source_ip"].mode().iloc[0] if not failed_df["source_ip"].empty else "N/A"

    summary_text = (
        f"**Dataset Overview:** Analyzed **{total_events:,}** events recorded between **{time_str}**, "
        f"encompassing **{unique_users}** unique user identities and **{unique_ips}** source IP addresses.\n\n"
        f"**Authentication Activity:** Recorded **{successful_logins:,}** successful logins and **{failed_logins:,}** failed attempts. "
        f"The primary origin for failed authentications was `{top_failed_ip}`, with user `{top_failed_user}` experiencing the highest failure volume.\n\n"
        f"**Threat Triage Summary:** Correlated **{total_alerts}** actionable incidents (**{crit_count}** Critical, **{high_count}** High), "
        f"with **{open_alerts}** alerts currently requiring active analyst investigation. "
        f"{'Immediate incident response advised for Critical alerts.' if crit_count > 0 else 'All high-priority signals are within containment thresholds.'}"
    )
    return summary_text


def create_failed_logins_trend_chart(df: pd.DataFrame) -> Optional[go.Figure]:
    """Generate a time-series trend chart of failed authentications."""
    if df.empty or "timestamp" not in df.columns or "status" not in df.columns:
        return None

    failed_df = df[df["status"] == "FAILED"].copy()
    if failed_df.empty:
        return None

    if not pd.api.types.is_datetime64_any_dtype(failed_df["timestamp"]):
        failed_df["timestamp"] = pd.to_datetime(failed_df["timestamp"], utc=True, errors="coerce")
    failed_df = failed_df.dropna(subset=["timestamp"])
    if failed_df.empty:
        return None

    span = failed_df["timestamp"].max() - failed_df["timestamp"].min()
    freq = "15min" if span <= pd.Timedelta(hours=6) else "1h"

    failed_df["time_bucket"] = failed_df["timestamp"].dt.floor(freq)
    grouped = failed_df.groupby("time_bucket", observed=True).size().reset_index(name="failed_count")

    fig = px.area(
        grouped,
        x="time_bucket",
        y="failed_count",
        title=f"Failed Authentication Trend ({freq} bins)",
        labels={"time_bucket": "Time (UTC)", "failed_count": "Failed Attempts"},
        color_discrete_sequence=[PALETTE["failed"]],
    )
    fig.update_traces(mode="lines+markers", line=dict(width=2))
    return apply_dark_theme(fig)


def create_top_targeted_users_chart(df: pd.DataFrame, top_n: int = 8) -> Optional[go.Figure]:
    """Generate a bar chart of the most frequently targeted usernames by failed logins."""
    if df.empty or "username" not in df.columns or "status" not in df.columns:
        return None

    failed_df = df[df["status"] == "FAILED"]
    if failed_df.empty:
        return None

    user_counts = (
        failed_df["username"]
        .value_counts()
        .reset_index()
    )
    user_counts.columns = ["username", "failed_count"]

    fig = px.bar(
        user_counts.head(top_n),
        x="failed_count",
        y="username",
        orientation="h",
        title=f"Top Targeted Usernames by Failed Logins (Top {top_n})",
        labels={"failed_count": "Failed Logins", "username": "Username"},
        color="failed_count",
        color_continuous_scale=["#3b82f6", "#ef4444"],
    )
    fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
    return apply_dark_theme(fig)


def create_repeated_failure_ips_chart(df: pd.DataFrame, min_failures: int = 2) -> Optional[go.Figure]:
    """Generate a bar chart of source IPs associated with repeated login failures."""
    if df.empty or "source_ip" not in df.columns or "status" not in df.columns:
        return None

    failed_df = df[df["status"] == "FAILED"]
    if failed_df.empty:
        return None

    ip_counts = failed_df["source_ip"].value_counts().reset_index()
    ip_counts.columns = ["source_ip", "failed_count"]

    # Filter for repeated failures if possible, otherwise show available
    repeated = ip_counts[ip_counts["failed_count"] >= min_failures]
    if repeated.empty:
        repeated = ip_counts

    fig = px.bar(
        repeated.head(10),
        x="failed_count",
        y="source_ip",
        orientation="h",
        title="Source IPs with Repeated Failures",
        labels={"failed_count": "Failure Count", "source_ip": "Source IP"},
        color="failed_count",
        color_continuous_scale=["#f97316", "#ef4444"],
    )
    fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
    return apply_dark_theme(fig)


def create_detection_rule_frequency_chart(alerts: Sequence[Alert]) -> Optional[go.Figure]:
    """Generate a bar chart of detection rule triggering frequency."""
    if not alerts:
        return None

    rule_counts: dict[str, int] = {}
    for a in alerts:
        rule_counts[a.rule_name] = rule_counts.get(a.rule_name, 0) + 1

    df_rules = pd.DataFrame(
        [{"rule_name": r, "trigger_count": c} for r, c in rule_counts.items()]
    ).sort_values(by="trigger_count", ascending=False)

    fig = px.bar(
        df_rules,
        x="trigger_count",
        y="rule_name",
        orientation="h",
        title="Detection Rule Frequency",
        labels={"trigger_count": "Alert Count", "rule_name": "Detection Rule"},
        color_discrete_sequence=[PALETTE["primary"]],
    )
    fig.update_layout(yaxis=dict(autorange="reversed"))
    return apply_dark_theme(fig)


def create_alert_status_distribution_chart(
    alerts: Sequence[Alert],
    triage_manager: Optional[Any] = None,
) -> Optional[go.Figure]:
    """Generate a donut chart of alert triage status distribution."""
    if not alerts:
        return None

    status_counts: dict[str, int] = {}
    for a in alerts:
        st_val = a.status
        if triage_manager:
            rec = triage_manager.get_record(a.alert_id)
            st_val = rec.status
        status_counts[st_val] = status_counts.get(st_val, 0) + 1

    status_colors = {
        "Open": PALETTE["critical"],
        "Investigating": PALETTE["high"],
        "False Positive": PALETTE["info"],
        "Resolved": PALETTE["success"],
        "NEW": PALETTE["critical"],
    }

    labels = list(status_counts.keys())
    values = list(status_counts.values())
    colors = [status_colors.get(lbl, PALETTE["info"]) for lbl in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.6,
                marker=dict(colors=colors, line=dict(color="#0b0f19", width=2)),
                textinfo="label+value",
                hoverinfo="label+value+percent",
            )
        ]
    )
    fig.update_layout(title="Alert Triage Status Distribution")
    return apply_dark_theme(fig)


def compare_time_periods(
    df: pd.DataFrame,
    alerts: Sequence[Alert],
    start_p1: pd.Timestamp,
    end_p1: pd.Timestamp,
    start_p2: pd.Timestamp,
    end_p2: pd.Timestamp,
) -> dict[str, Any]:
    """Compute comparative metrics between two discrete observation periods."""
    if df.empty or "timestamp" not in df.columns:
        return {"has_data": False, "reason": "No event dataset available."}

    df_copy = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df_copy["timestamp"]):
        df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"], utc=True, errors="coerce")
    df_copy = df_copy.dropna(subset=["timestamp"])

    p1_events = df_copy[(df_copy["timestamp"] >= start_p1) & (df_copy["timestamp"] <= end_p1)]
    p2_events = df_copy[(df_copy["timestamp"] >= start_p2) & (df_copy["timestamp"] <= end_p2)]

    def calc_period_stats(pdf: pd.DataFrame, p_start: pd.Timestamp, p_end: pd.Timestamp) -> dict[str, Any]:
        count = len(pdf)
        failed = int((pdf["status"] == "FAILED").sum()) if "status" in pdf.columns else 0
        success = int((pdf["status"] == "SUCCESS").sum()) if "status" in pdf.columns else 0
        unique_users = int(pdf["username"].nunique()) if "username" in pdf.columns else 0
        unique_ips = int(pdf["source_ip"].nunique()) if "source_ip" in pdf.columns else 0

        # Filter alerts within period
        p_alerts = []
        for a in alerts:
            try:
                a_time = pd.to_datetime(a.first_seen, utc=True)
                if p_start <= a_time <= p_end:
                    p_alerts.append(a)
            except Exception:
                pass

        return {
            "events": count,
            "failed_logins": failed,
            "successful_logins": success,
            "unique_users": unique_users,
            "unique_ips": unique_ips,
            "alerts_count": len(p_alerts),
        }

    s1 = calc_period_stats(p1_events, start_p1, end_p1)
    s2 = calc_period_stats(p2_events, start_p2, end_p2)

    def calc_delta(val1: int, val2: int) -> dict[str, Any]:
        diff = val2 - val1
        pct = round((diff / val1 * 100), 1) if val1 > 0 else (100.0 if diff > 0 else 0.0)
        return {"abs_delta": diff, "pct_delta": pct}

    return {
        "has_data": True,
        "period1": {
            "start": start_p1.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "end": end_p1.strftime("%Y-%m-%d %H:%M:%S UTC"),
            **s1,
        },
        "period2": {
            "start": start_p2.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "end": end_p2.strftime("%Y-%m-%d %H:%M:%S UTC"),
            **s2,
        },
        "deltas": {
            "events": calc_delta(s1["events"], s2["events"]),
            "failed_logins": calc_delta(s1["failed_logins"], s2["failed_logins"]),
            "successful_logins": calc_delta(s1["successful_logins"], s2["successful_logins"]),
            "alerts": calc_delta(s1["alerts_count"], s2["alerts_count"]),
            "unique_users": calc_delta(s1["unique_users"], s2["unique_users"]),
            "unique_ips": calc_delta(s1["unique_ips"], s2["unique_ips"]),
        },
    }
