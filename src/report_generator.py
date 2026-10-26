"""SentinelSOC - Report Generation & Export Utilities.

Provides secure CSV and JSON reporting facilities for SOC analysts.
Implements spreadsheet formula injection protection (CWE-1236), safe JSON
serialization, and defensive copying to guarantee underlying evidence integrity.
"""

from __future__ import annotations

import copy
import csv
import io
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import pandas as pd

from src.detection_engine import Alert
from src.triage_manager import TriageManager, TriageRecord

# Spreadsheet formula trigger prefixes according to OWASP CSV Injection guidelines
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "|", "%")

# Sensitive fields to scrub from exported reports to prevent unintended leakage
SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "private_key",
    "auth_token",
    "session_secret",
}


def sanitize_csv_cell(value: Any) -> Any:
    """Sanitize a single CSV cell value against spreadsheet formula injection (CWE-1236).

    If an untrusted string starts with formula-triggering characters (=, +, -, @,
    tab, carriage return, pipe, percent), it is prefixed with a single quote (')
    to prevent spreadsheet engines (Excel, Calc) from executing malicious formulas.
    Pure numeric types and valid numerical strings are safely preserved.
    """
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return value

    val_str = str(value)
    if not val_str:
        return ""

    if val_str.startswith(FORMULA_PREFIXES):
        # Allow legitimate signed numbers (e.g., "-42", "+3.14")
        if val_str[0] in ("-", "+"):
            try:
                float(val_str)
                return value
            except ValueError:
                pass
        # Escape untrusted formula/command payload
        return f"'{val_str}"

    return value


def sanitize_dataframe_for_csv(df: pd.DataFrame) -> pd.DataFrame:
    """Return a sanitized defensive copy of a DataFrame for CSV export.

    Guarantees that the underlying DataFrame is never modified.
    """
    if df.empty:
        return df.copy()

    # Create defensive copy
    clean_df = df.copy(deep=True)

    for col in clean_df.columns:
        # Scrub sensitive column names if present
        if str(col).lower() in SENSITIVE_FIELD_NAMES:
            clean_df[col] = "[REDACTED]"
            continue

        # Sanitize object/string columns
        if clean_df[col].dtype == object or pd.api.types.is_string_dtype(clean_df[col]):
            clean_df[col] = clean_df[col].apply(sanitize_csv_cell)

    return clean_df


def safe_json_default(obj: Any) -> Any:
    """Custom JSON serializer default handler for non-serializable objects."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, pd.Timestamp):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    if isinstance(obj, Path):
        return obj.name  # Only expose filename, never full host path
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def sanitize_source_name(source_name: Optional[str]) -> str:
    """Strip local directories and environment paths from dataset source names."""
    if not source_name or source_name == "None":
        return "Unspecified Dataset"
    return Path(source_name).name


def export_events_to_csv(
    events_df: pd.DataFrame,
    filters_applied: Optional[dict[str, Any]] = None,
) -> str:
    """Export security events to CSV format with formula injection protection.

    Does not modify the original events_df.
    """
    if events_df.empty:
        # Return empty CSV with standard column headers
        cols = ["event_id", "timestamp", "event_type", "username", "source_ip", "status", "message"]
        return ",".join(cols) + "\n"

    # Filter defensively if requested
    df_to_export = events_df.copy(deep=True)
    if filters_applied:
        if filters_applied.get("status"):
            df_to_export = df_to_export[df_to_export["status"].isin(filters_applied["status"])]
        if filters_applied.get("event_type"):
            df_to_export = df_to_export[df_to_export["event_type"].isin(filters_applied["event_type"])]
        if filters_applied.get("username"):
            u = str(filters_applied["username"]).lower()
            df_to_export = df_to_export[df_to_export["username"].astype(str).str.lower().str.contains(u)]
        if filters_applied.get("source_ip"):
            ip = str(filters_applied["source_ip"]).lower()
            df_to_export = df_to_export[df_to_export["source_ip"].astype(str).str.lower().str.contains(ip)]

    sanitized_df = sanitize_dataframe_for_csv(df_to_export)
    return sanitized_df.to_csv(index=False)


def export_alerts_to_csv(
    alerts: Sequence[Alert],
    triage_manager: Optional[TriageManager] = None,
    filters_applied: Optional[dict[str, Any]] = None,
) -> str:
    """Export correlated alerts with analyst triage records to CSV.

    Applies spreadsheet formula injection sanitization to all fields.
    Does not modify original alert instances.
    """
    if not alerts:
        cols = [
            "alert_id",
            "rule_name",
            "severity",
            "confidence",
            "status",
            "username",
            "source_ips",
            "first_seen",
            "last_seen",
            "event_count",
            "related_event_ids",
            "explanation",
            "analyst_notes",
            "disposition_reason",
        ]
        return ",".join(cols) + "\n"

    filtered_alerts = list(alerts)
    if filters_applied:
        if filters_applied.get("severity"):
            filtered_alerts = [a for a in filtered_alerts if a.severity in filters_applied["severity"]]
        if filters_applied.get("rule_name"):
            filtered_alerts = [a for a in filtered_alerts if a.rule_name in filters_applied["rule_name"]]
        if filters_applied.get("status"):
            filtered_alerts = [a for a in filtered_alerts if a.status in filters_applied["status"]]

    rows: list[dict[str, Any]] = []
    for a in filtered_alerts:
        # Retrieve persistent triage details if manager provided
        t_status = a.status
        t_notes = a.analyst_notes
        t_reason = ""
        if triage_manager:
            rec = triage_manager.get_record(a.alert_id)
            t_status = rec.status
            t_notes = rec.notes
            t_reason = rec.disposition_reason

        row = {
            "alert_id": sanitize_csv_cell(a.alert_id),
            "rule_name": sanitize_csv_cell(a.rule_name),
            "severity": sanitize_csv_cell(a.severity),
            "confidence": sanitize_csv_cell(a.confidence),
            "status": sanitize_csv_cell(t_status),
            "username": sanitize_csv_cell(a.username or "N/A"),
            "source_ips": sanitize_csv_cell(", ".join(a.source_ips)),
            "first_seen": sanitize_csv_cell(a.first_seen),
            "last_seen": sanitize_csv_cell(a.last_seen),
            "event_count": a.event_count,
            "related_event_ids": sanitize_csv_cell(", ".join(a.related_event_ids)),
            "explanation": sanitize_csv_cell(a.explanation),
            "analyst_notes": sanitize_csv_cell(t_notes),
            "disposition_reason": sanitize_csv_cell(t_reason),
        }
        rows.append(row)

    output = io.StringIO()
    if rows:
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)
    return output.getvalue()


def generate_structured_json_report(
    events_df: pd.DataFrame,
    alerts: Sequence[Alert],
    triage_manager: Optional[TriageManager] = None,
    source_name: str = "",
    filters_applied: Optional[dict[str, Any]] = None,
    executive_summary: str = "",
) -> str:
    """Generate a structured, safe JSON incident and operations report.

    Features:
    - Clear distinction between generated report metadata and raw logs
    - Complete summary of selected observation period and filters
    - Redaction of environmental secrets and absolute server paths
    - Safe serialization of datetimes and custom types
    """
    clean_source = sanitize_source_name(source_name)
    now_utc = datetime.now(timezone.utc).isoformat()

    # Observation period calculation
    earliest_str = "N/A"
    latest_str = "N/A"
    total_events = len(events_df)
    failed_logins = 0
    successful_logins = 0

    if not events_df.empty and "timestamp" in events_df.columns:
        earliest_ts = events_df["timestamp"].min()
        latest_ts = events_df["timestamp"].max()
        if pd.notna(earliest_ts):
            earliest_str = pd.to_datetime(earliest_ts).isoformat()
        if pd.notna(latest_ts):
            latest_str = pd.to_datetime(latest_ts).isoformat()

        if "status" in events_df.columns:
            status_col = events_df["status"].astype(str)
            failed_logins = int((status_col == "FAILED").sum())
            successful_logins = int((status_col == "SUCCESS").sum())

    # Alert severity & triage metrics
    severity_breakdown = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
    }
    status_breakdown = {
        "Open": 0,
        "Investigating": 0,
        "False Positive": 0,
        "Resolved": 0,
    }

    serialized_alerts: list[dict[str, Any]] = []
    for a in alerts:
        sev = a.severity.upper() if a.severity else "INFORMATIONAL"
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        rec_status = a.status
        rec_notes = a.analyst_notes
        rec_reason = ""
        rec_checklist = {}
        if triage_manager:
            t_rec = triage_manager.get_record(a.alert_id)
            rec_status = t_rec.status
            rec_notes = t_rec.notes
            rec_reason = t_rec.disposition_reason
            rec_checklist = t_rec.checklist

        status_breakdown[rec_status] = status_breakdown.get(rec_status, 0) + 1

        alert_dict = {
            "alert_id": a.alert_id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "confidence": a.confidence,
            "status": rec_status,
            "target_username": a.username or "N/A",
            "source_ips": list(a.source_ips),
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
            "event_count": a.event_count,
            "related_event_ids": list(a.related_event_ids),
            "explanation": a.explanation,
            "recommended_steps": list(a.recommended_steps),
            "analyst_notes": rec_notes,
            "disposition_reason": rec_reason,
            "checklist": rec_checklist,
        }
        serialized_alerts.append(alert_dict)

    # Event types summary (without unnecessarily dumping all raw rows)
    event_type_summary: dict[str, int] = {}
    if not events_df.empty and "event_type" in events_df.columns:
        event_type_summary = events_df["event_type"].value_counts().to_dict()

    report_payload = {
        "report_metadata": {
            "report_title": "SentinelSOC Incident & Security Analytics Report",
            "report_classification": "EDUCATIONAL_SOC_GENERATED_REPORT",
            "report_version": "1.0",
            "generated_at": now_utc,
            "generated_by": "SentinelSOC Security Operations Platform",
            "source_dataset": clean_source,
            "applied_filters": filters_applied or {},
            "environment_sanitized": True,
            "disclaimer": (
                "This document is an analytically generated incident report based on ingested "
                "security logs. It is explicitly distinguished from raw, unprocessed log streams."
            ),
        },
        "period_summary": {
            "observation_window": {
                "earliest_event": earliest_str,
                "latest_event": latest_str,
            },
            "total_events_analyzed": total_events,
            "total_alerts_detected": len(alerts),
            "authentication_metrics": {
                "successful_logins": successful_logins,
                "failed_logins": failed_logins,
            },
            "alerts_by_severity": severity_breakdown,
            "alerts_by_status": status_breakdown,
            "executive_summary": executive_summary,
        },
        "correlated_alerts": serialized_alerts,
        "evidence_scope": {
            "event_types_distribution": event_type_summary,
            "included_event_count": total_events,
        },
    }

    return json.dumps(report_payload, default=safe_json_default, indent=2)
