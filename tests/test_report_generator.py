"""Unit tests for SentinelSOC report generation, CSV/JSON exports, and security controls."""

import csv
import io
import json
from datetime import datetime, timezone
import pandas as pd
import pytest

from src.detection_engine import Alert
from src.report_generator import (
    export_alerts_to_csv,
    export_events_to_csv,
    generate_structured_json_report,
    sanitize_csv_cell,
    sanitize_dataframe_for_csv,
    sanitize_source_name,
)
from src.triage_manager import TriageManager, TriageRecord


@pytest.fixture
def sample_events_df():
    return pd.DataFrame([
        {
            "event_id": "EVT-101",
            "timestamp": pd.to_datetime("2026-10-24T10:00:00Z"),
            "event_type": "LOGIN",
            "username": "admin",
            "source_ip": "198.51.100.20",
            "status": "FAILED",
            "message": "Authentication failed for user admin",
        },
        {
            "event_id": "EVT-102",
            "timestamp": pd.to_datetime("2026-10-24T10:01:00Z"),
            "event_type": "LOGIN",
            "username": "admin",
            "source_ip": "198.51.100.20",
            "status": "SUCCESS",
            "message": "User admin logged in",
        },
        {
            "event_id": "EVT-103",
            "timestamp": pd.to_datetime("2026-10-24T10:05:00Z"),
            "event_type": "FILE_ACCESS",
            "username": "bob",
            "source_ip": "192.168.1.50",
            "status": "SUCCESS",
            "message": "File opened",
        },
    ])


@pytest.fixture
def sample_alerts_list():
    return [
        Alert(
            alert_id="ALT-101",
            rule_name="Brute-Force Attack Pattern",
            severity="CRITICAL",
            username="admin",
            source_ips=["198.51.100.20"],
            first_seen="2026-10-24 10:00:00Z",
            last_seen="2026-10-24 10:01:00Z",
            event_count=2,
            related_event_ids=["EVT-101", "EVT-102"],
            explanation="Multiple failed logins followed by success",
            recommended_steps=["Reset admin credentials", "Block IP 198.51.100.20"],
            status="Open",
            confidence="HIGH",
            analyst_notes="Under active containment",
        ),
        Alert(
            alert_id="ALT-102",
            rule_name="Off-Hours Privileged Access",
            severity="MEDIUM",
            username="bob",
            source_ips=["192.168.1.50"],
            first_seen="2026-10-24 10:05:00Z",
            last_seen="2026-10-24 10:05:00Z",
            event_count=1,
            related_event_ids=["EVT-103"],
            explanation="Access detected outside standard shifts",
            recommended_steps=["Verify user schedule"],
            status="Resolved",
            confidence="LOW",
        ),
    ]


@pytest.fixture
def sample_triage_mgr(tmp_path):
    mgr = TriageManager(storage_path=tmp_path / "triage.json")
    mgr.update_record(
        "ALT-101",
        status="Investigating",
        notes="Validating firewall logs.",
        disposition_reason="Confirmed attack.",
    )
    return mgr


# =========================================================
# Formula Injection Protection Tests (CWE-1236)
# =========================================================
def test_formula_injection_sanitization():
    """Verify spreadsheet formula triggering characters are properly neutralized."""
    # Test formula triggers
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert sanitize_csv_cell("-2+3+cmd|...") == "'-2+3+cmd|..."
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("\t=1+1") == "'\t=1+1"
    assert sanitize_csv_cell("\r=1+1") == "'\r=1+1"
    assert sanitize_csv_cell("%0A=1+1") == "'%0A=1+1"
    assert sanitize_csv_cell("|cmd") == "'|cmd"

    # Test that genuine numbers are preserved
    assert sanitize_csv_cell(42) == 42
    assert sanitize_csv_cell(-42) == -42
    assert sanitize_csv_cell(3.14) == 3.14
    assert sanitize_csv_cell("-42") == "-42"
    assert sanitize_csv_cell("+3.14") == "+3.14"

    # Test normal strings and empty values
    assert sanitize_csv_cell("alice") == "alice"
    assert sanitize_csv_cell("192.168.1.1") == "192.168.1.1"
    assert sanitize_csv_cell("") == ""
    assert sanitize_csv_cell(None) == ""


def test_sanitize_dataframe_formula_injection():
    """Verify DataFrame sanitization catches formula payloads in cells while preserving originals."""
    raw_df = pd.DataFrame([
        {
            "username": "=DDE('cmd';'/C calc';'A0')",
            "source_ip": "-192.168.1.1",
            "message": "@danger",
            "status": "FAILED",
        }
    ])

    clean_df = sanitize_dataframe_for_csv(raw_df)

    # Clean DataFrame must have single quotes prefixed
    assert clean_df["username"].iloc[0].startswith("'=")
    assert clean_df["source_ip"].iloc[0].startswith("'-")
    assert clean_df["message"].iloc[0].startswith("'@")

    # Original DataFrame must remain untouched (evidence immutability)
    assert raw_df["username"].iloc[0] == "=DDE('cmd';'/C calc';'A0')"
    assert raw_df["source_ip"].iloc[0] == "-192.168.1.1"


# =========================================================
# CSV Export Tests
# =========================================================
def test_export_events_to_csv_basic(sample_events_df):
    """Test exporting valid events to CSV format."""
    csv_text = export_events_to_csv(sample_events_df)
    reader = list(csv.reader(io.StringIO(csv_text)))
    assert len(reader) == 4  # Header + 3 rows
    headers = reader[0]
    assert "event_id" in headers
    assert "username" in headers
    assert "source_ip" in headers
    assert "status" in headers

    # Verify content parsed accurately
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows[0]["username"] == "admin"
    assert rows[0]["status"] == "FAILED"


def test_export_events_to_csv_empty():
    """Verify exporting empty DataFrame returns headers without error."""
    csv_text = export_events_to_csv(pd.DataFrame())
    reader = list(csv.reader(io.StringIO(csv_text)))
    assert len(reader) == 1
    assert "event_id" in reader[0]


def test_export_events_to_csv_filtered(sample_events_df):
    """Verify CSV export strictly honors applied filters."""
    # Filter by status
    csv_text = export_events_to_csv(sample_events_df, filters_applied={"status": ["FAILED"]})
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == 1
    assert rows[0]["event_id"] == "EVT-101"

    # Filter by username
    csv_text_user = export_events_to_csv(sample_events_df, filters_applied={"username": "bob"})
    rows_user = list(csv.DictReader(io.StringIO(csv_text_user)))
    assert len(rows_user) == 1
    assert rows_user[0]["username"] == "bob"


def test_export_alerts_to_csv_basic(sample_alerts_list, sample_triage_mgr):
    """Test exporting alerts with persistent triage state to CSV."""
    csv_text = export_alerts_to_csv(sample_alerts_list, triage_manager=sample_triage_mgr)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == 2

    alt1 = rows[0]
    assert alt1["alert_id"] == "ALT-101"
    assert alt1["severity"] == "CRITICAL"
    assert alt1["status"] == "Investigating"
    assert alt1["analyst_notes"] == "Validating firewall logs."
    assert alt1["disposition_reason"] == "Confirmed attack."


def test_export_alerts_to_csv_empty():
    """Verify exporting empty alerts returns header line."""
    csv_text = export_alerts_to_csv([])
    reader = list(csv.reader(io.StringIO(csv_text)))
    assert len(reader) == 1
    assert "alert_id" in reader[0]


def test_export_alerts_to_csv_filtered(sample_alerts_list):
    """Verify alert CSV export honors severity filter."""
    csv_text = export_alerts_to_csv(sample_alerts_list, filters_applied={"severity": ["CRITICAL"]})
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == 1
    assert rows[0]["alert_id"] == "ALT-101"


# =========================================================
# Structured JSON Report Tests
# =========================================================
def test_generate_structured_json_report_basic(sample_events_df, sample_alerts_list, sample_triage_mgr):
    """Test generating a structured JSON report with all required sections."""
    json_text = generate_structured_json_report(
        sample_events_df,
        sample_alerts_list,
        triage_manager=sample_triage_mgr,
        source_name="C:/temp/incident_logs.csv",
        filters_applied={"severity": ["CRITICAL", "MEDIUM"]},
        executive_summary="Multiple threats detected.",
    )

    data = json.loads(json_text)
    assert "report_metadata" in data
    assert "period_summary" in data
    assert "correlated_alerts" in data
    assert "evidence_scope" in data

    # Metadata checks
    meta = data["report_metadata"]
    assert meta["report_title"] == "SentinelSOC Incident & Security Analytics Report"
    assert "generated_at" in meta
    # Source dataset must have local path stripped
    assert meta["source_dataset"] == "incident_logs.csv"
    assert meta["environment_sanitized"] is True
    assert "disclaimer" in meta

    # Period summary checks
    summary = data["period_summary"]
    assert summary["total_events_analyzed"] == 3
    assert summary["total_alerts_detected"] == 2
    assert summary["authentication_metrics"]["failed_logins"] == 1
    assert summary["authentication_metrics"]["successful_logins"] == 2
    assert summary["alerts_by_severity"]["CRITICAL"] == 1
    assert summary["alerts_by_severity"]["MEDIUM"] == 1

    # Correlated alerts checks
    alerts = data["correlated_alerts"]
    assert len(alerts) == 2
    assert alerts[0]["alert_id"] == "ALT-101"
    assert alerts[0]["status"] == "Investigating"
    assert alerts[0]["analyst_notes"] == "Validating firewall logs."


def test_generate_structured_json_report_empty():
    """Verify generating JSON report on empty dataset produces valid JSON without errors."""
    json_text = generate_structured_json_report(pd.DataFrame(), [])
    data = json.loads(json_text)
    assert data["period_summary"]["total_events_analyzed"] == 0
    assert data["period_summary"]["total_alerts_detected"] == 0
    assert len(data["correlated_alerts"]) == 0


def test_sanitize_source_name():
    """Verify source name scrubbing removes absolute host directory paths."""
    assert sanitize_source_name("C:\\Users\\Analyst\\AppData\\Local\\Temp\\logs.csv") == "logs.csv"
    assert sanitize_source_name("/var/log/auth.log") == "auth.log"
    assert sanitize_source_name(None) == "Unspecified Dataset"
    assert sanitize_source_name("None") == "Unspecified Dataset"


# =========================================================
# Evidence Immutability Test
# =========================================================
def test_original_evidence_not_altered(sample_events_df, sample_alerts_list):
    """Critical requirement: Exporting reports must never alter in-memory evidence."""
    # Add formula payload to the in-memory dataframe
    sample_events_df.at[0, "message"] = "=MALICIOUS_DDE_PAYLOAD()"
    orig_message = sample_events_df.at[0, "message"]
    orig_alert_status = sample_alerts_list[0].status

    # Perform CSV & JSON exports
    _ = export_events_to_csv(sample_events_df)
    _ = export_alerts_to_csv(sample_alerts_list)
    _ = generate_structured_json_report(sample_events_df, sample_alerts_list)

    # Confirm original in-memory data remains unchanged
    assert sample_events_df.at[0, "message"] == orig_message
    assert sample_alerts_list[0].status == orig_alert_status
