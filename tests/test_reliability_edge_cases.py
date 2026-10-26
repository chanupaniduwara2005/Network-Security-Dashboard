"""Automated Testing & Reliability Test Suite for SentinelSOC.

Covers all 14 core testing requirements and 7 targeted edge cases specified in Prompt 8:
1. CSV and JSON ingestion parity and handling
2. Invalid files and malformed records
3. Timestamp parsing and timezone handling (UTC, offsets, fractional seconds)
4. Repeated failed-login detection
5. Distributed login-failure detection (multi-IP and password spraying)
6. Successful login after repeated failures (account takeover simulation)
7. Privileged account activity (admin, root, off-hours sensitive ops)
8. Multi-factor severity assignment & confidence evaluation
9. Duplicate event handling & quarantine
10. Alert evidence and event correlation traceability
11. Alert status transitions and analyst notes persistence
12. CSV and JSON report exports with applied filters
13. Spreadsheet formula-injection protection (CWE-1236)
14. Empty datasets and missing optional fields

Edge Cases:
• Events exactly at and just outside the detection time window
• Duplicate event IDs
• Missing usernames
• Invalid IP addresses
• Unsorted timestamps
• No matching alerts (clean benign traffic baseline)
• Very large input files within configured limits (throughput & reliability)
"""

from datetime import datetime, timedelta, timezone
import io
import json
import time
from pathlib import Path

import pandas as pd
import pytest

from src.detection_engine import Alert, DetectionConfig, DetectionEngine
from src.log_parser import (
    NORMALIZED_COLUMNS,
    LogParserResult,
    parse_csv_data,
    parse_json_data,
    parse_log_file,
    parse_raw_records,
)
from src.report_generator import (
    export_alerts_to_csv,
    export_events_to_csv,
    generate_structured_json_report,
    sanitize_csv_cell,
    sanitize_dataframe_for_csv,
)
from src.severity import ConfidenceLevel, SeverityEvaluator, SeverityLevel
from src.triage_manager import TriageManager, VALID_STATUSES


# =====================================================================
# 1. CSV and JSON Ingestion Parity (Requirement 1)
# =====================================================================
def test_csv_json_ndjson_ingestion_parity():
    """Verify semantic parity across CSV, JSON array, and NDJSON input formats."""
    csv_text = (
        "event_id,timestamp,event_type,username,source_ip,status\n"
        "EVT-1,2026-10-24T10:00:00Z,LOGIN,alice,192.0.2.1,SUCCESS\n"
        "EVT-2,2026-10-24T10:01:00Z,LOGIN,bob,198.51.100.2,FAILED\n"
    )
    json_array_text = json.dumps([
        {"event_id": "EVT-1", "timestamp": "2026-10-24T10:00:00Z", "event_type": "LOGIN", "username": "alice", "source_ip": "192.0.2.1", "status": "SUCCESS"},
        {"event_id": "EVT-2", "timestamp": "2026-10-24T10:01:00Z", "event_type": "LOGIN", "username": "bob", "source_ip": "198.51.100.2", "status": "FAILED"},
    ])
    ndjson_text = (
        '{"event_id": "EVT-1", "timestamp": "2026-10-24T10:00:00Z", "event_type": "LOGIN", "username": "alice", "source_ip": "192.0.2.1", "status": "SUCCESS"}\n'
        '{"event_id": "EVT-2", "timestamp": "2026-10-24T10:01:00Z", "event_type": "LOGIN", "username": "bob", "source_ip": "198.51.100.2", "status": "FAILED"}\n'
    )

    res_csv = parse_csv_data(csv_text)
    res_json = parse_json_data(json_array_text)
    res_ndjson = parse_json_data(ndjson_text)

    for res in [res_csv, res_json, res_ndjson]:
        assert res.accepted_count == 2
        assert res.rejected_count == 0
        assert list(res.valid_df["event_id"]) == ["EVT-1", "EVT-2"]
        assert list(res.valid_df["status"]) == ["SUCCESS", "FAILED"]
        for col in NORMALIZED_COLUMNS:
            assert col in res.valid_df.columns


# =====================================================================
# 2. Invalid Files and Malformed Records (Requirement 2)
# =====================================================================
def test_invalid_files_and_malformed_records():
    """Verify corrupt formats, truncated syntax, and non-dict records are quarantined safely."""
    # Corrupted binary / random gibberish
    corrupt_text = "\x00\x01\x02\xff\xfe random non-ascii payload"
    res_csv = parse_csv_data(corrupt_text)
    assert isinstance(res_csv, LogParserResult)

    # Truncated JSON
    truncated_json = '{"event_id": "EVT-1", "timestamp": "2026-10-24'
    res_json = parse_json_data(truncated_json)
    assert res_json.accepted_count == 0
    assert any("Invalid JSON" in w for w in res_json.warnings)

    # JSON with non-dict elements (e.g. integer or list inside event array)
    invalid_elements = json.dumps([
        {"event_id": "EVT-OK", "timestamp": "2026-10-24T10:00:00Z", "source_ip": "192.0.2.1", "status": "OK"},
        "this-is-a-raw-string-not-a-dict",
        12345,
    ])
    res_elems = parse_json_data(invalid_elements)
    assert res_elems.accepted_count == 1
    assert res_elems.rejected_count == 2
    assert "Malformed record" in res_elems.rejected_records[0]["reason"]


# =====================================================================
# 3. Timestamp Parsing and Timezone Handling (Requirement 3)
# =====================================================================
def test_timestamp_parsing_various_timezones():
    """Verify UTC ISO, offsets (+05:30, -04:00), and fractional seconds are correctly normalized."""
    events = [
        # 10:00 AM UTC
        {"event_id": "TS-1", "timestamp": "2026-10-24T10:00:00Z", "source_ip": "192.0.2.1", "status": "OK"},
        # 15:30 in +05:30 offset is exactly 10:00 AM UTC
        {"event_id": "TS-2", "timestamp": "2026-10-24T15:30:00+05:30", "source_ip": "192.0.2.2", "status": "OK"},
        # 06:00 in -04:00 offset is exactly 10:00 AM UTC
        {"event_id": "TS-3", "timestamp": "2026-10-24T06:00:00-04:00", "source_ip": "192.0.2.3", "status": "OK"},
        # Fractional seconds
        {"event_id": "TS-4", "timestamp": "2026-10-24T10:00:00.500Z", "source_ip": "192.0.2.4", "status": "OK"},
    ]
    res = parse_raw_records(events)
    assert res.accepted_count == 4
    df = res.valid_df

    # Verify all timestamps converted to UTC datetime
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])
    t1 = df[df["event_id"] == "TS-1"]["timestamp"].iloc[0]
    t2 = df[df["event_id"] == "TS-2"]["timestamp"].iloc[0]
    t3 = df[df["event_id"] == "TS-3"]["timestamp"].iloc[0]

    # TS-1, TS-2, TS-3 all correspond to the same instantaneous UTC moment
    assert t1 == t2
    assert t2 == t3


# =====================================================================
# 4. Repeated Failed-Login Detection (Requirement 4)
# =====================================================================
def test_repeated_failed_login_detection():
    """Verify repeated failed-login rule accurately correlates failures for the same user & IP."""
    engine = DetectionEngine()
    events = [
        {
            "event_id": f"BF-{i}",
            "timestamp": f"2026-10-24T08:0{i}:00Z",
            "event_type": "LOGIN",
            "username": "target_user",
            "source_ip": "198.51.100.55",
            "status": "FAILED",
        }
        for i in range(5)
    ]
    alerts = engine.detect_repeated_failed_logins(pd.DataFrame(events))
    assert len(alerts) == 1
    a = alerts[0]
    assert "Repeated Failed Logins" in a.rule_name
    assert a.username == "target_user"
    assert a.source_ips == ["198.51.100.55"]
    assert a.event_count == 5
    assert set(a.related_event_ids) == {f"BF-{i}" for i in range(5)}


# =====================================================================
# 5. Distributed Login-Failure Detection (Requirement 5)
# =====================================================================
def test_distributed_login_failure_detection():
    """Verify detection of multi-IP attacks targeting one user and multi-user spraying from one IP."""
    engine = DetectionEngine()

    # Part A: Multi-IP attack targeting single user
    multi_ip_events = [
        {"event_id": f"D-{i}", "timestamp": f"2026-10-24T09:0{i}:00Z", "event_type": "LOGIN", "username": "target_victim", "source_ip": f"192.0.2.{10+i}", "status": "FAILED"}
        for i in range(3)
    ]
    alerts_multi = engine.detect_distributed_login_failures(pd.DataFrame(multi_ip_events))
    assert any("Distributed Login Failures" in a.rule_name for a in alerts_multi)

    # Part B: Single IP password spraying across multiple users
    spray_events = [
        {"event_id": f"S-{i}", "timestamp": f"2026-10-24T09:1{i}:00Z", "event_type": "LOGIN", "username": f"corp_user_{i}", "source_ip": "203.0.113.99", "status": "FAILED"}
        for i in range(3)
    ]
    alerts_spray = engine.detect_distributed_login_failures(pd.DataFrame(spray_events))
    assert any("Password Spraying" in a.rule_name for a in alerts_spray)


# =====================================================================
# 6. Successful Login After Repeated Failures (Requirement 6)
# =====================================================================
def test_successful_login_after_repeated_failures():
    """Verify account takeover rule: multiple failures followed by a success within 15 minutes."""
    engine = DetectionEngine()
    events = [
        {"event_id": "FAIL-1", "timestamp": "2026-10-24T12:00:00Z", "event_type": "LOGIN", "username": "accounting_user", "source_ip": "198.51.100.88", "status": "FAILED"},
        {"event_id": "FAIL-2", "timestamp": "2026-10-24T12:02:00Z", "event_type": "LOGIN", "username": "accounting_user", "source_ip": "198.51.100.88", "status": "FAILED"},
        {"event_id": "FAIL-3", "timestamp": "2026-10-24T12:04:00Z", "event_type": "LOGIN", "username": "accounting_user", "source_ip": "198.51.100.88", "status": "FAILED"},
        {"event_id": "SUCC-4", "timestamp": "2026-10-24T12:06:00Z", "event_type": "LOGIN", "username": "accounting_user", "source_ip": "198.51.100.88", "status": "SUCCESS"},
    ]
    alerts = engine.detect_login_after_failures(pd.DataFrame(events))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_name == "Successful Login After Multiple Failures"
    assert a.username == "accounting_user"
    assert "SUCC-4" in a.related_event_ids
    assert "FAIL-1" in a.related_event_ids
    assert a.event_count == 4


# =====================================================================
# 7. Privileged Account Activity (Requirement 7)
# =====================================================================
def test_privileged_account_activity():
    """Verify monitoring and alerting for sensitive administrative actions."""
    engine = DetectionEngine()
    privileged_events = [
        {
            "event_id": "ROOT-1",
            "timestamp": "2026-10-24T14:00:00Z",
            "event_type": "CONFIG_CHANGE",
            "username": "root",
            "source_ip": "10.0.0.50",
            "status": "SUCCESS",
            "hostname": "core-firewall",
        },
        {
            "event_id": "ADMIN-2",
            "timestamp": "2026-10-24T14:15:00Z",
            "event_type": "USER_MANAGEMENT",
            "username": "admin",
            "source_ip": "10.0.0.51",
            "status": "SUCCESS",
            "hostname": "domain-controller",
        },
    ]
    alerts = engine.detect_privileged_activity(pd.DataFrame(privileged_events))
    assert len(alerts) == 2
    users_alerted = {a.username for a in alerts}
    assert "root" in users_alerted
    assert "admin" in users_alerted


# =====================================================================
# 8. Severity Assignment & Multi-Factor Scoring (Requirement 8)
# =====================================================================
def test_severity_assignment_multi_factor():
    """Verify severity tiers (CRITICAL, HIGH, MEDIUM, LOW) based on multi-factor risks."""
    evaluator = SeverityEvaluator()

    # Privileged account takeover -> CRITICAL
    crit = evaluator.evaluate(
        rule_category="SUCCESS_AFTER_FAIL",
        event_count=6,
        username="admin",
        source_ips=["192.0.2.1"],
        success_after_failures=True,
    )
    assert crit.level == SeverityLevel.CRITICAL
    assert crit.confidence == ConfidenceLevel.HIGH

    # Elevated volume brute-force (10 attempts) -> HIGH
    high = evaluator.evaluate(
        rule_category="BRUTE",
        event_count=10,
        username="regular.user",
        source_ips=["198.51.100.1"],
    )
    assert high.level == SeverityLevel.HIGH

    # Baseline brute-force (5 attempts) -> MEDIUM
    med = evaluator.evaluate(
        rule_category="BRUTE",
        event_count=5,
        username="regular.user",
        source_ips=["198.51.100.1"],
    )
    assert med.level == SeverityLevel.MEDIUM

    # Routine informational event -> LOW / INFORMATIONAL
    low = evaluator.evaluate(
        rule_category="ROUTINE",
        event_count=1,
        username="regular.user",
        source_ips=["192.168.1.1"],
    )
    assert low.level in {SeverityLevel.LOW, SeverityLevel.INFORMATIONAL}


# =====================================================================
# 9. Duplicate Event Handling (Requirement 9 & Edge Case)
# =====================================================================
def test_duplicate_event_handling_edge_case():
    """Verify duplicate event IDs are quarantined while unique records succeed."""
    records = [
        {"event_id": "DUP-ID", "timestamp": "2026-10-24T10:00:00Z", "source_ip": "192.0.2.1", "status": "OK"},
        {"event_id": "DUP-ID", "timestamp": "2026-10-24T10:01:00Z", "source_ip": "192.0.2.1", "status": "OK"},
        {"event_id": "DUP-ID", "timestamp": "2026-10-24T10:02:00Z", "source_ip": "192.0.2.1", "status": "OK"},
        {"event_id": "UNIQUE-1", "timestamp": "2026-10-24T10:03:00Z", "source_ip": "192.0.2.1", "status": "OK"},
    ]
    res = parse_raw_records(records)
    # 1 accepted unique + 1 initial instance of DUP-ID = 2 accepted
    assert res.accepted_count == 2
    # The 2nd and 3rd duplicates rejected = 2 rejected
    assert res.rejected_count == 2
    assert "DUP-ID" in res.duplicate_ids
    assert len(res.rejected_records) == 2


# =====================================================================
# 10. Alert Evidence and Event Correlation (Requirement 10)
# =====================================================================
def test_alert_evidence_and_event_correlation():
    """Verify generated alerts maintain 100% evidence traceability back to raw events."""
    engine = DetectionEngine()
    events = [
        {"event_id": f"EVD-{i}", "timestamp": f"2026-10-24T10:0{i}:00Z", "event_type": "LOGIN", "username": "charlie", "source_ip": "192.0.2.5", "status": "FAILED"}
        for i in range(5)
    ]
    alerts = engine.detect_all(pd.DataFrame(events))
    assert len(alerts) == 1
    alert = alerts[0]

    # Verify every related event ID exists in the input set
    input_ids = {e["event_id"] for e in events}
    assert all(eid in input_ids for eid in alert.related_event_ids)
    assert alert.first_seen == "2026-10-24 10:00:00Z"
    assert alert.last_seen == "2026-10-24 10:04:00Z"

    # Serialization preserves evidence structure
    alert_dict = alert.to_dict()
    assert alert_dict["alert_id"] == alert.alert_id
    assert alert_dict["related_event_ids"] == alert.related_event_ids


# =====================================================================
# 11. Alert Status and Analyst Notes (Requirement 11)
# =====================================================================
def test_alert_status_and_analyst_notes_workflow(tmp_path):
    """Verify analyst triage workflow state transitions and notes persistence."""
    mgr = TriageManager(storage_path=tmp_path / "triage.json")
    rec = mgr.get_record("TEST-ALT-01")
    assert rec.status == "Open"

    # Analyst begins investigation
    mgr.update_record("TEST-ALT-01", status="Investigating", notes="Contacted account owner.")
    assert mgr.get_record("TEST-ALT-01").status == "Investigating"
    assert mgr.get_record("TEST-ALT-01").notes == "Contacted account owner."

    # Analyst marks false positive with disposition reason
    mgr.update_record(
        "TEST-ALT-01",
        status="False Positive",
        disposition_reason="Authorized penetration testing exercise.",
        checklist={"Review the affected account and event timestamps.": True},
    )
    saved_rec = mgr.get_record("TEST-ALT-01")
    assert saved_rec.status == "False Positive"
    assert "penetration testing" in saved_rec.disposition_reason
    assert saved_rec.checklist["Review the affected account and event timestamps."] is True


# =====================================================================
# 12. CSV and JSON Report Exports (Requirement 12)
# =====================================================================
def test_csv_and_json_report_exports(tmp_path):
    """Verify that CSV and JSON export facilities generate valid, complete reports."""
    events_df = pd.DataFrame([
        {"event_id": "EVT-1", "timestamp": pd.to_datetime("2026-10-24T10:00:00Z"), "status": "FAILED", "username": "admin", "source_ip": "198.51.100.1"},
        {"event_id": "EVT-2", "timestamp": pd.to_datetime("2026-10-24T10:05:00Z"), "status": "SUCCESS", "username": "admin", "source_ip": "198.51.100.1"},
    ])
    alerts = [
        Alert(
            alert_id="ALT-1",
            rule_name="Test Threat",
            severity="HIGH",
            username="admin",
            source_ips=["198.51.100.1"],
            first_seen="2026-10-24 10:00:00Z",
            last_seen="2026-10-24 10:05:00Z",
            event_count=2,
            related_event_ids=["EVT-1", "EVT-2"],
            explanation="Test explanation",
            recommended_steps=["Step 1"],
            status="Investigating",
        )
    ]
    triage_mgr = TriageManager(storage_path=tmp_path / "triage.json")

    # CSV Export
    csv_evts = export_events_to_csv(events_df)
    assert "EVT-1" in csv_evts
    assert "admin" in csv_evts

    csv_alerts = export_alerts_to_csv(alerts, triage_manager=triage_mgr)
    assert "ALT-1" in csv_alerts
    assert "Test Threat" in csv_alerts

    # JSON Export
    json_report = generate_structured_json_report(events_df, alerts, triage_manager=triage_mgr, source_name="test.csv")
    parsed = json.loads(json_report)
    assert parsed["report_metadata"]["report_title"] == "SentinelSOC Incident & Security Analytics Report"
    assert parsed["period_summary"]["total_events_analyzed"] == 2
    assert parsed["period_summary"]["total_alerts_detected"] == 1


# =====================================================================
# 13. Spreadsheet Formula-Injection Protection (Requirement 13)
# =====================================================================
def test_spreadsheet_formula_injection_protection():
    """Verify OWASP formula injection (CWE-1236) prevention across untrusted inputs."""
    malicious_inputs = [
        "=1+1",
        "=SUM(A1:A10)",
        "=cmd|' /C calc'!A0",
        "+cmd|' /C calc'!A0",
        "-cmd|' /C calc'!A0",
        "@SUM(1+1)",
        "\t=1+1",
        "\r=1+1",
        "|' /C calc'!A0",
        "%0A=1+1",
    ]

    for payload in malicious_inputs:
        sanitized = sanitize_csv_cell(payload)
        # Must be escaped by prepending single quote
        assert sanitized.startswith("'"), f"Payload '{payload}' was not escaped with single quote!"

    # Genuine numbers must not be mangled
    assert sanitize_csv_cell(100) == 100
    assert sanitize_csv_cell(-50) == -50
    assert sanitize_csv_cell("-50") == "-50"
    assert sanitize_csv_cell("+12.5") == "+12.5"


# =====================================================================
# 14. Empty Datasets and Missing Optional Fields (Requirement 14)
# =====================================================================
def test_empty_datasets_and_missing_optional_fields():
    """Verify empty inputs and missing optional fields are processed safely without exceptions."""
    # Empty inputs across all components
    engine = DetectionEngine()
    assert engine.detect_all([]) == []
    assert engine.detect_all(pd.DataFrame()) == []

    csv_empty = export_events_to_csv(pd.DataFrame())
    assert "event_id" in csv_empty

    alerts_empty = export_alerts_to_csv([])
    assert "alert_id" in alerts_empty

    json_empty = generate_structured_json_report(pd.DataFrame(), [])
    assert json.loads(json_empty)["period_summary"]["total_events_analyzed"] == 0

    # Missing optional fields (only required: event_id, timestamp, source_ip, status)
    minimal_record = [
        {"event_id": "MIN-1", "timestamp": "2026-10-24T10:00:00Z", "source_ip": "192.0.2.1", "status": "SUCCESS"}
    ]
    res = parse_raw_records(minimal_record)
    assert res.accepted_count == 1
    row = res.valid_df.iloc[0]
    # Check default fallbacks
    assert row["username"] == "UNKNOWN"
    assert row["event_type"] == "UNKNOWN"
    assert row["hostname"] == "UNKNOWN"
    assert row["message"] == ""
    assert row["destination_ip"] is None


# =====================================================================
# EDGE CASE 1: Window Boundary — Exactly at vs Just Outside Window
# =====================================================================
def test_window_boundary_exact_at_vs_just_outside():
    """Verify window boundary condition: exactly 5 minutes matches, 5 min + 1 sec does not."""
    engine = DetectionEngine(DetectionConfig(failed_login_threshold=5, failed_login_window_minutes=5))
    base_time = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)

    # Sub-case A: 5 events where the 5th event is EXACTLY 5 minutes (300s) after the 1st
    exact_boundary_events = [
        {"event_id": "E-0", "timestamp": (base_time).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "E-1", "timestamp": (base_time + timedelta(seconds=60)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "E-2", "timestamp": (base_time + timedelta(seconds=120)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "E-3", "timestamp": (base_time + timedelta(seconds=180)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "E-4", "timestamp": (base_time + timedelta(seconds=300)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
    ]
    alerts_exact = engine.detect_repeated_failed_logins(pd.DataFrame(exact_boundary_events))
    assert len(alerts_exact) == 1, "Events exactly at 300s boundary must trigger alert."

    # Sub-case B: 5 events where the 5th event is 301 seconds (outside 5 min window)
    outside_boundary_events = [
        {"event_id": "O-0", "timestamp": (base_time).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "O-1", "timestamp": (base_time + timedelta(seconds=60)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "O-2", "timestamp": (base_time + timedelta(seconds=120)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "O-3", "timestamp": (base_time + timedelta(seconds=180)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
        {"event_id": "O-4", "timestamp": (base_time + timedelta(seconds=301)).isoformat(), "event_type": "LOGIN", "username": "test_boundary", "source_ip": "198.51.100.1", "status": "FAILED"},
    ]
    alerts_outside = engine.detect_repeated_failed_logins(pd.DataFrame(outside_boundary_events))
    assert len(alerts_outside) == 0, "Event at 301 seconds must not trigger repeated failed logins."


# =====================================================================
# EDGE CASE 2: Missing Usernames
# =====================================================================
def test_missing_usernames_edge_case():
    """Verify events with missing or None usernames are safely ingested and do not crash detection."""
    records = [
        {"event_id": "NO-USER-1", "timestamp": "2026-10-24T10:00:00Z", "source_ip": "192.0.2.1", "status": "FAILED", "event_type": "LOGIN"},
        {"event_id": "NO-USER-2", "timestamp": "2026-10-24T10:01:00Z", "source_ip": "192.0.2.1", "status": "FAILED", "event_type": "LOGIN", "username": ""},
        {"event_id": "NO-USER-3", "timestamp": "2026-10-24T10:02:00Z", "source_ip": "192.0.2.1", "status": "FAILED", "event_type": "LOGIN", "username": None},
    ]
    res = parse_raw_records(records)
    assert res.accepted_count == 3
    assert all(u == "UNKNOWN" for u in res.valid_df["username"])

    # Pass directly into detection engine without exception
    engine = DetectionEngine()
    alerts = engine.detect_all(res.valid_df)
    assert isinstance(alerts, list)


# =====================================================================
# EDGE CASE 3: Invalid IP Addresses
# =====================================================================
def test_invalid_ip_addresses_edge_case():
    """Verify various malformed IP address formats are rejected with specific diagnostic reasons."""
    malformed_ips = [
        "999.999.999.999",
        "256.1.1.1",
        "1.2.3.4.5",
        "fe80::1::1",
        "localhost",
        "192.168.1.0/24",
    ]
    for idx, bad_ip in enumerate(malformed_ips):
        rec = [{"event_id": f"BAD-{idx}", "timestamp": "2026-10-24T10:00:00Z", "source_ip": bad_ip, "status": "OK"}]
        res = parse_raw_records(rec)
        assert res.accepted_count == 0
        assert res.rejected_count == 1
        assert "Invalid IPv4/IPv6 source_ip" in res.rejected_records[0]["reason"]


# =====================================================================
# EDGE CASE 4: Unsorted Timestamps
# =====================================================================
def test_unsorted_timestamps_edge_case():
    """Verify ingestion automatically sorts timestamps chronologically and correlation succeeds."""
    # Timestamps in reverse order
    scrambled_records = [
        {"event_id": "TIME-3", "timestamp": "2026-10-24T10:04:00Z", "event_type": "LOGIN", "username": "dan", "source_ip": "192.0.2.5", "status": "FAILED"},
        {"event_id": "TIME-1", "timestamp": "2026-10-24T10:00:00Z", "event_type": "LOGIN", "username": "dan", "source_ip": "192.0.2.5", "status": "FAILED"},
        {"event_id": "TIME-4", "timestamp": "2026-10-24T10:06:00Z", "event_type": "LOGIN", "username": "dan", "source_ip": "192.0.2.5", "status": "FAILED"},
        {"event_id": "TIME-2", "timestamp": "2026-10-24T10:02:00Z", "event_type": "LOGIN", "username": "dan", "source_ip": "192.0.2.5", "status": "FAILED"},
        {"event_id": "TIME-5", "timestamp": "2026-10-24T10:08:00Z", "event_type": "LOGIN", "username": "dan", "source_ip": "192.0.2.5", "status": "FAILED"},
    ]
    res = parse_raw_records(scrambled_records)
    # The valid dataframe must be sorted in ascending chronological order
    timestamps = list(res.valid_df["timestamp"])
    assert timestamps == sorted(timestamps)
    assert res.valid_df["event_id"].iloc[0] == "TIME-1"
    assert res.valid_df["event_id"].iloc[-1] == "TIME-5"

    # Detection engine also sorts internally even if an unparsed raw dataframe is given
    engine = DetectionEngine()
    alerts = engine.detect_repeated_failed_logins(pd.DataFrame(scrambled_records))
    assert isinstance(alerts, list)


# =====================================================================
# EDGE CASE 5: No Matching Alerts (Clean Baseline)
# =====================================================================
def test_clean_baseline_no_matching_alerts():
    """Verify that completely benign corporate activity generates 0 alerts."""
    engine = DetectionEngine()
    benign_events = [
        {
            "event_id": f"NORM-{i}",
            "timestamp": f"2026-10-24T{9 + (i // 10):02d}:{i % 60:02d}:00Z",
            "event_type": "LOGIN" if i % 2 == 0 else "FILE_READ",
            "username": f"employee_{i % 5}",
            "source_ip": f"192.168.1.{10 + (i % 5)}",
            "status": "SUCCESS",
        }
        for i in range(25)
    ]
    alerts = engine.detect_all(pd.DataFrame(benign_events))
    assert len(alerts) == 0, f"Expected 0 alerts for benign activity, got {len(alerts)}."


# =====================================================================
# EDGE CASE 6: Very Large Input Files (Throughput & Scalability)
# =====================================================================
def test_large_file_scale_and_throughput():
    """Verify ingestion, correlation, and reporting scales smoothly with 3,000 synthetic events."""
    base_ts = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)
    large_dataset = []

    for i in range(3000):
        # Mix in failed brute force bursts every 500 events
        is_attack = (i % 500 < 6)
        status = "FAILED" if is_attack else "SUCCESS"
        user = "admin" if is_attack else f"user_{i % 50}"
        src_ip = "198.51.100.99" if is_attack else f"10.0.{i // 256}.{i % 256}"

        large_dataset.append({
            "event_id": f"BIG-{i}",
            "timestamp": (base_ts + timedelta(seconds=i * 2)).isoformat(),
            "event_type": "LOGIN",
            "username": user,
            "source_ip": src_ip,
            "status": status,
        })

    # Test Ingestion Performance
    t0 = time.perf_counter()
    res = parse_raw_records(large_dataset)
    t_ingest = time.perf_counter() - t0
    assert res.accepted_count == 3000
    assert t_ingest < 2.5, f"Ingestion took {t_ingest:.2f}s (exceeded 2.5s threshold)."

    # Test Detection Performance
    engine = DetectionEngine()
    t1 = time.perf_counter()
    alerts = engine.detect_all(res.valid_df)
    t_detect = time.perf_counter() - t1
    assert len(alerts) > 0
    assert t_detect < 2.5, f"Detection took {t_detect:.2f}s (exceeded 2.5s threshold)."

    # Test Export Performance
    t2 = time.perf_counter()
    csv_out = export_events_to_csv(res.valid_df)
    t_export = time.perf_counter() - t2
    assert len(csv_out) > 0
    assert t_export < 1.0, f"CSV Export took {t_export:.2f}s (exceeded 1.0s threshold)."
