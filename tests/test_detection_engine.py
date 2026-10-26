"""Unit test suite for SentinelSOC threat detection engine."""

from datetime import datetime, timezone
import pandas as pd
import pytest

from src.detection_engine import Alert, DetectionConfig, DetectionEngine
from src.log_parser import parse_log_file


@pytest.fixture
def engine():
    """Provides a DetectionEngine instance with default parameters."""
    return DetectionEngine()


def test_repeated_failed_logins_triggers(engine):
    """5 failed logins within 5 minutes triggers Repeated Failed Logins rule."""
    events = [
        {
            "event_id": f"FAIL-{i}",
            "timestamp": f"2026-10-24T10:0{i}:00Z",
            "event_type": "LOGIN",
            "username": "victim.user",
            "source_ip": "198.51.100.20",
            "status": "FAILED",
        }
        for i in range(5)
    ]
    alerts = engine.detect_repeated_failed_logins(pd.DataFrame(events))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "Repeated Failed Logins (Potential Brute-Force)"
    assert alert.username == "victim.user"
    assert "198.51.100.20" in alert.source_ips
    assert alert.event_count == 5
    assert len(alert.related_event_ids) == 5
    assert alert.status == "NEW"


def test_repeated_failed_logins_below_threshold(engine):
    """4 failed logins (below threshold of 5) does NOT trigger the rule."""
    events = [
        {
            "event_id": f"FAIL-{i}",
            "timestamp": f"2026-10-24T10:0{i}:00Z",
            "event_type": "LOGIN",
            "username": "victim.user",
            "source_ip": "198.51.100.20",
            "status": "FAILED",
        }
        for i in range(4)
    ]
    alerts = engine.detect_repeated_failed_logins(pd.DataFrame(events))
    assert len(alerts) == 0


def test_repeated_failed_logins_outside_window(engine):
    """5 failed logins spread over 2 hours (outside 5 min window) does NOT trigger."""
    events = [
        {
            "event_id": f"FAIL-{i}",
            "timestamp": f"2026-10-24T{10+i:02d}:00:00Z",
            "event_type": "LOGIN",
            "username": "victim.user",
            "source_ip": "198.51.100.20",
            "status": "FAILED",
        }
        for i in range(5)
    ]
    alerts = engine.detect_repeated_failed_logins(pd.DataFrame(events))
    assert len(alerts) == 0


def test_distributed_login_failures_multi_ip(engine):
    """Failed logins against one user from 3 distinct IPs triggers Distributed rule."""
    events = [
        {"event_id": "D-1", "timestamp": "2026-10-24T11:00:00Z", "event_type": "LOGIN", "username": "alice", "source_ip": "192.0.2.1", "status": "FAILED"},
        {"event_id": "D-2", "timestamp": "2026-10-24T11:02:00Z", "event_type": "LOGIN", "username": "alice", "source_ip": "192.0.2.2", "status": "FAILED"},
        {"event_id": "D-3", "timestamp": "2026-10-24T11:04:00Z", "event_type": "LOGIN", "username": "alice", "source_ip": "192.0.2.3", "status": "FAILED"},
    ]
    alerts = engine.detect_distributed_login_failures(pd.DataFrame(events))
    assert any("Distributed Login Failures" in a.rule_name for a in alerts)
    target_alert = next(a for a in alerts if "Distributed Login Failures" in a.rule_name)
    assert target_alert.username == "alice"
    assert len(target_alert.source_ips) == 3


def test_password_spraying_single_ip_multi_user(engine):
    """Single IP failing logins across 3 distinct users triggers Password Spraying."""
    events = [
        {"event_id": "S-1", "timestamp": "2026-10-24T11:20:00Z", "event_type": "LOGIN", "username": "user1", "source_ip": "203.0.113.88", "status": "FAILED"},
        {"event_id": "S-2", "timestamp": "2026-10-24T11:20:10Z", "event_type": "LOGIN", "username": "user2", "source_ip": "203.0.113.88", "status": "FAILED"},
        {"event_id": "S-3", "timestamp": "2026-10-24T11:20:20Z", "event_type": "LOGIN", "username": "user3", "source_ip": "203.0.113.88", "status": "FAILED"},
    ]
    alerts = engine.detect_distributed_login_failures(pd.DataFrame(events))
    assert any("Password Spraying" in a.rule_name for a in alerts)
    spray_alert = next(a for a in alerts if "Password Spraying" in a.rule_name)
    assert "203.0.113.88" in spray_alert.source_ips
    assert spray_alert.event_count == 3


def test_login_after_failures_triggers(engine):
    """3 failures followed by 1 successful login triggers Login After Failures."""
    events = [
        {"event_id": "F-1", "timestamp": "2026-10-24T08:10:00Z", "event_type": "LOGIN", "username": "carol", "source_ip": "192.0.2.12", "status": "FAILED"},
        {"event_id": "F-2", "timestamp": "2026-10-24T08:11:00Z", "event_type": "LOGIN", "username": "carol", "source_ip": "192.0.2.12", "status": "FAILED"},
        {"event_id": "F-3", "timestamp": "2026-10-24T08:12:00Z", "event_type": "LOGIN", "username": "carol", "source_ip": "192.0.2.12", "status": "FAILED"},
        {"event_id": "OK-4", "timestamp": "2026-10-24T08:14:00Z", "event_type": "LOGIN", "username": "carol", "source_ip": "192.0.2.12", "status": "SUCCESS"},
    ]
    alerts = engine.detect_login_after_failures(pd.DataFrame(events))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "Successful Login After Multiple Failures"
    assert alert.username == "carol"
    assert alert.event_count == 4
    assert "OK-4" in alert.related_event_ids
    assert "F-1" in alert.related_event_ids


def test_login_after_failures_below_threshold(engine):
    """2 failures followed by success (threshold=3) does NOT trigger the rule."""
    events = [
        {"event_id": "F-1", "timestamp": "2026-10-24T08:10:00Z", "event_type": "LOGIN", "username": "carol", "source_ip": "192.0.2.12", "status": "FAILED"},
        {"event_id": "F-2", "timestamp": "2026-10-24T08:11:00Z", "event_type": "LOGIN", "username": "carol", "source_ip": "192.0.2.12", "status": "FAILED"},
        {"event_id": "OK-3", "timestamp": "2026-10-24T08:14:00Z", "event_type": "LOGIN", "username": "carol", "source_ip": "192.0.2.12", "status": "SUCCESS"},
    ]
    alerts = engine.detect_login_after_failures(pd.DataFrame(events))
    assert len(alerts) == 0


def test_privileged_activity_triggers(engine):
    """Privileged user ('admin') performing 'PRIVILEGE_ELEVATION' triggers contextual alert."""
    events = [
        {
            "event_id": "PRIV-1",
            "timestamp": "2026-10-24T08:45:00Z",
            "event_type": "PRIVILEGE_ELEVATION",
            "username": "admin",
            "source_ip": "192.0.2.10",
            "status": "SUCCESS",
            "hostname": "auth-server",
        }
    ]
    alerts = engine.detect_privileged_activity(pd.DataFrame(events))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "Privileged Account Sensitive Activity"
    assert alert.username == "admin"
    assert "contextual audit monitoring" in alert.explanation


def test_unprivileged_normal_user_no_privileged_alert(engine):
    """Standard user ('bob') reading a file does NOT trigger privileged activity."""
    events = [
        {
            "event_id": "NORM-1",
            "timestamp": "2026-10-24T08:05:00Z",
            "event_type": "LOGIN",
            "username": "bob.jones",
            "source_ip": "192.0.2.11",
            "status": "SUCCESS",
            "hostname": "workstation-02",
        }
    ]
    alerts = engine.detect_privileged_activity(pd.DataFrame(events))
    assert len(alerts) == 0


def test_suspicious_patterns_port_scan(engine):
    """PORT_SCAN event type triggers Network Reconnaissance alert."""
    events = [
        {
            "event_id": "SCAN-1",
            "timestamp": "2026-10-24T14:30:00Z",
            "event_type": "PORT_SCAN",
            "username": "scanner_bot",
            "source_ip": "198.51.100.99",
            "status": "BLOCKED",
            "hostname": "edge-router",
        }
    ]
    alerts = engine.detect_suspicious_patterns(pd.DataFrame(events))
    assert len(alerts) >= 1
    assert any("Reconnaissance" in a.rule_name for a in alerts)


def test_ordinary_activity_triggers_zero_alerts(engine):
    """Standard benign daily activity produces zero false-positive alerts."""
    events = [
        {"event_id": "B-1", "timestamp": "2026-10-24T09:00:00Z", "event_type": "LOGIN", "username": "emily", "source_ip": "192.0.2.15", "status": "SUCCESS"},
        {"event_id": "B-2", "timestamp": "2026-10-24T09:15:00Z", "event_type": "FILE_ACCESS", "username": "emily", "source_ip": "192.0.2.15", "status": "SUCCESS"},
        {"event_id": "B-3", "timestamp": "2026-10-24T17:00:00Z", "event_type": "LOGOUT", "username": "emily", "source_ip": "192.0.2.15", "status": "SUCCESS"},
    ]
    alerts = engine.detect_all(pd.DataFrame(events))
    assert len(alerts) == 0


def test_empty_events_handling(engine):
    """Empty dataframe or empty list returns empty list safely without crashing."""
    assert engine.detect_all([]) == []
    assert engine.detect_all(pd.DataFrame()) == []


def test_sample_security_logs_detection():
    """Verify that sample_security_logs.csv triggers expected security alerts."""
    result = parse_log_file("data/sample_security_logs.csv")
    assert result.has_data

    engine = DetectionEngine()
    alerts = engine.detect_all(result.valid_df)

    assert len(alerts) > 0

    # Ensure brute force on admin was caught
    assert any(
        a.username == "admin" and "Brute-Force" in a.rule_name
        for a in alerts
    ), "Expected Brute-Force alert on 'admin' account."

    # Ensure password spray was caught
    assert any(
        "Password Spraying" in a.rule_name
        for a in alerts
    ), "Expected Password Spraying alert."

    # Ensure port scan was caught
    assert any(
        "Reconnaissance" in a.rule_name
        for a in alerts
    ), "Expected Reconnaissance alert."
