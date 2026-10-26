"""Unit tests for SentinelSOC Analytics visualizations and period comparison logic."""

import pandas as pd
import plotly.graph_objects as go
import pytest

from src.dashboard_utils import (
    compare_time_periods,
    create_alert_status_distribution_chart,
    create_detection_rule_frequency_chart,
    create_failed_logins_trend_chart,
    create_repeated_failure_ips_chart,
    create_top_targeted_users_chart,
)
from src.detection_engine import Alert
from src.triage_manager import TriageManager


@pytest.fixture
def analytics_sample_events():
    return pd.DataFrame([
        {
            "event_id": f"EVT-{i}",
            "timestamp": pd.to_datetime(f"2026-10-24T{10 + i // 10:02d}:{i % 60:02d}:00Z"),
            "event_type": "LOGIN",
            "username": "admin" if i < 15 else ("alice" if i < 25 else "bob"),
            "source_ip": "198.51.100.20" if i < 12 else ("203.0.113.5" if i < 20 else "192.168.1.10"),
            "status": "FAILED" if i % 2 == 0 else "SUCCESS",
            "message": "Auth event",
        }
        for i in range(30)
    ])


@pytest.fixture
def analytics_sample_alerts():
    return [
        Alert(
            alert_id="ALT-001",
            rule_name="Repeated Failed Logins",
            severity="CRITICAL",
            username="admin",
            source_ips=["198.51.100.20"],
            first_seen="2026-10-24 10:05:00Z",
            last_seen="2026-10-24 10:10:00Z",
            event_count=5,
            related_event_ids=["EVT-0", "EVT-2", "EVT-4", "EVT-6", "EVT-8"],
            explanation="Multiple login failures",
            recommended_steps=["Isolate IP"],
            status="Open",
        ),
        Alert(
            alert_id="ALT-002",
            rule_name="Distributed Password Spraying",
            severity="HIGH",
            username="alice",
            source_ips=["203.0.113.5", "198.51.100.20"],
            first_seen="2026-10-24 10:15:00Z",
            last_seen="2026-10-24 10:20:00Z",
            event_count=4,
            related_event_ids=["EVT-16", "EVT-18"],
            explanation="Spraying across multiple accounts",
            recommended_steps=["Reset passwords"],
            status="Investigating",
        ),
    ]


def test_failed_logins_trend_chart_with_data(analytics_sample_events):
    """Test creating failed login trend chart with valid events."""
    fig = create_failed_logins_trend_chart(analytics_sample_events)
    assert isinstance(fig, go.Figure)


def test_failed_logins_trend_chart_empty():
    """Verify failed login trend chart returns None gracefully when empty."""
    assert create_failed_logins_trend_chart(pd.DataFrame()) is None
    no_failures = pd.DataFrame([{"timestamp": "2026-10-24T10:00:00Z", "status": "SUCCESS"}])
    assert create_failed_logins_trend_chart(no_failures) is None


def test_top_targeted_users_chart_with_data(analytics_sample_events):
    """Test generating top targeted users bar chart."""
    fig = create_top_targeted_users_chart(analytics_sample_events)
    assert isinstance(fig, go.Figure)


def test_top_targeted_users_chart_empty():
    """Verify top targeted users chart returns None when empty."""
    assert create_top_targeted_users_chart(pd.DataFrame()) is None


def test_repeated_failure_ips_chart_with_data(analytics_sample_events):
    """Test generating repeated failure source IPs chart."""
    fig = create_repeated_failure_ips_chart(analytics_sample_events)
    assert isinstance(fig, go.Figure)


def test_repeated_failure_ips_chart_empty():
    """Verify repeated failure IPs chart returns None when empty."""
    assert create_repeated_failure_ips_chart(pd.DataFrame()) is None


def test_detection_rule_frequency_chart_with_data(analytics_sample_alerts):
    """Test generating detection rule frequency chart."""
    fig = create_detection_rule_frequency_chart(analytics_sample_alerts)
    assert isinstance(fig, go.Figure)


def test_detection_rule_frequency_chart_empty():
    """Verify rule frequency chart returns None for empty alerts."""
    assert create_detection_rule_frequency_chart([]) is None


def test_alert_status_distribution_chart(analytics_sample_alerts, tmp_path):
    """Test alert status donut chart with and without triage manager."""
    mgr = TriageManager(storage_path=tmp_path / "triage.json")
    fig = create_alert_status_distribution_chart(analytics_sample_alerts, mgr)
    assert isinstance(fig, go.Figure)
    assert create_alert_status_distribution_chart([]) is None


def test_compare_time_periods_success(analytics_sample_events, analytics_sample_alerts):
    """Test comparing two distinct time periods produces valid deltas and metrics."""
    min_ts = analytics_sample_events["timestamp"].min()
    max_ts = analytics_sample_events["timestamp"].max()
    mid_ts = min_ts + (max_ts - min_ts) / 2

    res = compare_time_periods(
        analytics_sample_events,
        analytics_sample_alerts,
        start_p1=min_ts,
        end_p1=mid_ts,
        start_p2=mid_ts,
        end_p2=max_ts,
    )

    assert res["has_data"] is True
    assert "period1" in res
    assert "period2" in res
    assert "deltas" in res
    assert "events" in res["deltas"]
    assert "failed_logins" in res["deltas"]
    assert "alerts" in res["deltas"]


def test_compare_time_periods_empty():
    """Test comparing time periods on empty DataFrame returns graceful status without crashing."""
    res = compare_time_periods(
        pd.DataFrame(),
        [],
        pd.Timestamp("2026-10-24 10:00:00Z"),
        pd.Timestamp("2026-10-24 10:30:00Z"),
        pd.Timestamp("2026-10-24 10:30:00Z"),
        pd.Timestamp("2026-10-24 11:00:00Z"),
    )
    assert res["has_data"] is False
