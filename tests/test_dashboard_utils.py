"""Unit tests for dashboard utility functions and chart generators."""

import pandas as pd
import pytest
import plotly.graph_objects as go

from src.dashboard_utils import (
    create_alerts_severity_donut,
    create_events_by_type_bar,
    create_events_timeline_chart,
    create_top_failed_ips_bar,
    generate_dataset_summary,
)
from src.detection_engine import Alert


@pytest.fixture
def sample_events():
    return pd.DataFrame([
        {
            "event_id": "EVT-1",
            "timestamp": pd.to_datetime("2026-10-24T08:00:00Z"),
            "event_type": "LOGIN",
            "username": "alice",
            "source_ip": "192.0.2.10",
            "status": "SUCCESS",
        },
        {
            "event_id": "EVT-2",
            "timestamp": pd.to_datetime("2026-10-24T08:05:00Z"),
            "event_type": "LOGIN",
            "username": "bob",
            "source_ip": "198.51.100.20",
            "status": "FAILED",
        },
    ])


@pytest.fixture
def sample_alerts():
    return [
        Alert(
            alert_id="ALT-001",
            rule_name="Test Rule",
            severity="HIGH",
            username="bob",
            source_ips=["198.51.100.20"],
            first_seen="2026-10-24 08:05:00Z",
            last_seen="2026-10-24 08:05:00Z",
            event_count=1,
            related_event_ids=["EVT-2"],
            explanation="Test explanation",
            recommended_steps=["Step 1"],
            status="NEW",
            confidence="HIGH",
            severity_justification=["Test factor"],
        )
    ]


def test_events_timeline_chart(sample_events):
    fig = create_events_timeline_chart(sample_events)
    assert isinstance(fig, go.Figure)


def test_events_timeline_empty():
    assert create_events_timeline_chart(pd.DataFrame()) is None


def test_alerts_severity_donut(sample_alerts):
    fig = create_alerts_severity_donut(sample_alerts)
    assert isinstance(fig, go.Figure)


def test_alerts_severity_donut_empty():
    assert create_alerts_severity_donut([]) is None


def test_events_by_type_bar(sample_events):
    fig = create_events_by_type_bar(sample_events)
    assert isinstance(fig, go.Figure)


def test_top_failed_ips_bar(sample_events):
    fig = create_top_failed_ips_bar(sample_events)
    assert isinstance(fig, go.Figure)


def test_generate_dataset_summary(sample_events, sample_alerts):
    summary = generate_dataset_summary(sample_events, sample_alerts)
    assert "Dataset Overview" in summary
    assert "alice" in summary or "bob" in summary
    assert "198.51.100.20" in summary
