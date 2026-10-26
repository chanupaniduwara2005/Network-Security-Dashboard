"""Unit test suite for SentinelSOC alert severity and correlation scoring module."""

import pytest

from src.severity import (
    ConfidenceLevel,
    SeverityAssessment,
    SeverityConfig,
    SeverityEvaluator,
    SeverityLevel,
)


@pytest.fixture
def evaluator():
    """Provides a standard SeverityEvaluator instance."""
    return SeverityEvaluator()


def test_critical_severity_account_takeover_privileged(evaluator):
    """Account takeover attempt against a privileged user escalates to CRITICAL severity."""
    assessment = evaluator.evaluate(
        rule_category="SUCCESS_AFTER_FAIL",
        event_count=5,
        username="admin",
        source_ips=["192.0.2.10", "198.51.100.45"],
        success_after_failures=True,
    )
    assert assessment.level == SeverityLevel.CRITICAL
    assert assessment.score >= 80
    assert assessment.confidence == ConfidenceLevel.HIGH
    assert any("privileged system administrator" in j for j in assessment.justification)


def test_critical_severity_massive_brute_force(evaluator):
    """Extreme failure volume (>= 15 attempts) triggers CRITICAL severity."""
    assessment = evaluator.evaluate(
        rule_category="BRUTE",
        event_count=20,
        username="john.doe",
        source_ips=["198.51.100.50"],
    )
    assert assessment.level == SeverityLevel.CRITICAL
    assert assessment.confidence == ConfidenceLevel.HIGH
    assert any("High-volume attack" in j for j in assessment.justification)


def test_critical_severity_large_botnet_spray(evaluator):
    """Distributed attack with >= 5 distinct IPs triggers CRITICAL severity."""
    assessment = evaluator.evaluate(
        rule_category="DIST",
        event_count=10,
        username="alice",
        source_ips=["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"],
    )
    assert assessment.level == SeverityLevel.CRITICAL
    assert assessment.confidence == ConfidenceLevel.HIGH
    assert any("Coordinated botnet footprint" in j for j in assessment.justification)


def test_high_severity_standard_takeover(evaluator):
    """Success after multiple failures for a standard non-admin account triggers HIGH severity."""
    assessment = evaluator.evaluate(
        rule_category="SUCCESS_AFTER_FAIL",
        event_count=4,
        username="standard.user",
        source_ips=["192.0.2.15"],
        success_after_failures=True,
    )
    assert assessment.level == SeverityLevel.HIGH
    assert assessment.confidence == ConfidenceLevel.HIGH
    assert assessment.score >= 60


def test_high_severity_elevated_failed_logins(evaluator):
    """8 to 14 failed logins produces HIGH severity."""
    assessment = evaluator.evaluate(
        rule_category="BRUTE",
        event_count=9,
        username="regular.user",
        source_ips=["198.51.100.22"],
    )
    assert assessment.level == SeverityLevel.HIGH
    assert any("Elevated volume" in j for j in assessment.justification)


def test_medium_severity_standard_brute_force(evaluator):
    """5 to 7 failed logins produces MEDIUM severity."""
    assessment = evaluator.evaluate(
        rule_category="BRUTE",
        event_count=5,
        username="regular.user",
        source_ips=["198.51.100.22"],
    )
    assert assessment.level == SeverityLevel.MEDIUM
    assert any("Sustained attempts" in j for j in assessment.justification)


def test_medium_severity_privileged_routine_audit(evaluator):
    """Privileged sensitive action defaults to MEDIUM audit severity with LOW confidence."""
    assessment = evaluator.evaluate(
        rule_category="PRIV",
        event_count=1,
        username="root",
        source_ips=["10.0.1.10"],
    )
    assert assessment.level == SeverityLevel.MEDIUM
    # Routine administrative work is low confidence malice unless correlated with other alerts
    assert assessment.confidence == ConfidenceLevel.LOW
    assert any("Contextual audit event" in j for j in assessment.justification)


def test_low_severity_off_hours_attempt(evaluator):
    """Single off-hours failed attempt receives LOW severity."""
    assessment = evaluator.evaluate(
        rule_category="OFFHOURS",
        event_count=1,
        username="guest_user",
        source_ips=["198.51.100.120"],
        is_off_hours=True,
    )
    assert assessment.level == SeverityLevel.LOW
    assert any("off-hours" in j.lower() for j in assessment.justification)


def test_informational_severity_benign_event(evaluator):
    """Baseline score with zero threat factors produces INFORMATIONAL or LOW level."""
    assessment = evaluator.evaluate(
        rule_category="UNKNOWN_GENERIC",
        event_count=1,
        username="normal_user",
    )
    assert assessment.level in {SeverityLevel.INFORMATIONAL, SeverityLevel.LOW}
    assert assessment.score <= 30


def test_boundary_conditions_failure_counts(evaluator):
    """Test boundary transitions: 4 (Low) -> 5 (Medium) -> 8 (High) -> 15 (Critical)."""
    # 4 failures (below standard threshold of 5)
    r_4 = evaluator.evaluate(rule_category="BRUTE", event_count=4, username="user")
    assert r_4.level == SeverityLevel.LOW

    # 5 failures (exact medium threshold)
    r_5 = evaluator.evaluate(rule_category="BRUTE", event_count=5, username="user")
    assert r_5.level == SeverityLevel.MEDIUM

    # 7 failures (still medium)
    r_7 = evaluator.evaluate(rule_category="BRUTE", event_count=7, username="user")
    assert r_7.level == SeverityLevel.MEDIUM

    # 8 failures (exact high threshold)
    r_8 = evaluator.evaluate(rule_category="BRUTE", event_count=8, username="user")
    assert r_8.level == SeverityLevel.HIGH

    # 14 failures (still high)
    r_14 = evaluator.evaluate(rule_category="BRUTE", event_count=14, username="user")
    assert r_14.level == SeverityLevel.HIGH

    # 15 failures (exact critical threshold)
    r_15 = evaluator.evaluate(rule_category="BRUTE", event_count=15, username="user")
    assert r_15.level == SeverityLevel.CRITICAL


def test_multi_signal_correlation_boost(evaluator):
    """Multiple correlated signals elevate severity score and confidence."""
    single_signal = evaluator.evaluate(
        rule_category="OFFHOURS",
        event_count=1,
        username="user1",
        multiple_correlated_signals=False,
    )
    multi_signal = evaluator.evaluate(
        rule_category="OFFHOURS",
        event_count=1,
        username="user1",
        multiple_correlated_signals=True,
    )
    assert multi_signal.score > single_signal.score
    assert multi_signal.confidence == ConfidenceLevel.HIGH
    assert any("Multiple independent threat signals" in j for j in multi_signal.justification)


def test_insufficient_or_missing_information(evaluator):
    """Handles None/empty usernames and missing source IP lists without crashing."""
    res_none = evaluator.evaluate(
        rule_category="BRUTE",
        event_count=0,
        username=None,
        source_ips=None,
    )
    assert isinstance(res_none, SeverityAssessment)
    assert res_none.score >= 0
    assert len(res_none.justification) > 0
