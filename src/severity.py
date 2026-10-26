"""SentinelSOC - Alert Severity & Correlation Scoring Module.

Defines a defensible, multi-factor severity model and confidence scoring engine
for security operations triage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Sequence, Union


class SeverityLevel(str, Enum):
    """Standardized SOC alert severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ConfidenceLevel(str, Enum):
    """Confidence that the observed signal represents genuine suspicious activity."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SeverityAssessment:
    """Holds the computed severity, confidence score, and explanatory evidence."""
    level: SeverityLevel
    score: int  # 0 to 100
    confidence: ConfidenceLevel
    justification: list[str] = field(default_factory=list)


@dataclass
class SeverityConfig:
    """Configurable weights and thresholds for severity evaluation."""
    # Failure count thresholds
    critical_failure_count: int = 15
    high_failure_count: int = 8
    medium_failure_count: int = 5

    # Distributed source IP thresholds
    critical_ip_count: int = 5
    high_ip_count: int = 3

    # Privileged account list
    privileged_users: list[str] = field(
        default_factory=lambda: [
            "admin",
            "root",
            "administrator",
            "service_db",
            "service_backup",
            "security_admin",
            "steve.rogers",
        ]
    )


class SeverityEvaluator:
    """Evaluates multi-factor context to assign explainable alert severity and confidence."""

    def __init__(self, config: Optional[SeverityConfig] = None):
        self.config = config or SeverityConfig()

    def evaluate(
        self,
        rule_category: str,
        event_count: int = 1,
        username: Optional[str] = None,
        source_ips: Optional[Sequence[str]] = None,
        success_after_failures: bool = False,
        is_off_hours: bool = False,
        multiple_correlated_signals: bool = False,
    ) -> SeverityAssessment:
        """Calculate explainable severity and confidence based on environmental factors."""
        source_ips = source_ips or []
        user_clean = (username or "").strip().lower()
        is_privileged = user_clean in {u.lower() for u in self.config.privileged_users}
        num_ips = len(source_ips)

        score = 20  # Baseline informational score
        justifications: list[str] = []
        confidence = ConfidenceLevel.MEDIUM

        # ------------------------------------------------------------------
        # Factor 1: Account Takeover Potential (Success after Failures)
        # ------------------------------------------------------------------
        if success_after_failures:
            score += 45
            justifications.append(
                "Observed successful authentication immediately following multiple failed attempts."
            )
            confidence = ConfidenceLevel.HIGH
            if is_privileged:
                score += 30
                justifications.append(
                    f"Target account '{username}' is a privileged system administrator role (+30 critical risk)."
                )
            if num_ips > 1:
                score += 15
                justifications.append(
                    f"Successful login originated from a different IP than previous failures ({num_ips} IPs involved)."
                )

        # ------------------------------------------------------------------
        # Factor 2: Volume of Failed Attempts
        # ------------------------------------------------------------------
        elif "BRUTE" in rule_category.upper() or "FAILED" in rule_category.upper():
            if event_count >= self.config.critical_failure_count:
                score += 60
                justifications.append(
                    f"High-volume attack: {event_count} failed logins exceeds critical threshold ({self.config.critical_failure_count})."
                )
                confidence = ConfidenceLevel.HIGH
            elif event_count >= self.config.high_failure_count:
                score += 40
                justifications.append(
                    f"Elevated volume: {event_count} failed logins exceeds high threshold ({self.config.high_failure_count})."
                )
                confidence = ConfidenceLevel.HIGH
            elif event_count >= self.config.medium_failure_count:
                score += 25
                justifications.append(
                    f"Sustained attempts: {event_count} failed logins exceeds detection threshold ({self.config.medium_failure_count})."
                )
            else:
                score += 5
                justifications.append(
                    f"Low failure volume ({event_count} attempts) below standard brute-force threshold."
                )
                confidence = ConfidenceLevel.LOW

            if is_privileged:
                score += 20
                justifications.append(f"Target account '{username}' has administrative privileges.")

        # ------------------------------------------------------------------
        # Factor 3: Distributed Sources / Password Spraying
        # ------------------------------------------------------------------
        elif "DIST" in rule_category.upper() or "SPRAY" in rule_category.upper():
            score += 35
            justifications.append("Distributed pattern targeting multiple accounts or utilizing multiple source IPs.")
            confidence = ConfidenceLevel.HIGH

            if num_ips >= self.config.critical_ip_count:
                score += 35
                justifications.append(
                    f"Coordinated botnet footprint: {num_ips} distinct source IPs exceed critical threshold ({self.config.critical_ip_count})."
                )
            elif num_ips >= self.config.high_ip_count:
                score += 20
                justifications.append(
                    f"Multi-source correlation: {num_ips} distinct source IPs involved."
                )

            if is_privileged:
                score += 20
                justifications.append("Privileged identity targeted among affected accounts.")

        # ------------------------------------------------------------------
        # Factor 4: Privileged Account Activity Auditing
        # ------------------------------------------------------------------
        elif "PRIV" in rule_category.upper():
            score = 45
            justifications.append(
                f"Contextual audit event: Privileged account '{username}' performed sensitive administrative action."
            )
            confidence = ConfidenceLevel.LOW  # Routine sysadmin work unless correlated with anomalies
            if is_off_hours:
                score += 20
                justifications.append("Sensitive action took place outside business hours.")
                confidence = ConfidenceLevel.MEDIUM

        # ------------------------------------------------------------------
        # Factor 5: Network Reconnaissance & Probes
        # ------------------------------------------------------------------
        elif "SCAN" in rule_category.upper() or "RECON" in rule_category.upper():
            score = 40
            justifications.append("Automated perimeter port scanning / reconnaissance signature detected.")
            confidence = ConfidenceLevel.HIGH

        # ------------------------------------------------------------------
        # Factor 6: Off-Hours Activity
        # ------------------------------------------------------------------
        elif "OFFHOURS" in rule_category.upper():
            score = 25
            justifications.append("Activity observed during designated off-hours window.")
            confidence = ConfidenceLevel.LOW

        # ------------------------------------------------------------------
        # Correlated Multi-Signal Escalation
        # ------------------------------------------------------------------
        if multiple_correlated_signals:
            score += 15
            justifications.append(
                "Multiple independent threat signals correlated across the same entity or timeframe."
            )
            confidence = ConfidenceLevel.HIGH

        # Clamp score between 0 and 100
        final_score = max(0, min(100, score))

        # Map score to SeverityLevel
        if final_score >= 80:
            level = SeverityLevel.CRITICAL
        elif final_score >= 60:
            level = SeverityLevel.HIGH
        elif final_score >= 40:
            level = SeverityLevel.MEDIUM
        elif final_score >= 20:
            level = SeverityLevel.LOW
        else:
            level = SeverityLevel.INFORMATIONAL

        return SeverityAssessment(
            level=level,
            score=final_score,
            confidence=confidence,
            justification=justifications,
        )
