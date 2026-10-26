"""SentinelSOC - Alert Triage & Analyst Investigation Manager.

Handles analyst workflow state, investigation checklists, editable analyst notes,
and safe local persistence.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

VALID_STATUSES = ["Open", "Investigating", "False Positive", "Resolved"]

STATUS_NORMALIZE = {
    "NEW": "Open",
    "OPEN": "Open",
    "UNDER_INVESTIGATION": "Investigating",
    "INVESTIGATING": "Investigating",
    "FALSE_POSITIVE": "False Positive",
    "FALSE POSITIVE": "False Positive",
    "RESOLVED": "Resolved",
}

DEFAULT_CHECKLIST = [
    "Review the failed and successful login sequence.",
    "Check whether the source IP appears across other alerts.",
    "Review the affected account and event timestamps.",
    "Determine whether the activity is expected.",
    "Record a reason for the final disposition.",
]


@dataclass
class TriageRecord:
    """Holds persistent analyst triage status, notes, and checklist state for an alert."""

    alert_id: str
    status: str = "Open"
    notes: str = ""
    disposition_reason: str = ""
    checklist: dict[str, bool] = field(default_factory=dict)
    updated_at: str = ""

    def __post_init__(self):
        # Normalize status to standard 4 values
        norm = STATUS_NORMALIZE.get(str(self.status).upper(), self.status)
        if norm in VALID_STATUSES:
            self.status = norm
        else:
            self.status = "Open"

        # Initialize default checklist if empty
        if not self.checklist:
            self.checklist = {item: False for item in DEFAULT_CHECKLIST}
        else:
            # Ensure all default items are present
            for item in DEFAULT_CHECKLIST:
                if item not in self.checklist:
                    self.checklist[item] = False

        if not self.updated_at:
            self.updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    def to_dict(self) -> dict[str, Any]:
        """Convert record to JSON-serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "status": self.status,
            "notes": self.notes,
            "disposition_reason": self.disposition_reason,
            "checklist": self.checklist,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TriageRecord:
        """Create TriageRecord from dictionary with safe defaults."""
        return cls(
            alert_id=str(data.get("alert_id", "")),
            status=str(data.get("status", "Open")),
            notes=str(data.get("notes", "")),
            disposition_reason=str(data.get("disposition_reason", "")),
            checklist=data.get("checklist", {}),
            updated_at=str(data.get("updated_at", "")),
        )


class TriageManager:
    """Manages alert triage state in memory with optional safe local file persistence."""

    def __init__(self, storage_path: Optional[Path] = None):
        if storage_path is None:
            # Default to data/triage_state.json relative to project root
            self.storage_path = Path(__file__).resolve().parent.parent / "data" / "triage_state.json"
        else:
            self.storage_path = Path(storage_path)

        self.records: dict[str, TriageRecord] = {}
        self.load()

    def get_record(self, alert_id: str) -> TriageRecord:
        """Get or initialize the triage record for a given alert ID."""
        if alert_id not in self.records:
            self.records[alert_id] = TriageRecord(alert_id=alert_id)
        return self.records[alert_id]

    def update_record(
        self,
        alert_id: str,
        status: Optional[str] = None,
        notes: Optional[str] = None,
        disposition_reason: Optional[str] = None,
        checklist: Optional[dict[str, bool]] = None,
    ) -> TriageRecord:
        """Update triage state for an alert and persist to storage."""
        rec = self.get_record(alert_id)
        if status is not None:
            norm_status = STATUS_NORMALIZE.get(status.upper(), status)
            if norm_status in VALID_STATUSES:
                rec.status = norm_status
        if notes is not None:
            rec.notes = notes
        if disposition_reason is not None:
            rec.disposition_reason = disposition_reason
        if checklist is not None:
            rec.checklist = checklist

        rec.updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        self.save()
        return rec

    def load(self) -> bool:
        """Safely load triage records from local JSON storage."""
        if not self.storage_path.exists():
            return False

        try:
            content = self.storage_path.read_text(encoding="utf-8").strip()
            if not content:
                return False
            data = json.loads(content)
            if isinstance(data, dict):
                for alert_id, raw_rec in data.items():
                    if isinstance(raw_rec, dict):
                        self.records[alert_id] = TriageRecord.from_dict(raw_rec)
                return True
        except Exception:
            # Safe recovery on corrupted or unreadable storage
            return False
        return False

    def save(self) -> bool:
        """Safely persist triage records to local JSON file."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            serialized = {k: v.to_dict() for k, v in self.records.items()}
            # Write to a temporary file then rename for atomic write
            tmp_path = self.storage_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
            tmp_path.replace(self.storage_path)
            return True
        except Exception:
            return False

    def sync_alerts(self, alerts: list[Any]) -> None:
        """Synchronize detected alerts with existing persistent triage records."""
        for alert in alerts:
            rec = self.get_record(alert.alert_id)
            # Sync status and notes onto Alert object
            alert.status = rec.status
            if hasattr(alert, "analyst_notes"):
                alert.analyst_notes = rec.notes
