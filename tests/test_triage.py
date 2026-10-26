"""Unit test suite for SentinelSOC alert triage, investigation checklist, and persistence."""

import json
from pathlib import Path
import pytest

from src.detection_engine import Alert
from src.triage_manager import DEFAULT_CHECKLIST, TriageManager, TriageRecord, VALID_STATUSES


@pytest.fixture
def temp_triage_store(tmp_path):
    """Provides a TriageManager pointing to a temporary JSON file."""
    temp_file = tmp_path / "test_triage_state.json"
    return TriageManager(storage_path=temp_file)


def test_triage_record_initialization():
    """Verify that a TriageRecord initializes with default status and checklist."""
    rec = TriageRecord(alert_id="ALT-100")
    assert rec.alert_id == "ALT-100"
    assert rec.status == "Open"
    assert rec.notes == ""
    assert len(rec.checklist) == len(DEFAULT_CHECKLIST)
    for item in DEFAULT_CHECKLIST:
        assert rec.checklist[item] is False


def test_valid_status_transitions(temp_triage_store):
    """Verify updating alert status across all 4 permitted workflow statuses."""
    alert_id = "ALT-TEST-01"

    for status in VALID_STATUSES:
        rec = temp_triage_store.update_record(alert_id, status=status)
        assert rec.status == status

    # Verify normalization of legacy/lowercase statuses
    rec_norm = temp_triage_store.update_record(alert_id, status="under_investigation")
    assert rec_norm.status == "Investigating"

    rec_norm_fp = temp_triage_store.update_record(alert_id, status="false_positive")
    assert rec_norm_fp.status == "False Positive"


def test_analyst_notes_update(temp_triage_store):
    """Verify updating and persisting analyst notes for an alert."""
    alert_id = "ALT-NOTES-01"
    note_text = "Verified with user over Slack. Confirmed user was traveling in Singapore."

    rec = temp_triage_store.update_record(alert_id, notes=note_text)
    assert rec.notes == note_text

    # Retrieve again
    retrieved = temp_triage_store.get_record(alert_id)
    assert retrieved.notes == note_text


def test_checklist_updates(temp_triage_store):
    """Verify checking off investigation steps in the triage checklist."""
    alert_id = "ALT-CHECKLIST-01"
    rec = temp_triage_store.get_record(alert_id)

    # Check off first two items
    rec.checklist[DEFAULT_CHECKLIST[0]] = True
    rec.checklist[DEFAULT_CHECKLIST[1]] = True

    updated = temp_triage_store.update_record(alert_id, checklist=rec.checklist)
    assert updated.checklist[DEFAULT_CHECKLIST[0]] is True
    assert updated.checklist[DEFAULT_CHECKLIST[1]] is True
    assert updated.checklist[DEFAULT_CHECKLIST[2]] is False


def test_local_storage_persistence(tmp_path):
    """Verify that triage state persists across separate TriageManager instances."""
    storage_path = tmp_path / "persistence_test.json"

    # Instance 1: write notes and status
    manager1 = TriageManager(storage_path=storage_path)
    manager1.update_record(
        alert_id="ALT-PERSIST-1",
        status="Investigating",
        notes="Pushed to SOC tier-2 escalation queue.",
        disposition_reason="Potential credential stuffing",
    )

    # Verify JSON file was created on disk
    assert storage_path.exists()

    # Instance 2: read from disk
    manager2 = TriageManager(storage_path=storage_path)
    rec2 = manager2.get_record("ALT-PERSIST-1")

    assert rec2.status == "Investigating"
    assert rec2.notes == "Pushed to SOC tier-2 escalation queue."
    assert rec2.disposition_reason == "Potential credential stuffing"


def test_safe_corrupted_file_recovery(tmp_path):
    """Verify safe error handling and recovery when local storage contains malformed JSON."""
    corrupted_file = tmp_path / "corrupted.json"
    corrupted_file.write_text("{this is not valid json!}", encoding="utf-8")

    # Should not crash on corrupted file
    manager = TriageManager(storage_path=corrupted_file)
    rec = manager.get_record("ALT-NEW")
    assert rec.status == "Open"


def test_sync_alerts_with_triage_records(temp_triage_store):
    """Verify synchronizing alert objects with persisted triage records."""
    alerts = [
        Alert(
            alert_id="ALT-SYNC-1",
            rule_name="Brute Force",
            severity="HIGH",
            username="admin",
            source_ips=["198.51.100.1"],
            first_seen="2026-10-24 10:00:00Z",
            last_seen="2026-10-24 10:05:00Z",
            event_count=5,
            related_event_ids=["EVT-1", "EVT-2"],
            explanation="Test explanation",
            recommended_steps=["Step 1"],
            status="NEW",
        )
    ]

    # Pre-record triage status and notes
    temp_triage_store.update_record(
        "ALT-SYNC-1",
        status="Resolved",
        notes="IP blacklisted at perimeter firewall.",
    )

    temp_triage_store.sync_alerts(alerts)

    assert alerts[0].status == "Resolved"
    assert alerts[0].analyst_notes == "IP blacklisted at perimeter firewall."
