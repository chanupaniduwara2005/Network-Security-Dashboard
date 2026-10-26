"""Unit test suite for SentinelSOC log ingestion and normalization module."""

import io
import json
from pathlib import Path

import pytest

from src.log_parser import (
    NORMALIZED_COLUMNS,
    LogParserResult,
    parse_csv_data,
    parse_json_data,
    parse_log_file,
    parse_raw_records,
)


def test_parse_valid_csv():
    """Test standard valid CSV parsing with status and event normalization."""
    csv_data = """event_id,timestamp,event_type,username,source_ip,destination_ip,status,hostname,message
EVT-01,2026-10-24T09:00:00Z,login,alice,192.0.2.1,10.0.1.5,success,host-01,Login OK
EVT-02,2026-10-24T09:01:00Z,login,bob,192.0.2.2,10.0.1.5,failed,host-02,Bad password
"""
    result = parse_csv_data(csv_data)
    assert isinstance(result, LogParserResult)
    assert result.accepted_count == 2
    assert result.rejected_count == 0
    assert len(result.valid_df) == 2
    assert result.valid_df["status"].tolist() == ["SUCCESS", "FAILED"]
    assert result.valid_df["event_type"].tolist() == ["LOGIN", "LOGIN"]
    for col in NORMALIZED_COLUMNS:
        assert col in result.valid_df.columns


def test_parse_valid_json_array():
    """Test standard JSON array of event objects."""
    records = [
        {
            "event_id": "J-101",
            "timestamp": "2026-10-24T12:00:00Z",
            "event_type": "LOGIN",
            "username": "charlie",
            "source_ip": "198.51.100.10",
            "status": "SUCCESS",
        },
        {
            "event_id": "J-102",
            "timestamp": "2026-10-24T12:05:00Z",
            "event_type": "LOGOUT",
            "username": "charlie",
            "source_ip": "198.51.100.10",
            "status": "SUCCESS",
        },
    ]
    result = parse_json_data(json.dumps(records))
    assert result.accepted_count == 2
    assert result.rejected_count == 0
    assert result.valid_df.iloc[0]["event_id"] == "J-101"


def test_parse_valid_json_wrapped_dict():
    """Test JSON object with wrapped 'events' key."""
    payload = {
        "metadata": {"source": "firewall"},
        "events": [
            {
                "id": "W-201",
                "time": "2026-10-24T14:30:00Z",
                "action": "PORT_SCAN",
                "client_ip": "203.0.113.5",
                "status": "BLOCKED",
            }
        ],
    }
    result = parse_json_data(json.dumps(payload))
    assert result.accepted_count == 1
    assert result.rejected_count == 0
    assert result.valid_df.iloc[0]["event_id"] == "W-201"
    assert result.valid_df.iloc[0]["source_ip"] == "203.0.113.5"


def test_parse_valid_ndjson():
    """Test JSON Lines (NDJSON) format parsing."""
    ndjson_data = (
        '{"event_id": "ND-1", "timestamp": "2026-10-24T01:00:00Z", "source_ip": "192.0.2.5", "status": "OK"}\n'
        '{"event_id": "ND-2", "timestamp": "2026-10-24T01:05:00Z", "source_ip": "192.0.2.6", "status": "DENIED"}\n'
    )
    result = parse_json_data(ndjson_data)
    assert result.accepted_count == 2
    assert result.rejected_count == 0


def test_missing_required_columns():
    """Test rejection when critical fields (event_id, timestamp, source_ip) are missing."""
    records = [
        # Missing source_ip
        {"event_id": "ERR-1", "timestamp": "2026-10-24T10:00:00Z", "status": "SUCCESS"},
        # Missing timestamp
        {"event_id": "ERR-2", "source_ip": "192.0.2.1", "status": "SUCCESS"},
        # Missing event_id
        {"timestamp": "2026-10-24T10:00:00Z", "source_ip": "192.0.2.1", "status": "SUCCESS"},
    ]
    result = parse_raw_records(records)
    assert result.accepted_count == 0
    assert result.rejected_count == 3
    assert len(result.rejected_records) == 3


def test_invalid_timestamps():
    """Test that invalid timestamp formats are rejected safely without crashing."""
    csv_data = """event_id,timestamp,source_ip,status
BAD-TS-1,this-is-not-a-timestamp,192.0.2.10,SUCCESS
GOOD-TS-2,2026-10-24T15:30:00Z,192.0.2.10,SUCCESS
"""
    result = parse_csv_data(csv_data)
    assert result.accepted_count == 1
    assert result.rejected_count == 1
    assert "Invalid timestamp format" in result.rejected_records[0]["reason"]


def test_invalid_ip_addresses():
    """Test that invalid IPv4/IPv6 strings are caught and rejected."""
    csv_data = """event_id,timestamp,source_ip,destination_ip,status
BAD-IP-1,2026-10-24T15:00:00Z,999.999.999.999,10.0.1.1,SUCCESS
BAD-IP-2,2026-10-24T15:01:00Z,192.0.2.1,not-an-ip-address,SUCCESS
GOOD-IP-3,2026-10-24T15:02:00Z,192.0.2.1,10.0.1.1,SUCCESS
"""
    result = parse_csv_data(csv_data)
    assert result.accepted_count == 1
    assert result.rejected_count == 2
    assert "Invalid IPv4/IPv6 source_ip" in result.rejected_records[0]["reason"]
    assert "Invalid destination_ip" in result.rejected_records[1]["reason"]


def test_empty_input():
    """Test that empty CSV and JSON inputs return clean warnings without crashing."""
    res_csv = parse_csv_data("")
    assert res_csv.accepted_count == 0
    assert len(res_csv.warnings) > 0

    res_json = parse_json_data("   ")
    assert res_json.accepted_count == 0
    assert len(res_json.warnings) > 0


def test_malformed_csv():
    """Test malformed CSV structure handling."""
    # Line with inconsistent field counts
    malformed = "event_id,timestamp,source_ip\nEVT-1,2026-10-24T00:00:00Z,192.0.2.1,extra,unexpected,columns\n"
    # Even if pandas parser handles or warns, it should not unhandled-crash
    result = parse_csv_data(malformed)
    assert isinstance(result, LogParserResult)


def test_malformed_json():
    """Test malformed JSON syntax handling."""
    broken_json = '{"event_id": "BROKEN", "timestamp": "2026-10-24"'
    result = parse_json_data(broken_json)
    assert result.accepted_count == 0
    assert any("Invalid JSON" in w for w in result.warnings)


def test_duplicate_event_ids():
    """Test detection and rejection of duplicate event IDs."""
    csv_data = """event_id,timestamp,source_ip,status
DUP-1,2026-10-24T10:00:00Z,192.0.2.10,SUCCESS
DUP-1,2026-10-24T10:05:00Z,192.0.2.10,SUCCESS
UNIQUE-2,2026-10-24T10:10:00Z,192.0.2.10,SUCCESS
"""
    result = parse_csv_data(csv_data)
    assert result.accepted_count == 2
    assert result.rejected_count == 1
    assert "DUP-1" in result.duplicate_ids
    assert "Duplicate event_id detected" in result.rejected_records[0]["reason"]


def test_parse_sample_security_logs_file():
    """Test loading the synthetic data/sample_security_logs.csv dataset."""
    sample_path = Path(__file__).resolve().parent.parent / "data" / "sample_security_logs.csv"
    assert sample_path.exists(), "Sample log file data/sample_security_logs.csv must exist."

    result = parse_log_file(sample_path)
    assert result.accepted_count >= 50
    assert result.rejected_count == 0
    assert result.has_data
    # Verify chronological ordering
    timestamps = result.valid_df["timestamp"].tolist()
    assert timestamps == sorted(timestamps)
