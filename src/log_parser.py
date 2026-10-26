"""SentinelSOC - Security Log Ingestion & Normalization Module.

This module provides parsing and normalization capabilities for authentication
and security event logs in CSV and JSON formats.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, TextIO, Union

import pandas as pd

# Canonical normalized schema fields
NORMALIZED_COLUMNS = [
    "event_id",
    "timestamp",
    "event_type",
    "username",
    "source_ip",
    "destination_ip",
    "status",
    "hostname",
    "message",
]

# Field aliases for flexible ingestion from diverse log sources
FIELD_ALIASES: dict[str, list[str]] = {
    "event_id": ["event_id", "id", "eventid", "record_id", "uuid"],
    "timestamp": ["timestamp", "time", "datetime", "date_time", "@timestamp", "log_time"],
    "event_type": ["event_type", "action", "type", "activity", "event_name"],
    "username": ["username", "user", "user_name", "account", "actor", "login_user"],
    "source_ip": ["source_ip", "src_ip", "sourceip", "client_ip", "src_addr", "ip"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "target_ip", "server_ip"],
    "status": ["status", "result", "outcome", "disposition"],
    "hostname": ["hostname", "host", "device_name", "computer_name", "server"],
    "message": ["message", "msg", "description", "details", "reason"],
}


@dataclass
class LogParserResult:
    """Holds the result of a log ingestion and normalization run."""

    valid_df: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=NORMALIZED_COLUMNS))
    rejected_records: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    total_records: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    duplicate_ids: list[str] = field(default_factory=list)

    @property
    def has_data(self) -> bool:
        """Returns True if there is at least one accepted record."""
        return not self.valid_df.empty


def _is_valid_ip(ip_str: Any) -> bool:
    """Validate IPv4 or IPv6 address string."""
    if not ip_str or pd.isna(ip_str):
        return False
    ip_str = str(ip_str).strip()
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _normalize_status(val: Any) -> str:
    """Standardize status to common SOC values (SUCCESS, FAILED, BLOCKED, UNKNOWN)."""
    if not val or pd.isna(val):
        return "UNKNOWN"
    s = str(val).strip().upper()
    if s in {"SUCCESS", "SUCCESSFUL", "OK", "ALLOW", "ALLOWED", "PASS"}:
        return "SUCCESS"
    if s in {"FAIL", "FAILED", "FAILURE", "DENIED", "DENY", "REJECT", "REJECTED", "ERROR"}:
        return "FAILED"
    if s in {"BLOCK", "BLOCKED", "DROP", "DROPPED"}:
        return "BLOCKED"
    return s


def _normalize_event_type(val: Any) -> str:
    """Standardize event_type values (e.g., LOGIN, LOGOUT, AUTH_ATTEMPT)."""
    if not val or pd.isna(val):
        return "UNKNOWN"
    return str(val).strip().upper()


def _extract_canonical_record(raw_dict: dict[str, Any]) -> dict[str, Any]:
    """Map raw record keys to canonical field names using known aliases."""
    raw_lower = {str(k).strip().lower(): v for k, v in raw_dict.items()}
    canonical: dict[str, Any] = {}

    for target_col, aliases in FIELD_ALIASES.items():
        matched_val = None
        for alias in aliases:
            if alias in raw_lower:
                matched_val = raw_lower[alias]
                break
        canonical[target_col] = matched_val

    return canonical


def parse_raw_records(records: list[dict[str, Any]]) -> LogParserResult:
    """Validate, clean, and normalize a list of raw log record dictionaries."""
    result = LogParserResult(total_records=len(records))

    if not records:
        result.warnings.append("No records found in input data.")
        return result

    seen_ids: set[str] = set()
    accepted_rows: list[dict[str, Any]] = []

    for index, raw in enumerate(records, start=1):
        if not isinstance(raw, dict):
            result.rejected_records.append({
                "row_index": index,
                "raw": str(raw),
                "reason": "Malformed record: Expected key-value dictionary.",
            })
            continue

        canonical = _extract_canonical_record(raw)
        rejection_reasons: list[str] = []

        # 1. Event ID Validation & Duplicate Check
        event_id = canonical.get("event_id")
        if event_id is None or pd.isna(event_id) or str(event_id).strip() == "":
            rejection_reasons.append("Missing required field 'event_id'.")
            event_id_clean = None
        else:
            event_id_clean = str(event_id).strip()
            if event_id_clean in seen_ids:
                rejection_reasons.append(f"Duplicate event_id detected: '{event_id_clean}'.")
                result.duplicate_ids.append(event_id_clean)
            seen_ids.add(event_id_clean)

        # 2. Timestamp Validation (Timezone-safe)
        raw_ts = canonical.get("timestamp")
        parsed_ts = None
        if raw_ts is None or pd.isna(raw_ts) or str(raw_ts).strip() == "":
            rejection_reasons.append("Missing required field 'timestamp'.")
        else:
            try:
                # Convert to UTC ISO timestamp
                parsed_ts = pd.to_datetime(raw_ts, utc=True)
            except Exception:
                rejection_reasons.append(f"Invalid timestamp format: '{raw_ts}'.")

        # 3. Source IP Validation (Required for network/auth logs)
        raw_src_ip = canonical.get("source_ip")
        if raw_src_ip is None or pd.isna(raw_src_ip) or str(raw_src_ip).strip() == "":
            rejection_reasons.append("Missing required field 'source_ip'.")
        elif not _is_valid_ip(raw_src_ip):
            rejection_reasons.append(f"Invalid IPv4/IPv6 source_ip address: '{raw_src_ip}'.")

        # 4. Destination IP Validation (Optional, but must be valid if provided)
        raw_dst_ip = canonical.get("destination_ip")
        if raw_dst_ip is not None and not pd.isna(raw_dst_ip) and str(raw_dst_ip).strip() != "":
            if not _is_valid_ip(raw_dst_ip):
                rejection_reasons.append(f"Invalid destination_ip address: '{raw_dst_ip}'.")

        # 5. Username (Check for presence, warn if missing)
        raw_user = canonical.get("username")
        if raw_user is None or pd.isna(raw_user) or str(raw_user).strip() == "":
            clean_username = "UNKNOWN"
            result.warnings.append(f"Row {index} (Event {event_id_clean or 'N/A'}): Empty username.")
        else:
            clean_username = str(raw_user).strip()

        # Reject if critical fields failed
        if rejection_reasons:
            result.rejected_records.append({
                "row_index": index,
                "event_id": event_id_clean,
                "raw": raw,
                "reason": " | ".join(rejection_reasons),
            })
            continue

        # Build clean normalized record
        clean_row = {
            "event_id": event_id_clean,
            "timestamp": parsed_ts,
            "event_type": _normalize_event_type(canonical.get("event_type")),
            "username": clean_username,
            "source_ip": str(raw_src_ip).strip(),
            "destination_ip": str(raw_dst_ip).strip() if (raw_dst_ip and not pd.isna(raw_dst_ip)) else None,
            "status": _normalize_status(canonical.get("status")),
            "hostname": str(canonical.get("hostname", "")).strip() if canonical.get("hostname") and not pd.isna(canonical.get("hostname")) else "UNKNOWN",
            "message": str(canonical.get("message", "")).strip() if canonical.get("message") and not pd.isna(canonical.get("message")) else "",
        }
        accepted_rows.append(clean_row)

    result.accepted_count = len(accepted_rows)
    result.rejected_count = len(result.rejected_records)

    if accepted_rows:
        df = pd.DataFrame(accepted_rows)
        # Sort by timestamp for SOC chronological analysis
        df = df.sort_values(by="timestamp", ascending=True).reset_index(drop=True)
        result.valid_df = df
    else:
        result.valid_df = pd.DataFrame(columns=NORMALIZED_COLUMNS)

    return result


def parse_csv_data(file_or_text: Union[str, Path, TextIO, BinaryIO]) -> LogParserResult:
    """Parse CSV data from a file path, string, or file-like stream."""
    try:
        if isinstance(file_or_text, (str, Path)) and Path(str(file_or_text)).is_file():
            df_raw = pd.read_csv(file_or_text)
        elif isinstance(file_or_text, str):
            # Check for empty string
            if not file_or_text.strip():
                res = LogParserResult()
                res.warnings.append("Input CSV file is empty.")
                return res
            df_raw = pd.read_csv(io.StringIO(file_or_text))
        else:
            # File-like object (BytesIO or StringIO)
            content = file_or_text.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            if not content.strip():
                res = LogParserResult()
                res.warnings.append("Input CSV file is empty.")
                return res
            df_raw = pd.read_csv(io.StringIO(content))

        # Convert raw DataFrame to dict records
        records = df_raw.to_dict(orient="records")
        return parse_raw_records(records)
    except pd.errors.EmptyDataError:
        res = LogParserResult()
        res.warnings.append("Input CSV file is completely empty.")
        return res
    except pd.errors.ParserError as pe:
        res = LogParserResult()
        res.warnings.append(f"Malformed CSV formatting: {pe}")
        return res
    except Exception as e:
        res = LogParserResult()
        res.warnings.append(f"Failed to parse CSV: {str(e)}")
        return res


def parse_json_data(file_or_text: Union[str, Path, TextIO, BinaryIO]) -> LogParserResult:
    """Parse JSON log records from JSON array, wrapped dict, or NDJSON (JSON Lines)."""
    raw_str = ""
    try:
        if isinstance(file_or_text, (str, Path)) and Path(str(file_or_text)).is_file():
            raw_str = Path(str(file_or_text)).read_text(encoding="utf-8")
        elif isinstance(file_or_text, str):
            raw_str = file_or_text
        else:
            content = file_or_text.read()
            if isinstance(content, bytes):
                raw_str = content.decode("utf-8", errors="replace")
            else:
                raw_str = str(content)

        raw_str = raw_str.strip()
        if not raw_str:
            res = LogParserResult()
            res.warnings.append("Input JSON file is empty.")
            return res

        # Attempt standard JSON parsing
        try:
            parsed = json.loads(raw_str)
        except json.JSONDecodeError:
            # Fallback check for NDJSON (JSON Lines)
            lines = [line.strip() for line in raw_str.splitlines() if line.strip()]
            records = []
            for line_idx, line in enumerate(lines, start=1):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as ndjson_err:
                    res = LogParserResult()
                    res.warnings.append(f"Invalid JSON content (line {line_idx}): {ndjson_err}")
                    return res
            return parse_raw_records(records)

        # Handle parsed JSON structures
        if isinstance(parsed, list):
            return parse_raw_records(parsed)
        elif isinstance(parsed, dict):
            # Check for common wrapper keys like "events", "records", "logs", "data"
            for wrapper_key in ["events", "records", "logs", "data", "items"]:
                if wrapper_key in parsed and isinstance(parsed[wrapper_key], list):
                    return parse_raw_records(parsed[wrapper_key])
            # Single event dict
            return parse_raw_records([parsed])
        else:
            res = LogParserResult()
            res.warnings.append(f"Unexpected JSON root type: expected list or object, got {type(parsed).__name__}.")
            return res

    except Exception as e:
        res = LogParserResult()
        res.warnings.append(f"Failed to parse JSON file: {str(e)}")
        return res


def parse_log_file(file_or_path: Union[str, Path, TextIO, BinaryIO], filename: str = "") -> LogParserResult:
    """Universal dispatcher that parses a log file based on its name or content type."""
    name = ""
    if isinstance(file_or_path, (str, Path)):
        name = str(file_or_path).lower()
    elif filename:
        name = filename.lower()
    elif hasattr(file_or_path, "name"):
        name = getattr(file_or_path, "name").lower()

    if name.endswith(".json") or name.endswith(".ndjson"):
        return parse_json_data(file_or_path)
    elif name.endswith(".csv"):
        return parse_csv_data(file_or_path)
    else:
        # Auto-detect between JSON and CSV based on first non-whitespace character
        if isinstance(file_or_path, (str, Path)) and Path(str(file_or_path)).is_file():
            sample = Path(str(file_or_path)).read_text(encoding="utf-8", errors="ignore").lstrip()
            if sample.startswith(("[", "{")):
                return parse_json_data(file_or_path)
            return parse_csv_data(file_or_path)
        
        # Default to CSV
        return parse_csv_data(file_or_path)
