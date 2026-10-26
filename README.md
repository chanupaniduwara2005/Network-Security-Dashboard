# SentinelSOC — Mini SOC Alert Dashboard

**SentinelSOC** is a modern, educational Security Operations Center (SOC) dashboard designed to simulate how cybersecurity analysts monitor, triage, and investigate suspicious security events and authentication anomalies.

> ⚠️ **Educational Project Disclaimer**  
> SentinelSOC is built exclusively for learning, demonstration, and cybersecurity portfolio purposes. It is **not** a production-grade Security Information and Event Management (SIEM) or enterprise monitoring platform. Do not connect it to production networks or sensitive security pipelines.

---

## 🎯 Learning Objectives

By building and exploring SentinelSOC, students and aspiring security analysts learn:
- **SOC Fundamentals:** Understand the role of security analysts, the alert triage lifecycle, and threat detection principles.
- **Log Ingestion & Normalization:** Ingest and normalize security events (timestamps, user identities, source IP addresses, logon statuses) across CSV, JSON array, and JSON Lines (NDJSON) formats.
- **Rule-Based Threat Detection:** Detect common attacks (credential brute-forcing, password spraying, off-hours probes, port scans).
- **Multi-Factor Severity Modeling:** Assign defensible severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) based on failure volume, privileged account targeting, and botnet distribution.
- **Analyst Investigation & Triage Workflows:** Walk through a standard SOC triage methodology, check off investigation milestones, record editable analyst notes, and update incident statuses (`Open`, `Investigating`, `False Positive`, `Resolved`).
- **Evidence Traceability vs. Detection Hypotheses:** Rigorously separate recorded factual log evidence from suggested detection hypotheses.
- **State Persistence:** Retain analyst notes, checklist progress, and case dispositions across application reloads.
- **Python Security Engineering:** Build lightweight, interactive security tools using modern Python libraries.

---

## 🛠️ Technologies Used

- **Python 3.11+**: Core programming language.
- **Streamlit**: Reactive web dashboard framework with dark cybersecurity theme.
- **Pandas**: Structured security log parsing, schema normalization, and tabular filtering.
- **Plotly**: Interactive visualization and attack trend charting.
- **Pytest**: Unit testing for detection algorithms, triage workflows, and log processing functions.

---

## 📂 Project Structure

```text
SentinelSOC/
├── .streamlit/
│   └── config.toml               # Streamlit dark cybersecurity theme configuration
├── app.py                        # Main Streamlit dashboard application
├── pytest.ini                    # Pytest configuration and pythonpath discovery
├── requirements.txt              # Core Python dependencies
├── README.md                     # Project documentation & setup instructions
├── .gitignore                    # Git exclusion rules
├── data/
│   ├── .gitkeep
│   ├── sample_security_logs.csv  # 55 synthetic events (normal & attack simulations)
│   └── triage_state.json         # [NEW] Persistent analyst triage records and notes
├── src/
│   ├── __init__.py
│   ├── log_parser.py             # CSV/JSON ingestion, validation & normalization engine
│   ├── detection_engine.py       # Rule-based threat detection and event correlation engine
│   ├── severity.py               # Multi-factor severity evaluation & confidence scoring
│   ├── dashboard_utils.py        # Plotly dark theme chart generators, comparison & analytics
│   ├── report_generator.py       # [NEW] Safe CSV/JSON report exports, formula sanitization & scrubbers
│   └── triage_manager.py         # Analyst triage state, checklist & persistence manager
├── tests/
│   ├── .gitkeep
│   ├── test_log_parser.py        # Unit tests for log parser and edge cases (12 tests)
│   ├── test_detection_engine.py  # Unit tests for detection rules and boundaries (13 tests)
│   ├── test_severity.py          # Unit tests for severity levels and scoring factors (12 tests)
│   ├── test_dashboard_utils.py   # Unit tests for chart generators and summary synthesis (7 tests)
│   ├── test_triage.py            # Unit tests for triage workflows and persistence (7 tests)
│   ├── test_report_generator.py  # Unit tests for CSV/JSON reports, injection sanitization (12 tests)
│   ├── test_analytics.py         # Unit tests for analytics visualizations & period comparisons (11 tests)
│   └── test_reliability_edge_cases.py # [NEW] Reliability & edge-case test suite (20 tests)
└── screenshots/                  # Architecture and UI preview screenshots
    └── .gitkeep
```

---

## 🚦 Implementation Status

| Milestone | Status | Description |
|:---|:---:|:---|
| **Phase 1: Project Foundation** | **Completed** | Directory structure, dependency configuration, Streamlit baseline shell, and dark theme. |
| **Phase 2: Log Ingestion & Data Engine** | **Completed** | Parsing for CSV, JSON arrays, and NDJSON; timezone-safe ISO timestamp conversion; IPv4/IPv6 validation; quarantine reporting for malformed/duplicate rows; Streamlit file uploader and interactive log explorer. |
| **Phase 3: Threat Detection Engine** | **Completed** | Rule-based correlation engine covering brute-force attacks, distributed login failures / password spraying, login-after-failures, privileged account activity, and suspicious reconnaissance patterns. |
| **Phase 4: Alert Severity & Correlation** | **Completed** | Multi-factor severity model (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`), confidence separation, explainable severity justifications, and multi-faceted alert triage filtering. |
| **Phase 5: Professional SOC Dashboard** | **Completed** | 5 working operational views (Overview, Security Events, Alerts, Analytics, Reports), Plotly dark charts, live KPIs, event inspector, and downloadable triage reports (Markdown, CSV, JSON). |
| **Phase 6: Alert Investigation & Triage** | **Completed** | Analyst investigation workspace, chronological evidence viewer, recorded facts vs. hypotheses separation, 5-point checklist, editable analyst notes, and safe local persistence. |
| **Phase 7: Analytics & Report Export** | **Completed** | Deep-dive behavioral analytics, temporal period comparisons, formula injection (CWE-1236) sanitized CSV/JSON exports, reporting period reviews, and evidence immutability guarantees. |

---

## 📊 Deep-Dive Threat Analytics

The **Analytics** view provides security analysts with multi-dimensional visibility into ingested telemetry:

| Analytics Metric / Chart | Technical Interpretation & SOC Purpose |
|:---|:---|
| **Security Events Over Time** | Chronological timeline of all ingested events stacked by outcome (`SUCCESS`, `FAILED`, `BLOCKED`). Used to spot volume surges and off-hours anomalies. |
| **Failed-Login Trends** | Dedicated area chart tracking failure velocity across time buckets. Surges and elevated baselines reflect automated credential guessing and brute-force campaigns. |
| **Alert Severity Distribution** | Donut visualization categorizing triggered alerts into severity tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`). Focuses immediate containment on top tiers. |
| **Alert Triage Status Distribution** | Donut chart showing lifecycle breakdown (`Open`, `Investigating`, `False Positive`, `Resolved`). Monitors team investigation backlog and resolution velocity. |
| **Most Frequently Affected Usernames** | Ranked horizontal bar chart identifying targeted accounts. High counts highlight primary targets for credential compromise and account takeover. |
| **Repeated Failure Source IPs** | Horizontal bar chart highlighting origin IPs generating multiple failed authentications. Flags rogue scanners, proxies, and botnets for firewall blacklisting. |
| **Detection Rule Frequency** | Bar chart detailing which correlation rules trigger most often. Highlights predominant attack vectors across the network. |
| **Time Period Comparison Analytics** | Evaluates Period 1 (earlier baseline) vs. Period 2 (later activity) when sufficient temporal span exists (> 5 minutes). Calculates percentage deltas for event volume, failed logins, alerts, and active IPs to gauge attack escalation or containment effectiveness. |

---

## 📑 Report Generation & Export Formats

The **Reports** view enables analysts to scope, review, and export verifiable documentation:

### 1. Available Export Formats
- **Filtered Security Events (CSV):** Detailed export of event records matching active status, type, date range, or keyword filters.
- **Correlated Alerts & Triage Records (CSV):** Tabular export of alerts including rule name, severity, confidence, target user, source IPs, first/last seen timestamps, event counts, persistent analyst notes, and disposition reasons.
- **Structured Operations Report (JSON):** Machine-readable JSON artifact containing full report metadata, generation timestamps, period observation window, summary metrics, alert details, checklist progress, and evidence distribution.
- **Executive Incident Briefing (Markdown):** Formatted narrative report ready for incident response documentation or post-incident reviews.

### 2. Selected Reporting Period Review
Prior to downloading, analysts can review an executive summary including:
- Exact **Report Generation Timestamp** in UTC.
- Normalized **Observation Period** (earliest to latest event in scope).
- Summary of all **Active Filters** applied.
- Dataset Threat & Evidence Synthesis text.

---

## 🔒 Security & Data Integrity Considerations

1. **Spreadsheet Formula Injection Defense (CWE-1236):**
   Untrusted strings in exported CSV files starting with formula-triggering characters (`=`, `+`, `-`, `@`, `\t`, `\r`, `|`, `%`) are automatically prefixed with a single quote (`'`). This prevents spreadsheet software (Excel, LibreOffice Calc) from executing malicious dynamic data exchange (DDE) commands or formulas while preserving legitimate numerical values.
2. **Safe JSON Serialization:**
   Custom JSON encoder safely serializes datetimes, sets, and custom types without crashing or invoking arbitrary code evaluation.
3. **No Dynamic Execution:**
   Uploaded CSV/JSON logs are strictly parsed as data structures; user-provided content is never executed or evaluated.
4. **Environment & Secrets Scrubbing:**
   Local host directory paths (e.g. `C:\Users\...`) and sensitive parameters (`password`, `token`, `secret`, `api_key`) are redacted from report metadata and exported files.
5. **Clear Report vs. Raw Log Distinction:**
   All exported reports embed clear metadata tags and disclaimers identifying them as generated analytical artifacts, preventing confusion with raw system log streams.
6. **Underlying Evidence Immutability:**
   Report generation utilizes defensive data copies (`copy.deepcopy` and `.copy()`). Sanitization and filtering are applied strictly to the export streams; in-memory log evidence and alert records remain 100% authentic and unmodified.

---

## 🔍 Alert Investigation & Triage Workflow

SentinelSOC models the triage workflow of a Tier-1 / Tier-2 SOC analyst.

### 1. Triage Lifecycle Statuses
Analysts can transition each alert through 4 standard operational statuses:
- **`Open`:** Newly generated alert awaiting initial analyst review.
- **`Investigating`:** Active investigation underway; analyst is reviewing event timelines or contacting the user.
- **`False Positive`:** Activity verified as benign (e.g. employee typo, authorized vulnerability scan, scheduled maintenance).
- **`Resolved`:** Confirmed incident mitigated or contained (e.g. source IP blocked, account password reset, token revoked).

### 2. Separation of Recorded Facts vs. Suggested Hypotheses
To avoid cognitive bias and premature conclusions, the investigation workspace strictly bifurcates:
- **Recorded Facts:** Immutable log telemetry (exact event timestamps, source/destination IPs, usernames, status codes, and hostnames).
- **Suggested Hypotheses:** The detection engine's rule criteria, severity justifications, and potential underlying causes. Analysts are reminded that detection rules are hypotheses, not automatic verdicts.

### 3. Five-Point Investigation Checklist
Each alert provides an interactive checklist guiding analysts through methodical triage:
1. *Review the failed and successful login sequence.*
2. *Check whether the source IP appears across other alerts.*
3. *Review the affected account and event timestamps.*
4. *Determine whether the activity is expected.*
5. *Record a reason for the final disposition.*

### 4. Local State Persistence & Limitations
Triage records (statuses, analyst notes, disposition summaries, and checklist progress) are managed by `TriageManager` and stored locally in `data/triage_state.json`.

---

## 🚀 Setup & Execution Guide (Windows)

```powershell
# 1. Open the Project Directory
cd "c:\MY Workings\University Life\Antigravity\Network Security Dashboard - CS PROJECT\SentinelSOC"

# 2. Activate Virtual Environment
.\.venv\Scripts\Activate.ps1

# 3. Run the Automated Test Suite (94 Unit Tests)
pytest -v

# 4. Launch the Dashboard
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`. 
1. Click **"📂 Load Built-in Sample Logs"** in the sidebar.
2. Navigate to **"Analytics"** to inspect behavioral trends, rule frequencies, and temporal comparisons.
3. Navigate to **"Reports"** to configure report filters, review reporting period summaries, and download formula-sanitized CSV, JSON, and Markdown reports!
