"""
Central configuration for the Cybersecurity Threat Intelligence Platform Solution.

Associates only edit the .env file (GEMINI_API_KEY and GEMINI_MODEL). Every other system setting and
shared constant lives here as a simple, readable value. The router threshold below comes from the
scaffold's own configs/app_config.json alert_thresholds.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# CrewAI environment bootstrap — must run before any `crewai` import, which is
# why main.py, streamlit_UI.py and the tests import this module first.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent

os.environ.setdefault("CREWAI_STORAGE_DIR", str(PROJECT_ROOT / ".crewai_storage"))
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_DISABLE_TRACING", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("DO_NOT_TRACK", "1")
Path(os.environ["CREWAI_STORAGE_DIR"]).mkdir(exist_ok=True)

load_dotenv(PROJECT_ROOT / ".env")


@dataclass
class SystemConfig:
    """All system settings in one place."""

    # From .env — the ONLY two values associates configure
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

    # Project folders
    data_dir: str = str(PROJECT_ROOT / "data")

    # Reliability settings
    max_retries: int = 3
    retry_delay_seconds: int = 2

    # Router threshold (business policy from app_config.json, applied to the analyst's LLM-judged value).
    #   * A critical incident (>= this many critical threats) runs the response in PRIORITY mode and is
    #     queued for a human SOC analyst to approve before the containment plan is adopted (HITL).
    critical_threat_floor: int = 1      # critical_threats >= this -> PRIORITY MODE + human review

    # SQLite audit trail — kept at the project root so data/ holds only input data
    db_file: str = str(PROJECT_ROOT / "threat_intel.db")


# Single shared configuration object used across the whole project
config = SystemConfig()


def validate_config() -> bool:
    """Check critical settings. Raises ValueError when something is wrong."""
    if not config.gemini_api_key or config.gemini_api_key.lower().startswith("your"):
        raise ValueError("GEMINI_API_KEY is missing. Paste your key into the .env file.")
    if not config.gemini_model:
        raise ValueError("GEMINI_MODEL is missing. Set it in the .env file.")
    if config.max_retries < 1:
        raise ValueError("max_retries must be at least 1.")
    if config.critical_threat_floor < 1:
        raise ValueError("critical_threat_floor must be at least 1.")
    return True


# ---------------------------------------------------------------------------
# Shared constants — every module reads these from here (single source of truth)
# ---------------------------------------------------------------------------

# Threat-intelligence lifecycle status values
STATUS_PROCESSING = "PROCESSING"
STATUS_COMPLETED = "COMPLETED"
STATUS_REVIEW = "QUEUED_FOR_REVIEW"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"

# Flow routing labels (the single criticality router) — distinct strings
ROUTE_PRIORITY = "priority"      # critical incident -> PRIORITY MODE + HITL
ROUTE_STANDARD = "standard"      # no critical threats -> STANDARD MODE, auto-complete

# Threat taxonomy the Detection agent classifies against
THREAT_CATEGORIES = ["malware", "phishing", "ransomware", "ddos", "data_breach", "insider_threat",
                     "zero_day_exploit", "apt_attack"]
# Severity taxonomy
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]
# Incident-response lifecycle stages the Responder agent plans across
RESPONSE_STAGES = ["identification", "containment", "eradication", "recovery", "lessons_learned"]
# Reference frameworks the Recommendation agent maps to
SECURITY_FRAMEWORKS = ["NIST CSF", "CIS Controls", "MITRE ATT&CK", "ISO 27001", "SANS Top 20"]

# Streamlit status badge: status -> (streamlit method name, message)
STATUS_STYLES = {
    STATUS_COMPLETED: ("success", "Threat intelligence complete - no critical incident"),
    STATUS_APPROVED: ("success", "Incident response approved by a SOC analyst"),
    STATUS_REJECTED: ("error", "Incident response rejected by a SOC analyst"),
    STATUS_REVIEW: ("warning", "Critical incident - queued for human review (HITL)"),
    STATUS_PROCESSING: ("info", "Processing"),
}

# SQLite schema for the threat-intelligence audit trail
TI_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_intelligence (
    record_id            TEXT PRIMARY KEY,
    organization         TEXT,
    status               TEXT,
    response_mode        TEXT,
    threat_severity_score REAL,
    critical_threats     INTEGER,
    compromised_systems  INTEGER,
    created_at           TEXT,
    resolved_at          TEXT,
    record_json          TEXT
)
"""
