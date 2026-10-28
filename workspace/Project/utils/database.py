"""
SQLite audit trail (preloaded) — the single persistence layer.

Every finished (or human-reviewed) threat-intelligence run is written to a small SQLite database
(`threat_intel.db` at the project root) so the console can show a history of past runs. Two public
functions: one records a run, one lists them back newest-first.
"""

import json
import sqlite3
from typing import Any, Dict, List

from core.config import TI_DB_SCHEMA, config


def record_intel(record: Dict[str, Any]) -> None:
    """Insert or replace one intelligence record in the audit database."""
    connection = sqlite3.connect(config.db_file)
    try:
        connection.execute(TI_DB_SCHEMA)
        connection.execute(
            "INSERT OR REPLACE INTO threat_intelligence "
            "(record_id, organization, status, response_mode, threat_severity_score, critical_threats, "
            "compromised_systems, created_at, resolved_at, record_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.get("record_id", ""),
                record.get("organization", ""),
                record.get("status", ""),
                record.get("response_mode", ""),
                float(record.get("threat_severity_score", 0.0) or 0.0),
                int(record.get("critical_threats", 0) or 0),
                int(record.get("compromised_systems", 0) or 0),
                record.get("created_at", ""),
                record.get("resolved_at", ""),
                json.dumps(record, default=str),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def list_intel(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent intelligence records (newest first) for the console."""
    connection = sqlite3.connect(config.db_file)
    try:
        connection.execute(TI_DB_SCHEMA)
        rows = connection.execute(
            "SELECT record_json FROM threat_intelligence ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        connection.close()
    return [json.loads(row[0]) for row in rows]
