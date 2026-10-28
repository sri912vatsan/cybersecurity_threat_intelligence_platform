"""
Threat-intelligence state management.

The whole workflow shares ONE dictionary called the "intelligence record". It is created when an
organization is submitted and updated by every step. Every function here receives that dictionary,
changes it, and returns it.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from core.config import STATUS_PROCESSING


def create_intel_state(org_info: Dict[str, Any]) -> Dict[str, Any]:
    """Create the starting intelligence record for one organization."""
    timestamp = datetime.now(timezone.utc).isoformat()
    record_id = f"TI-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"
    return {
        "record_id": record_id,
        "organization": org_info.get("organization", "UNKNOWN"),

        # Filled by the Threat Detection agent (LLM)
        "threat_data": {},
        "threat_severity_score": 0.0,
        "compromised_systems": 0,
        "detected": False,

        # Filled by the Threat Analysis agent (LLM)
        "threat_analysis": {},
        "critical_threats": 0,
        "analyzed": False,

        # Filled by the Incident Response agent (LLM); PRIORITY or STANDARD mode set by the router
        "response_actions": [],
        "forensic_findings": [],
        "containment_summary": "",
        "response_mode": "",
        "responded": False,

        # Filled by the Security Recommendation agent (LLM)
        "security_recommendations": [],
        "roadmap": [],
        "recommendations_count": 0,
        "confidence": 0.0,
        "rationale": "",
        "report": "",

        # PROCESSING -> COMPLETED / QUEUED_FOR_REVIEW / APPROVED / REJECTED
        "status": STATUS_PROCESSING,
        "hitl": {"required": False, "decision": None, "reviewer_note": None},

        "agent_analyses": {},
        "errors": [],
        "metrics": {},
        "created_at": timestamp,
        "updated_at": timestamp,
        "resolved_at": None,
        "duration_seconds": None,
    }


def add_agent_result(state: Dict[str, Any], agent_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Store one agent's result inside state['agent_analyses']."""
    state["agent_analyses"][agent_name] = result
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    return state


def finalize_status(state: Dict[str, Any], status: str) -> Dict[str, Any]:
    """Set the final status and stamp the timing on the record."""
    resolved_at = datetime.now(timezone.utc)
    created_at = datetime.fromisoformat(state["created_at"])
    state["status"] = status
    state["resolved_at"] = resolved_at.isoformat()
    state["duration_seconds"] = round((resolved_at - created_at).total_seconds(), 1)
    state["updated_at"] = resolved_at.isoformat()
    return state


def add_error(state: Dict[str, Any], error_message: str, agent_name: str = None) -> Dict[str, Any]:
    """Record an error in the record's error history."""
    state["errors"].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": error_message,
        "agent": agent_name,
    })
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    return state
