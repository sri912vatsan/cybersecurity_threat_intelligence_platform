"""
Security event data tool.

Implement siem_events_tool(organization) as a CrewAI @tool that collects
an organization's security event data from the store. Deterministic.

See the problem description for the display name and the return shape.
"""

import json
from pathlib import Path
from typing import Any, Dict

from crewai.tools import tool

from core.config import config


@tool("SIEM Event Monitor")
def siem_events_tool(organization: str) -> Dict[str, Any]:
    """
    Retrieve SIEM security-event data for an organization.

    The tool reads deterministic data from data/threat_store.json.
    It does not perform LLM reasoning, severity scoring, or threat
    classification.

    Args:
        organization: Organization whose SIEM event data should
            be retrieved.

    Returns:
        A dictionary containing the organization, availability status,
        and SIEM event data.
    """

    store_path = Path(config.data_dir) / "threat_store.json"

    try:
        with store_path.open("r", encoding="utf-8") as file:
            store = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        return {
            "organization": organization,
            "available": False,
            "siem_events": {},
            "error": f"Unable to load threat store: {exc}",
        }

    organizations = store.get("organizations", {})
    organization_data = organizations.get(organization)

    if organization_data is None:
        return {
            "organization": organization,
            "available": False,
            "siem_events": {},
        }

    siem_events = organization_data.get(
        "siem",
        {},
    )

    return {
        "organization": organization,
        "available": True,
        "siem_events": siem_events,
    }
