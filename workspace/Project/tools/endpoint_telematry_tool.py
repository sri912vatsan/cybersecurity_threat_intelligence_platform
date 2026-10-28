"""
Endpoint telemetry tool.

Implement endpoint_telemetry_tool(organization) as a CrewAI @tool that
surfaces an organization's endpoint telemetry for the agent to weigh.
Deterministic.

See the problem description for the display name and the return shape.
"""

import json
from pathlib import Path
from typing import Any, Dict

from crewai.tools import tool

from core.config import config


@tool("Endpoint Detection and Response Telemetry")
def endpoint_telemetry_tool(organization: str) -> Dict[str, Any]:
    """
    Retrieve endpoint detection and response telemetry for an organization.

    The tool reads deterministic endpoint data from
    data/threat_store.json. It does not perform LLM reasoning or
    derive additional security conclusions.

    Args:
        organization: Organization whose endpoint telemetry should
            be retrieved.

    Returns:
        A dictionary containing the organization, availability status,
        and endpoint telemetry data.
    """

    store_path = Path(config.data_dir) / "threat_store.json"

    try:
        with store_path.open("r", encoding="utf-8") as file:
            store = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        return {
            "organization": organization,
            "available": False,
            "endpoint_telemetry": {},
            "error": f"Unable to load threat store: {exc}",
        }

    organizations = store.get("organizations", {})
    organization_data = organizations.get(organization)

    if organization_data is None:
        return {
            "organization": organization,
            "available": False,
            "endpoint_telemetry": {},
        }

    endpoint_telemetry = organization_data.get(
        "endpoint",
        {},
    )

    return {
        "organization": organization,
        "available": True,
        "endpoint_telemetry": endpoint_telemetry,
    }
