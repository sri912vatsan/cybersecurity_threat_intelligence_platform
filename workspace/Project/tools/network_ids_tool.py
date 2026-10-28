"""
Network intrusion-detection tool.

Implement network_ids_tool(organization) as a CrewAI @tool that surfaces
an organization's intrusion-detection signals for the agent to weigh.
Deterministic.

See the problem description for the display name and the return shape.
"""

import json
from pathlib import Path
from typing import Any, Dict

from crewai.tools import tool

from core.config import config


@tool("Network Intrusion Detection Monitor")
def network_ids_tool(organization: str) -> Dict[str, Any]:
    """
    Retrieve network intrusion-detection signals for an organization.

    The tool reads deterministic network IDS data from
    data/threat_store.json. It does not perform LLM reasoning or
    calculate threat severity.

    Args:
        organization: Organization whose network IDS data should
            be retrieved.

    Returns:
        A dictionary containing the organization, availability status,
        and network intrusion-detection data.
    """

    store_path = Path(config.data_dir) / "threat_store.json"

    try:
        with store_path.open("r", encoding="utf-8") as file:
            store = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        return {
            "organization": organization,
            "available": False,
            "network_ids": {},
            "error": f"Unable to load threat store: {exc}",
        }

    organizations = store.get("organizations", {})
    organization_data = organizations.get(organization)

    if organization_data is None:
        return {
            "organization": organization,
            "available": False,
            "network_ids": {},
        }

    network_ids = organization_data.get(
        "network_ids",
        {},
    )

    return {
        "organization": organization,
        "available": True,
        "network_ids": network_ids,
    }
