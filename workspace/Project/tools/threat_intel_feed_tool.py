"""
Threat-intelligence feed tool.

Implement threat_intel_feed_tool(organization) as a CrewAI @tool that
surfaces the external threat feed relevant to an organization for the
agent to weigh. Deterministic.

See the problem description for the display name and the return shape.
"""

import json
from pathlib import Path
from typing import Any, Dict

from crewai.tools import tool

from core.config import config


@tool("Threat Intelligence Feed")
def threat_intel_feed_tool(organization: str) -> Dict[str, Any]:
    """
    Retrieve external threat-intelligence feed data for an organization.

    The tool reads deterministic threat-feed data from
    data/threat_store.json. It does not perform LLM reasoning,
    attribution, severity assessment, or critical-threat counting.

    Args:
        organization: Organization whose threat-intelligence feed
            should be retrieved.

    Returns:
        A dictionary containing the organization, availability status,
        and threat-feed data.
    """

    store_path = Path(config.data_dir) / "threat_store.json"

    try:
        with store_path.open("r", encoding="utf-8") as file:
            store = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        return {
            "organization": organization,
            "available": False,
            "threat_feed": {},
            "error": f"Unable to load threat store: {exc}",
        }

    organizations = store.get("organizations", {})
    organization_data = organizations.get(organization)

    if organization_data is None:
        return {
            "organization": organization,
            "available": False,
            "threat_feed": {},
        }

    threat_feed = organization_data.get(
        "threat_feed",
        {},
    )

    return {
        "organization": organization,
        "available": True,
        "threat_feed": threat_feed,
    }
