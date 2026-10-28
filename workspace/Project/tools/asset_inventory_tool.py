"""
Asset inventory tool.

Implement asset_inventory_tool(organization) as a CrewAI @tool that surfaces
an organization's asset inventory for the agent to weigh. Deterministic.

See the problem description for the display name and the return shape.
"""

import json
from pathlib import Path
from typing import Any, Dict

from crewai.tools import tool

from core.config import config


@tool("Asset Inventory System")
def asset_inventory_tool(organization: str) -> Dict[str, Any]:
    """
    Retrieve the asset inventory for an organization.

    The tool reads deterministic data from data/threat_store.json.
    The same organization always produces the same result.

    Args:
        organization: Organization whose asset inventory should be retrieved.

    Returns:
        A dictionary containing the organization, availability status,
        and asset-inventory data.
    """

    store_path = Path(config.data_dir) / "threat_store.json"

    try:
        with store_path.open("r", encoding="utf-8") as file:
            store = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        return {
            "organization": organization,
            "available": False,
            "asset_inventory": {},
            "error": f"Unable to load threat store: {exc}",
        }

    organizations = store.get("organizations", {})
    organization_data = organizations.get(organization)

    if organization_data is None:
        return {
            "organization": organization,
            "available": False,
            "asset_inventory": {},
        }

    asset_inventory = organization_data.get(
        "asset_inventory",
        {},
    )

    return {
        "organization": organization,
        "available": True,
        "asset_inventory": asset_inventory,
    }
