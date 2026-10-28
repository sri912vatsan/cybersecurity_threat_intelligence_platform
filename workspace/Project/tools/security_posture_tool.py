"""
Security posture tool.

Implement security_posture_tool(organization) as a CrewAI @tool that
surfaces an organization's overall security-posture audit for the agent
to weigh. Deterministic.

See the problem description for the display name and the return shape.
"""

import json
from pathlib import Path
from typing import Any, Dict

from crewai.tools import tool

from core.config import config


@tool("Security Posture Audit")
def security_posture_tool(organization: str) -> Dict[str, Any]:
    """
    Retrieve the overall security-posture audit for an organization.

    The tool reads deterministic security-posture data from
    data/threat_store.json. It does not perform LLM reasoning,
    scoring, or recommendation generation.

    Args:
        organization: Organization whose security posture should
            be retrieved.

    Returns:
        A dictionary containing the organization, availability status,
        and security-posture audit data.
    """

    store_path = Path(config.data_dir) / "threat_store.json"

    try:
        with store_path.open("r", encoding="utf-8") as file:
            store = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        return {
            "organization": organization,
            "available": False,
            "security_posture": {},
            "error": f"Unable to load threat store: {exc}",
        }

    organizations = store.get("organizations", {})
    organization_data = organizations.get(organization)

    if organization_data is None:
        return {
            "organization": organization,
            "available": False,
            "security_posture": {},
        }

    security_posture = organization_data.get(
        "posture",
        {},
    )

    return {
        "organization": organization,
        "available": True,
        "security_posture": security_posture,
    }
