"""
Compliance benchmark tool.

Implement compliance_benchmark_tool(organization) as a CrewAI @tool that
surfaces an organization's standing against the reference frameworks for
the agent to weigh. Deterministic.

See the problem description for the display name and the return shape.
"""

import json
from pathlib import Path
from typing import Any, Dict

from crewai.tools import tool

from core.config import config


@tool("Compliance Framework Benchmark")
def compliance_benchmark_tool(organization: str) -> Dict[str, Any]:
    """
    Retrieve compliance-framework benchmark data for an organization.

    The tool reads deterministic compliance data from
    data/threat_store.json. It does not perform LLM reasoning,
    compliance scoring, or recommendation generation.

    Args:
        organization: Organization whose compliance benchmark should
            be retrieved.

    Returns:
        A dictionary containing the organization, availability status,
        and compliance benchmark data.
    """

    store_path = Path(config.data_dir) / "threat_store.json"

    try:
        with store_path.open("r", encoding="utf-8") as file:
            store = json.load(file)

    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        return {
            "organization": organization,
            "available": False,
            "compliance_benchmark": {},
            "error": f"Unable to load threat store: {exc}",
        }

    organizations = store.get("organizations", {})
    organization_data = organizations.get(organization)

    if organization_data is None:
        return {
            "organization": organization,
            "available": False,
            "compliance_benchmark": {},
        }

    compliance_benchmark = organization_data.get(
        "compliance",
        {},
    )

    return {
        "organization": organization,
        "available": True,
        "compliance_benchmark": compliance_benchmark,
    }
