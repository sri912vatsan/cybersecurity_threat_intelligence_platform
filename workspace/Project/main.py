"""
Application entry point.

Run (from the Project folder):
    python3 -m streamlit run main.py

Implement run_threat_intelligence(organization): validate the config, run the flow for one
organization, and return the finished record. Then render the pre-loaded console with it and HITL.
See the problem description for the entry contract and the interface call.
"""

# IMPORTANT:
# core.config must be imported before any module that imports CrewAI.
# Its module-level bootstrap configures CrewAI telemetry/tracing behavior.
from core.config import validate_config

import asyncio

from flows.threat_intelligence_flow import ThreatIntelligenceFlow
from human_intervention.approval_manager import (
    approve_response,
    reject_response,
)
from utils.database import list_intel
from streamlit_UI import render_app


def run_threat_intelligence(organization: str) -> dict:
    """
    Run the complete threat-intelligence workflow for one organization.

    This is the single programmatic entry point used by the Streamlit
    console.

    Args:
        organization: Organization selected for threat-intelligence analysis.

    Returns:
        The finished shared intelligence record.
    """

    validate_config()

    flow = ThreatIntelligenceFlow()

    asyncio.run(
        flow.kickoff_async(
            inputs={
                "organization": organization,
            }
        )
    )

    return flow.state["intel"]


render_app(
    run_threat_intelligence,
    approve_response,
    reject_response,
    list_intel,
)
