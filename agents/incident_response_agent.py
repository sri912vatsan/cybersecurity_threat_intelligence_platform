"""
Incident Response agent.

Implement IncidentResponseAgent (agent_name "responder"): a pure-LLM specialist
that builds an incident-response plan.

See the problem description for its tools, the result keys, and the schema.
"""

from typing import Any, Dict

from crewai import Crew, Process

from agents.base_agent import BaseThreatAgent
from tasks.incident_response_task import build_incident_response_task
from tools.asset_inventory_tool import asset_inventory_tool
from tools.vulnerability_scan_tool import vulnerability_scan_tool
from utils.llm_config import get_llm


class IncidentResponseAgent(BaseThreatAgent):
    """
    Incident-response specialist.

    The agent reasons over asset-inventory and vulnerability-scan data
    retrieved through deterministic tools and produces a structured
    incident-response assessment.
    """

    agent_name = "responder"

    def __init__(self) -> None:
        """
        Initialize the incident-response specialist.
        """

        super().__init__(
            role="Incident Response Specialist",
            goal=(
                "Develop a comprehensive incident-response plan based on the "
                "identified threats, affected systems, asset inventory, and "
                "vulnerability findings. Determine appropriate containment, "
                "forensic investigation, and response actions."
            ),
            backstory=(
                "You are an experienced cybersecurity incident-response "
                "specialist. You analyze evidence provided by security data "
                "sources, identify affected assets and relevant "
                "vulnerabilities, and formulate practical containment and "
                "forensic-response actions. Your recommendations must be "
                "grounded in the data retrieved by your tools."
            ),
            llm=get_llm(
                temperature=0.2,
                max_tokens=2000,
            ),
            tools=[
                asset_inventory_tool,
                vulnerability_scan_tool,
            ],
        )

    async def analyze_async(
        self,
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run the incident-response specialist.

        Creates a one-agent CrewAI Crew, executes the response task
        asynchronously, and returns the structured ResponseAssessment
        produced by the LLM.
        """

        task = build_incident_response_task(
            agent=self.crewai_agent,
            state=state,
        )

        crew = Crew(
            agents=[self.crewai_agent],
            tasks=[task],
            process=Process.sequential,
            verbose=False,
        )

        result = await crew.kickoff_async()

        # The task is contractually configured with output_pydantic
        # pointing to ResponseAssessment.
        assessment = result.pydantic

        if assessment is None:
            raise ValueError(
                "Incident response task did not return a structured "
                "ResponseAssessment."
            )

        # Pydantic v2.
        if hasattr(assessment, "model_dump"):
            data = assessment.model_dump()

        # Pydantic v1 compatibility.
        elif hasattr(assessment, "dict"):
            data = assessment.dict()

        else:
            raise TypeError(
                "Incident response task returned an unexpected "
                "structured-output type."
            )

        return {
            "response_actions": data.get("response_actions", []),
            "forensic_findings": data.get("forensic_findings", []),
            "containment_summary": data.get("containment_summary", ""),
            "responded": data.get("responded", True),
        }
