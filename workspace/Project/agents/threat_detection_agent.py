"""
Threat Detection agent.

Implement ThreatDetectionAgent (agent_name "detector"): a pure-LLM specialist
that detects threats and judges a threat_severity_score.

See the problem description for its tools, the result keys, and the schema.
"""

from typing import Any, Dict

from crewai import Crew, Process

from agents.base_agent import BaseThreatAgent
from tasks.threat_detection_task import build_threat_detection_task
from tools.network_ids_tool import network_ids_tool
from tools.siem_events_tool import siem_events_tool
from utils.llm_config import get_llm


class ThreatDetectionAgent(BaseThreatAgent):
    """
    Threat-detection specialist.

    Uses SIEM and network IDS telemetry to identify potential threats and
    produces an LLM-judged threat severity score.
    """

    agent_name = "detector"

    def __init__(self) -> None:
        """
        Initialize the threat-detection specialist.
        """

        super().__init__(
            role="Cybersecurity Threat Detection Specialist",
            goal=(
                "Detect and characterize cybersecurity threats affecting "
                "the organization by analyzing SIEM events and network "
                "intrusion-detection signals. Assess the evidence and use "
                "your cybersecurity judgment to determine an overall "
                "threat severity score and identify potentially "
                "compromised systems."
            ),
            backstory=(
                "You are an experienced cybersecurity threat detection "
                "specialist responsible for identifying active and emerging "
                "security threats. You correlate SIEM events with network "
                "intrusion-detection signals, distinguish meaningful "
                "security incidents from ordinary activity, and assess "
                "the overall severity of the observed threat landscape. "
                "Your severity assessment is based on your analysis of "
                "the available evidence rather than a hard-coded formula."
            ),
            llm=get_llm(
                temperature=0.2,
                max_tokens=2000,
            ),
            tools=[
                siem_events_tool,
                network_ids_tool,
            ],
        )

    async def analyze_async(
        self,
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Detect and characterize threats.

        Creates a one-agent CrewAI Crew, executes the threat-detection
        task asynchronously, and returns the structured DetectionAssessment
        produced by the LLM.
        """

        task = build_threat_detection_task(
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

        # The task is configured with output_pydantic=DetectionAssessment.
        assessment = result.pydantic

        if assessment is None:
            raise ValueError(
                "Threat detection task did not return a structured "
                "DetectionAssessment."
            )

        # Pydantic v2.
        if hasattr(assessment, "model_dump"):
            data = assessment.model_dump()

        # Pydantic v1 compatibility.
        elif hasattr(assessment, "dict"):
            data = assessment.dict()

        else:
            raise TypeError(
                "Threat detection task returned an unexpected "
                "structured-output type."
            )

        return {
            "threat_data": data.get(
                "threat_data",
                [],
            ),
            "threat_severity_score": data.get(
                "threat_severity_score",
                0.0,
            ),
            "compromised_systems": data.get(
                "compromised_systems",
                0,
            ),
            "detected": data.get(
                "detected",
                False,
            ),
        }
