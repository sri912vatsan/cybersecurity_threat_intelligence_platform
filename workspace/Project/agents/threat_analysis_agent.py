"""
Threat Analysis agent.

Implement ThreatAnalysisAgent (agent_name "analyst"): a pure-LLM specialist
that attributes threats and counts the critical_threats.

See the problem description for its tools, the result keys, and the schema.
"""

from typing import Any, Dict

from crewai import Crew, Process

from agents.base_agent import BaseThreatAgent
from tasks.threat_analysis_task import build_threat_analysis_task
from tools.endpoint_telemetry_tool import endpoint_telemetry_tool
from tools.threat_intel_feed_tool import threat_intel_feed_tool
from utils.llm_config import get_llm


class ThreatAnalysisAgent(BaseThreatAgent):
    """
    Threat-analysis specialist.

    Analyzes and attributes detected threats using threat-intelligence
    and endpoint telemetry data, then produces an LLM-judged count
    of critical threats.
    """

    agent_name = "analyst"

    def __init__(self) -> None:
        """
        Initialize the threat-analysis specialist.
        """

        super().__init__(
            role="Cybersecurity Threat Analysis Specialist",
            goal=(
                "Analyze and attribute the detected threats using available "
                "threat-intelligence and endpoint telemetry data. Determine "
                "the severity and significance of each threat and use your "
                "own cybersecurity judgment to identify how many threats "
                "should be classified as critical."
            ),
            backstory=(
                "You are an experienced cyber threat intelligence analyst "
                "specializing in threat attribution, adversary behavior, "
                "attack techniques, and incident severity assessment. "
                "You correlate internal endpoint evidence with external "
                "threat intelligence to understand the active threat "
                "landscape. Your critical-threat count must reflect your "
                "reasoned assessment of the evidence rather than a "
                "hard-coded formula or arbitrary threshold."
            ),
            llm=get_llm(
                temperature=0.2,
                max_tokens=2000,
            ),
            tools=[
                threat_intel_feed_tool,
                endpoint_telemetry_tool,
            ],
        )

    async def analyze_async(
        self,
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Analyze and attribute the threats.

        Creates a one-agent CrewAI Crew, executes the analysis task
        asynchronously, and returns the structured AnalysisAssessment
        produced by the LLM.
        """

        task = build_threat_analysis_task(
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

        # The task is configured with output_pydantic=AnalysisAssessment.
        assessment = result.pydantic

        if assessment is None:
            raise ValueError(
                "Threat analysis task did not return a structured "
                "AnalysisAssessment."
            )

        # Pydantic v2.
        if hasattr(assessment, "model_dump"):
            data = assessment.model_dump()

        # Pydantic v1 compatibility.
        elif hasattr(assessment, "dict"):
            data = assessment.dict()

        else:
            raise TypeError(
                "Threat analysis task returned an unexpected "
                "structured-output type."
            )

        return {
            "threat_analysis": data.get(
                "threat_analysis",
                "",
            ),
            "critical_threats": data.get(
                "critical_threats",
                0,
            ),
            "analyzed": data.get(
                "analyzed",
                True,
            ),
        }
