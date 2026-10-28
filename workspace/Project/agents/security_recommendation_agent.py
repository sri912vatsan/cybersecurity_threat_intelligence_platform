"""
Security Recommendation agent.

Implement SecurityRecommendationAgent (agent_name "advisor"): a pure-LLM
specialist that produces prioritised security recommendations and a report.

See the problem description for its tools, the result keys, and the schema.
"""

from typing import Any, Dict

from crewai import Crew, Process

from agents.base_agent import BaseThreatAgent
from tasks.security_recommendation_task import (
    build_security_recommendation_task,
)
from tools.compliance_benchmark_tool import compliance_benchmark_tool
from tools.security_posture_tool import security_posture_tool
from utils.llm_config import get_llm


class SecurityRecommendationAgent(BaseThreatAgent):
    """
    Security recommendation specialist.

    Synthesizes the threat analysis and incident-response findings with
    compliance and security-posture information to produce prioritized
    security improvements, a roadmap, and a final report.
    """

    agent_name = "advisor"

    def __init__(self) -> None:
        """
        Initialize the security recommendation specialist.
        """

        super().__init__(
            role="Cybersecurity Security Recommendation Specialist",
            goal=(
                "Synthesize the threat intelligence, threat analysis, "
                "incident-response findings, compliance posture, and "
                "security posture into prioritized security recommendations. "
                "Produce a practical remediation roadmap and a clear "
                "security intelligence report."
            ),
            backstory=(
                "You are an experienced cybersecurity security architect "
                "and risk advisor. You assess an organization's security "
                "posture against relevant compliance frameworks and "
                "security controls, correlate those findings with active "
                "threats and incident-response results, and prioritize "
                "security improvements according to risk, urgency, "
                "business impact, and feasibility. Your recommendations "
                "must be grounded in the information available through "
                "the provided tools and the intelligence record."
            ),
            llm=get_llm(
                temperature=0.4,
                max_tokens=2000,
            ),
            tools=[
                compliance_benchmark_tool,
                security_posture_tool,
            ],
        )

    async def analyze_async(
        self,
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run the security recommendation specialist.

        Creates a one-agent CrewAI Crew, executes the recommendation task
        asynchronously, and returns the structured RecommendationAssessment
        produced by the LLM.
        """

        task = build_security_recommendation_task(
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

        # The task is configured with output_pydantic=RecommendationAssessment.
        assessment = result.pydantic

        if assessment is None:
            raise ValueError(
                "Security recommendation task did not return a structured "
                "RecommendationAssessment."
            )

        # Pydantic v2.
        if hasattr(assessment, "model_dump"):
            data = assessment.model_dump()

        # Pydantic v1 compatibility.
        elif hasattr(assessment, "dict"):
            data = assessment.dict()

        else:
            raise TypeError(
                "Security recommendation task returned an unexpected "
                "structured-output type."
            )

        return {
            "security_recommendations": data.get(
                "security_recommendations",
                [],
            ),
            "roadmap": data.get(
                "roadmap",
                [],
            ),
            "recommendations_count": data.get(
                "recommendations_count",
                0,
            ),
            "confidence": data.get(
                "confidence",
                0.0,
            ),
            "rationale": data.get(
                "rationale",
                "",
            ),
            "report": data.get(
                "report",
                "",
            ),
        }
