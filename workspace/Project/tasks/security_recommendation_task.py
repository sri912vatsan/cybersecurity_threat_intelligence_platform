"""
Security Recommendation task.

Implement build_security_recommendation_task(agent, state) and the
RecommendationAssessment output schema.

The task instructs the agent to produce prioritised recommendations
and a report.

See the problem description for the output fields and the schema.
"""

from typing import Any, Dict, List

from crewai import Agent, Task
from pydantic import BaseModel, Field

from core.config import SECURITY_FRAMEWORKS


class SecurityRecommendation(BaseModel):
    """A single prioritized security recommendation."""

    priority: str = Field(
        ...,
        description=(
            "Priority of the recommendation. Use critical, high, "
            "medium, or low."
        ),
    )

    category: str = Field(
        ...,
        description=(
            "Security-control or recommendation category, such as "
            "identity, endpoint, network, data protection, vulnerability "
            "management, monitoring, governance, or incident response."
        ),
    )

    control: str = Field(
        ...,
        description=(
            "Relevant security control or framework control that the "
            "recommendation addresses."
        ),
    )

    recommendation: str = Field(
        ...,
        description=(
            "Specific actionable security recommendation."
        ),
    )


class RoadmapItem(BaseModel):
    """A security-improvement roadmap item."""

    initiative: str = Field(
        ...,
        description="Name of the security improvement initiative.",
    )

    timeframe: str = Field(
        ...,
        description=(
            "Recommended implementation timeframe, such as "
            "0-72 Hours, 1-4 Weeks, 1-6 Months, or Ongoing."
        ),
    )

    effort: str = Field(
        ...,
        description="Estimated implementation effort.",
    )

    roi: str = Field(
        ...,
        description="Expected security/business return or benefit.",
    )


class RecommendationAssessment(BaseModel):
    """Structured output produced by the Security Recommendation specialist."""

    security_recommendations: List[SecurityRecommendation] = Field(
        default_factory=list,
        description=(
            "Prioritized security recommendations derived from the "
            "complete threat-intelligence, incident-response, compliance, "
            "and security-posture evidence."
        ),
    )

    roadmap: List[RoadmapItem] = Field(
        default_factory=list,
        description=(
            "Prioritized implementation roadmap for the recommended "
            "security improvements."
        ),
    )

    recommendations_count: int = Field(
        ...,
        ge=0,
        description="Number of security recommendations produced.",
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence in the overall recommendation assessment, "
            "between 0.0 and 1.0."
        ),
    )

    rationale: str = Field(
        ...,
        description=(
            "Reasoning explaining why the recommendations were "
            "prioritized in their selected order."
        ),
    )

    report: str = Field(
        ...,
        description=(
            "Complete Markdown security intelligence report containing "
            "executive summary, key findings, incident response, "
            "prioritized recommendations, next steps, and human-review "
            "context where applicable."
        ),
    )


def build_security_recommendation_task(
    agent: Agent,
    state: Dict[str, Any],
) -> Task:
    """
    Build the security-recommendation CrewAI task.

    The task instructs the LLM to synthesize the complete intelligence
    record with compliance and security-posture evidence and produce
    prioritized recommendations, an implementation roadmap, and the
    final Markdown report.
    """

    organization = state.get("organization", "UNKNOWN")

    description = f"""
You are the Security Recommendation specialist for:

Organization: {organization}

Your responsibility is to synthesize the complete threat-intelligence
record and produce prioritized security recommendations, an
implementation roadmap, and the final security intelligence report.

SHARED INTELLIGENCE RECORD:
{state}

You MUST use both deterministic tools before producing the final
assessment:

1. Compliance Framework Benchmark
   - Review the organization's standing against relevant security
     frameworks.
   - Identify meaningful control or compliance gaps.
   - Use the findings to support framework/control recommendations.

2. Security Posture Audit
   - Review the organization's overall security posture.
   - Identify security-control weaknesses and improvement areas.
   - Use the findings to prioritize recommendations.

Do not invent compliance or security-posture findings that are not
available from the tools or shared intelligence record.

AVAILABLE REFERENCE FRAMEWORKS:

{SECURITY_FRAMEWORKS}

RECOMMENDATIONS

Produce a prioritized list of actionable security recommendations.

For every recommendation provide:

- priority
- category
- relevant security control or framework control
- actionable recommendation

Prioritize recommendations based on:

1. Immediate risk to the organization.
2. Active compromise and containment requirements.
3. Protection of critical and crown-jewel assets.
4. Likelihood of recurrence.
5. Exploitable vulnerabilities and control weaknesses.
6. Compliance and framework gaps.
7. Long-term security resilience.

Do not simply repeat the incident-response actions.

Recommendations should address both immediate remediation and
longer-term security improvements.

ROADMAP

Create a practical implementation roadmap.

Use appropriate timeframes such as:

- 0-72 Hours
- 1-4 Weeks
- 1-6 Months
- Ongoing

For each roadmap item provide:

- initiative
- timeframe
- effort
- expected security/business return (roi)

CONFIDENCE

Provide a confidence value between 0.0 and 1.0 representing your
confidence in the overall recommendation assessment based on the
available evidence.

RATIONALE

Explain why the recommendations were prioritized in their selected
order.

Connect the rationale to:

- observed threats
- threat severity
- compromised systems
- critical assets
- forensic findings
- incident-response requirements
- vulnerabilities
- compliance gaps
- security-posture weaknesses
- potential business impact

FINAL REPORT

Produce a complete Markdown security intelligence report.

Use the following sections where applicable:

# Security Intelligence Report

## Executive Summary

Summarize the overall security situation, major threats, severity,
business impact, and immediate concerns.

## Key Findings

Summarize the most important detection, threat-analysis, and forensic
findings.

## Incident Response

Summarize the response actions, containment strategy, and relevant
forensic findings.

## Prioritised Recommendations

Present the prioritized security recommendations and their relevant
controls/frameworks.

## Next Steps

Present the recommended implementation roadmap and immediate actions.

## Human Review — Critical Incident

If the intelligence record indicates that human review is required,
clearly identify that the incident requires SOC analyst review and
approval before the containment plan is adopted.

If human review is not required, do not incorrectly state that a
critical incident is awaiting approval.

The report must be useful to both technical security personnel and
business stakeholders.

Return ONLY the structured RecommendationAssessment represented by
the required schema.
"""

    return Task(
        description=description,
        expected_output=(
            "A structured RecommendationAssessment containing "
            "security_recommendations, roadmap, recommendations_count, "
            "confidence, rationale, and report."
        ),
        agent=agent,
        output_pydantic=RecommendationAssessment,
    )
