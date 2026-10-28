from typing import Any, Dict, List

from crewai import Agent, Task
from pydantic import BaseModel, Field

from core.config import SEVERITY_LEVELS, THREAT_CATEGORIES


class DetectedThreat(BaseModel):
    """A single detected threat."""

    severity: str = Field(
        ...,
        description="Threat severity: critical, high, medium, low, or informational.",
    )

    category: str = Field(
        ...,
        description="Threat category.",
    )

    vector: str = Field(
        ...,
        description="Attack vector or mechanism associated with the threat.",
    )

    source: str = Field(
        ...,
        description="Security-data source supporting the detection.",
    )


class ThreatData(BaseModel):
    """Structured threat-detection findings."""

    summary: str = Field(
        ...,
        description="Concise summary of the detected threat situation.",
    )

    threats: List[DetectedThreat] = Field(
        default_factory=list,
        description="Detected cybersecurity threats.",
    )


class DetectionAssessment(BaseModel):
    """Structured output produced by the Threat Detection specialist."""

    threat_data: ThreatData = Field(
        ...,
        description="Structured threat-detection findings.",
    )

    threat_severity_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description=(
            "Overall threat severity score from 0 to 100. "
            "This must be the LLM's evidence-based judgment."
        ),
    )

    compromised_systems: int = Field(
        ...,
        ge=0,
        description="Number of systems assessed as compromised.",
    )

    detected: bool = Field(
        ...,
        description="Whether meaningful cybersecurity threats were detected.",
    )


def build_threat_detection_task(
    agent: Agent,
    state: Dict[str, Any],
) -> Task:

    organization = state.get("organization", "UNKNOWN")

    description = f"""
You are the Threat Detection specialist for:

Organization: {organization}

Analyze the organization's security events and network intrusion
signals and identify meaningful cybersecurity threats.

SHARED INTELLIGENCE RECORD:
{state}

Use both deterministic security-data sources:

1. SIEM Event Monitor
2. Network Intrusion Detection Monitor

Correlate their evidence before producing the assessment.

Do not invent security telemetry.

For each meaningful detected threat provide:

- severity
- category
- attack vector
- supporting source

Use these threat categories where applicable:

{THREAT_CATEGORIES}

Use these severity levels:

{SEVERITY_LEVELS}

The `threat_severity_score` must be your own LLM-based cybersecurity
judgment from 0 to 100.

Do NOT calculate it using a hard-coded Python formula, weighted count,
or simple severity count.

The score should consider:

- security-event severity
- intrusion activity
- authentication anomalies
- attack vectors
- evidence of active attacks
- evidence of compromise
- potential business impact

Determine `compromised_systems` from the available evidence.

Set `detected` to true when meaningful cybersecurity threats are
supported by the evidence.

Return ONLY the structured DetectionAssessment.
"""

    return Task(
        description=description,
        expected_output=(
            "A structured DetectionAssessment containing threat_data, "
            "threat_severity_score, compromised_systems, and detected."
        ),
        agent=agent,
        output_pydantic=DetectionAssessment,
    )
