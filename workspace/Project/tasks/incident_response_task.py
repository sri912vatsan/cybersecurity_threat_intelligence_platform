"""
Incident Response task.

Implement build_incident_response_task(agent, state) and the
ResponseAssessment output schema.

The task instructs the agent to build an incident-response plan.
See the problem description for the output fields and the schema.
"""

from typing import Any, Dict, List

from crewai import Agent, Task
from pydantic import BaseModel, Field

from core.config import RESPONSE_STAGES


class ResponseAction(BaseModel):
    """A single prioritized incident-response action."""

    priority: str = Field(
        ...,
        description=(
            "Priority of the response action. Use values such as "
            "critical, immediate, high, urgent, medium, or low."
        ),
    )

    phase: str = Field(
        ...,
        description=(
            "Incident-response lifecycle phase. Prefer one of: "
            "identification, containment, eradication, recovery, "
            "or lessons_learned."
        ),
    )

    action: str = Field(
        ...,
        description="Specific actionable incident-response step.",
    )

    target: str = Field(
        ...,
        description=(
            "System, asset, identity, network segment, application, "
            "or other target affected by the response action."
        ),
    )


class ForensicFinding(BaseModel):
    """A forensic finding identified from the available evidence."""

    evidence: str = Field(
        ...,
        description="Evidence supporting the forensic finding.",
    )

    finding: str = Field(
        ...,
        description="Forensic conclusion derived from the available evidence.",
    )


class ResponseAssessment(BaseModel):
    """Structured output produced by the Incident Response specialist."""

    response_actions: List[ResponseAction] = Field(
        default_factory=list,
        description=(
            "Prioritized incident-response actions covering the "
            "applicable response lifecycle phases."
        ),
    )

    forensic_findings: List[ForensicFinding] = Field(
        default_factory=list,
        description=(
            "Important forensic findings and the evidence supporting "
            "those findings."
        ),
    )

    containment_summary: str = Field(
        ...,
        description=(
            "Concise summary of the recommended containment strategy, "
            "including the most important immediate containment measures."
        ),
    )

    responded: bool = Field(
        ...,
        description=(
            "True when a meaningful incident-response plan has been "
            "successfully developed from the available evidence."
        ),
    )


def build_incident_response_task(
    agent: Agent,
    state: Dict[str, Any],
) -> Task:
    """
    Build the incident-response CrewAI task.

    The task provides the specialist with the shared intelligence record
    and instructs it to use deterministic asset-inventory and vulnerability
    data before producing the structured response assessment.
    """

    organization = state.get("organization", "UNKNOWN")

    description = f"""
You are the Incident Response specialist for:

Organization: {organization}

Your responsibility is to develop a practical, prioritized
incident-response plan based on the complete threat-intelligence record.

SHARED INTELLIGENCE RECORD:
{state}

You MUST use both deterministic tools before finalizing your plan:

1. Asset Inventory System
   - Identify affected systems and assets.
   - Identify critical assets and crown-jewel systems.
   - Review network segments.
   - Review internet-exposed assets.
   - Use this information to determine appropriate containment targets.

2. Vulnerability Scanner
   - Review relevant vulnerability findings.
   - Identify weaknesses that may contribute to the incident.
   - Use the findings to support containment, eradication, recovery,
     and remediation decisions.

Do not invent asset or vulnerability information that is not available
from the tools or shared intelligence record.

INCIDENT-RESPONSE PLAN

Develop actionable response steps across the applicable incident-response
lifecycle phases:

{RESPONSE_STAGES}

For every response action provide:

- priority
- phase
- action
- target

Prioritize actions based on:

- active threat severity
- evidence of compromise
- compromised systems
- critical assets
- crown-jewel systems
- internet exposure
- lateral movement
- persistence
- data exfiltration
- relevant vulnerabilities
- potential business impact

The response plan must distinguish between immediate containment
actions and longer-term eradication, recovery, and lessons-learned
activities.

CONTAINMENT

Provide a concise `containment_summary`.

The containment strategy should clearly identify the most important
immediate actions needed to limit further compromise or data loss.

For critical incidents, give particular attention to:

- isolating compromised endpoints
- limiting lateral movement
- protecting crown-jewel systems
- blocking malicious infrastructure
- preserving evidence
- preventing further data exfiltration

Do not claim that a containment action has actually been executed.
This task produces a recommended response plan for the appropriate
human/security workflow.

FORENSIC FINDINGS

Identify important forensic findings from the available evidence.

For each finding provide:

- evidence
- finding

Do not invent forensic evidence.

RESPONSE QUALITY

Do not merely repeat the threat-detection or threat-analysis output.

Reason over the available threat intelligence, endpoint telemetry,
asset inventory, and vulnerability findings to produce a practical
incident-response plan.

Use the available evidence to determine which systems and assets should
receive the highest response priority.

Set `responded` to true when a meaningful incident-response plan has
been successfully developed from the available evidence.

Return ONLY the structured ResponseAssessment represented by the
required schema.
"""

    return Task(
        description=description,
        expected_output=(
            "A structured ResponseAssessment containing response_actions, "
            "forensic_findings, containment_summary, and responded."
        ),
        agent=agent,
        output_pydantic=ResponseAssessment,
    )
