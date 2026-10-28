"""
Threat Analysis task.

Implement build_threat_analysis_task(agent, state) and the
AnalysisAssessment output schema.

The task instructs the agent to analyze the threats and count the
critical_threats.

See the problem description for the output fields and the schema.
"""

from typing import Any, Dict, List

from crewai import Agent, Task
from pydantic import BaseModel, Field

from core.config import SEVERITY_LEVELS, THREAT_CATEGORIES


class ThreatActor(BaseModel):
    """Structured threat-actor attribution."""

    name: str = Field(
        ...,
        description="Name of the attributed threat actor.",
    )

    type: str = Field(
        ...,
        description=(
            "Type of threat actor, such as ransomware group, "
            "nation-state, cybercriminal group, or unknown."
        ),
    )

    motivation: str = Field(
        ...,
        description="Likely motivation of the threat actor.",
    )


class AttackPattern(BaseModel):
    """Structured attack-pattern analysis."""

    technique: str = Field(
        ...,
        description=(
            "MITRE ATT&CK technique or attack technique associated "
            "with the observed activity."
        ),
    )

    tactic: str = Field(
        ...,
        description="MITRE ATT&CK tactic associated with the technique.",
    )

    description: str = Field(
        ...,
        description="Description of how the attack pattern relates to the evidence.",
    )


class ThreatAnalysis(BaseModel):
    """Structured threat-analysis findings."""

    summary: str = Field(
        ...,
        description="Concise overall summary of the threat analysis.",
    )

    threat_actors: List[ThreatActor] = Field(
        default_factory=list,
        description=(
            "Threat actors attributed to the observed activity based "
            "on available evidence."
        ),
    )

    attack_patterns: List[AttackPattern] = Field(
        default_factory=list,
        description=(
            "Observed attack techniques and associated tactics."
        ),
    )

    business_impact: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Assessment of potential business impact, including "
            "operational, financial, data, regulatory, and reputational "
            "impact where applicable."
        ),
    )


class AnalysisAssessment(BaseModel):
    """Structured output produced by the Threat Analysis specialist."""

    threat_analysis: ThreatAnalysis = Field(
        ...,
        description="Structured analysis and attribution of detected threats.",
    )

    critical_threats: int = Field(
        ...,
        ge=0,
        description=(
            "Number of threats that the LLM independently judges to be "
            "critical based on the complete available evidence. This "
            "must be an evidence-based LLM judgment and must not be "
            "calculated using a hard-coded formula."
        ),
    )

    analyzed: bool = Field(
        ...,
        description=(
            "True when the available threat intelligence and endpoint "
            "telemetry have been successfully analyzed."
        ),
    )


def build_threat_analysis_task(
    agent: Agent,
    state: Dict[str, Any],
) -> Task:
    """
    Build the threat-analysis CrewAI task.

    The task instructs the LLM to correlate external threat intelligence
    with endpoint telemetry, attribute threats where possible, identify
    attack patterns, assess business impact, and independently judge
    the number of critical threats.
    """

    organization = state.get("organization", "UNKNOWN")

    description = f"""
You are the Threat Analysis specialist for:

Organization: {organization}

Analyze the threats identified during the detection stage and determine
their likely attribution, attack patterns, severity, and business impact.

SHARED INTELLIGENCE RECORD:
{state}

You MUST use both deterministic security-data sources before completing
your assessment:

1. Threat Intelligence Feed
   - Review active threat actors.
   - Review matched indicators of compromise.
   - Review known malware families.
   - Review linked campaigns.
   - Use this evidence to support threat attribution.

2. Endpoint Detection and Response Telemetry
   - Review compromised endpoints.
   - Review process anomalies.
   - Review lateral movement.
   - Review persistence mechanisms.
   - Review evidence of data exfiltration.
   - Use this evidence to establish whether threats are active and
     whether systems appear compromised.

Do not invent threat-intelligence or endpoint evidence that is not
available from the tools or shared intelligence record.

THREAT ANALYSIS

Produce a concise overall analysis summary.

Identify and attribute threat actors where the available evidence
supports attribution.

For each relevant threat actor provide:

- name
- type
- motivation

Identify the attack patterns associated with the observed activity.

For each attack pattern provide:

- MITRE ATT&CK technique or attack technique
- associated tactic
- explanation of how the technique relates to the available evidence

Use the configured threat taxonomy where applicable:

{THREAT_CATEGORIES}

Use the configured severity taxonomy where applicable:

{SEVERITY_LEVELS}

BUSINESS IMPACT

Assess the potential impact of the observed threats.

Consider, where applicable:

- operational disruption
- financial impact
- sensitive-data exposure
- regulatory/compliance impact
- reputational damage
- impact to critical or crown-jewel systems

Represent the business impact as structured key/value information.

Do not invent facts that are not supported by the available evidence.
Distinguish observed evidence from reasonable cybersecurity assessment.

CRITICAL THREAT JUDGMENT — VERY IMPORTANT

You MUST independently determine the number of critical threats based
on your analysis of the complete evidence.

The value of `critical_threats`:

- MUST be your own LLM judgment.
- MUST represent the number of threats you determine are genuinely
  critical.
- MUST consider severity, evidence of active compromise, affected
  systems, attack progression, persistence, lateral movement,
  exfiltration, threat-actor activity, and potential business impact.
- MUST NOT be calculated using a Python formula.
- MUST NOT simply count records whose input severity happens to be
  "critical".
- MUST NOT be derived from the configured critical-threat floor.
- MUST NOT be artificially increased or decreased to force a particular
  routing outcome.

The router will compare your resulting `critical_threats` value against
the configured business-policy threshold.

Your responsibility is to make the best evidence-based cybersecurity
judgment.

CORRELATION REQUIREMENT

Correlate the external threat-intelligence evidence with internal
endpoint telemetry.

For example, if threat intelligence identifies a known threat actor,
malware family, or campaign and endpoint telemetry independently shows
behavior consistent with that activity, explain the relationship in
the analysis.

Pay particular attention to:

- matched IOCs
- known malware
- active campaigns
- compromised endpoints
- process anomalies
- lateral movement
- persistence mechanisms
- data exfiltration
- critical business systems
- potential operational disruption

Do not simply copy the raw tool outputs.

Return ONLY the structured AnalysisAssessment represented by the
required schema.
"""

    return Task(
        description=description,
        expected_output=(
            "A structured AnalysisAssessment containing threat_analysis "
            "with summary, threat_actors, attack_patterns and "
            "business_impact, plus critical_threats and analyzed."
        ),
        agent=agent,
        output_pydantic=AnalysisAssessment,
    )
