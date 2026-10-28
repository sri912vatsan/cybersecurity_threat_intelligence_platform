"""
The CrewAI Flow for threat intelligence.

Implement ThreatIntelligenceFlow: a CrewAI Flow whose steps are wired with
@start, @listen and a @router (rejoining the mode branches with or_).
The router reads the analyst's own judgement.

See the problem description for the step methods, the routing labels,
and the mode/rejoin structure.
"""

import time
from typing import Any, Dict

from crewai.flow.flow import Flow, listen, or_, router, start

from agents.incident_response_agent import IncidentResponseAgent
from agents.security_recommendation_agent import SecurityRecommendationAgent
from agents.threat_analysis_agent import ThreatAnalysisAgent
from agents.threat_detection_agent import ThreatDetectionAgent

from core.config import (
    ROUTE_PRIORITY,
    ROUTE_STANDARD,
    STATUS_COMPLETED,
    STATUS_REVIEW,
    config,
)

from core.state import (
    add_agent_result,
    add_error,
    create_intel_state,
    finalize_status,
)

from utils.database import record_intel


class ThreatIntelligenceFlow(Flow):
    """
    Main CrewAI Flow for the cybersecurity threat-intelligence pipeline.

    The flow maintains exactly one shared intelligence record in:

        self.state["intel"]

    Every specialist reads from that record and returns its result to the
    corresponding flow step, which updates the shared record.
    """

    def __init__(self) -> None:
        super().__init__()

        self.detector = ThreatDetectionAgent()
        self.analyst = ThreatAnalysisAgent()
        self.responder = IncidentResponseAgent()
        self.advisor = SecurityRecommendationAgent()

    # ------------------------------------------------------------------
    # Step 1: Threat Detection
    # ------------------------------------------------------------------

    @start()
    async def detect_threats(self) -> Dict[str, Any]:
        """
        Create the intelligence record and run threat detection.

        This is the only @start step. It initializes the shared record and
        stores the workflow start timestamp before invoking the detector.
        """
        organization = self.state.get("organization", "UNKNOWN")

        intel = create_intel_state(
            {
                "organization": organization,
            }
        )

        self.state["intel"] = intel
        self.state["workflow_started_at"] = time.perf_counter()

        step_started = time.perf_counter()

        try:
            result = await self.detector.execute_async(
                self.state["intel"]
            )

            add_agent_result(
                self.state["intel"],
                self.detector.agent_name,
                result,
            )

            # Preserve the specialist's result in the main intelligence
            # record because these fields are consumed by later stages.
            self.state["intel"]["threat_data"] = result.get(
                "threat_data",
                {},
            )

            self.state["intel"]["threat_severity_score"] = result.get(
                "threat_severity_score",
                0.0,
            )

            self.state["intel"]["compromised_systems"] = result.get(
                "compromised_systems",
                0,
            )

            self.state["intel"]["detected"] = result.get(
                "detected",
                False,
            )

            if result.get("status") == "error":
                add_error(
                    self.state["intel"],
                    result.get(
                        "error",
                        "Threat detection failed.",
                    ),
                    self.detector.agent_name,
                )

        except Exception as exc:
            # The specialist contract says execute_async should never raise,
            # but keep the Flow resilient if an unexpected implementation
            # error occurs.
            add_error(
                self.state["intel"],
                str(exc),
                self.detector.agent_name,
            )

        self.state["intel"]["metrics"]["detector"] = round(
            time.perf_counter() - step_started,
            3,
        )

        return self.state["intel"]

    # ------------------------------------------------------------------
    # Step 2: Threat Analysis
    # ------------------------------------------------------------------

    @listen(detect_threats)
    async def analyze_threats(
        self,
        intel: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Analyze and attribute the detected threats.

        The analyst's critical_threats value is deliberately preserved
        as the LLM's structured judgment. No Python severity formula is
        applied here.
        """

        step_started = time.perf_counter()

        try:
            result = await self.analyst.execute_async(
                self.state["intel"]
            )

            add_agent_result(
                self.state["intel"],
                self.analyst.agent_name,
                result,
            )

            self.state["intel"]["threat_analysis"] = result.get(
                "threat_analysis",
                {},
            )

            self.state["intel"]["critical_threats"] = result.get(
                "critical_threats",
                0,
            )

            self.state["intel"]["analyzed"] = result.get(
                "analyzed",
                False,
            )

            if result.get("status") == "error":
                add_error(
                    self.state["intel"],
                    result.get(
                        "error",
                        "Threat analysis failed.",
                    ),
                    self.analyst.agent_name,
                )

        except Exception as exc:
            add_error(
                self.state["intel"],
                str(exc),
                self.analyst.agent_name,
            )

        self.state["intel"]["metrics"]["analyst"] = round(
            time.perf_counter() - step_started,
            3,
        )

        return self.state["intel"]

    # ------------------------------------------------------------------
    # Criticality Router
    # ------------------------------------------------------------------

    @router(analyze_threats)
    def route_by_criticality(self) -> str:
        """
        Route the workflow based on the analyst's own LLM judgment.

        This router is intentionally read-only. It does not modify the
        intelligence record.

        critical_threats >= config.critical_threat_floor
            -> PRIORITY mode + HITL

        critical_threats < config.critical_threat_floor
            -> STANDARD mode
        """

        # Read the shared intelligence record directly from Flow state.
        # This allows the router to be called without an explicit intel
        # argument, which is also how the unit tests exercise it.
        intel = self.state["intel"]

        critical_threats = intel.get(
            "critical_threats",
            0,
        )

        if critical_threats >= config.critical_threat_floor:
            return ROUTE_PRIORITY

        return ROUTE_STANDARD

    # ------------------------------------------------------------------
    # Mode branches
    # ------------------------------------------------------------------

    @listen(ROUTE_PRIORITY)
    def flag_priority_response(self) -> Dict[str, Any]:
        """
        Mark the run as priority and require human SOC review.

        The shared intelligence record is obtained from self.state because
        these branch methods are also directly callable without arguments.
        """

        self.state["intel"]["response_mode"] = "priority"
        self.state["intel"]["hitl"]["required"] = True

        return self.state["intel"]

    @listen(ROUTE_STANDARD)
    def mark_standard_response(self) -> Dict[str, Any]:
        """
        Mark the run as standard.

        Standard runs do not require human approval.
        """

        self.state["intel"]["response_mode"] = "standard"
        self.state["intel"]["hitl"]["required"] = False

        return self.state["intel"]

    # ------------------------------------------------------------------
    # Step 3: Incident Response
    # ------------------------------------------------------------------

    @listen(or_(flag_priority_response, mark_standard_response))
    async def respond_to_incidents(
        self,
        intel: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Rejoin the priority/standard branches and execute incident response.

        Both routing branches always reach this step.
        """

        step_started = time.perf_counter()

        try:
            result = await self.responder.execute_async(
                self.state["intel"]
            )

            add_agent_result(
                self.state["intel"],
                self.responder.agent_name,
                result,
            )

            self.state["intel"]["response_actions"] = result.get(
                "response_actions",
                [],
            )

            self.state["intel"]["forensic_findings"] = result.get(
                "forensic_findings",
                [],
            )

            self.state["intel"]["containment_summary"] = result.get(
                "containment_summary",
                "",
            )

            self.state["intel"]["responded"] = result.get(
                "responded",
                False,
            )

            if result.get("status") == "error":
                add_error(
                    self.state["intel"],
                    result.get(
                        "error",
                        "Incident response failed.",
                    ),
                    self.responder.agent_name,
                )

        except Exception as exc:
            add_error(
                self.state["intel"],
                str(exc),
                self.responder.agent_name,
            )

        self.state["intel"]["metrics"]["responder"] = round(
            time.perf_counter() - step_started,
            3,
        )

        return self.state["intel"]

    # ------------------------------------------------------------------
    # Step 4: Security Recommendations
    # ------------------------------------------------------------------

    @listen(respond_to_incidents)
    async def recommend_security(
        self,
        intel: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate prioritized security recommendations and the final report.
        """

        step_started = time.perf_counter()

        try:
            result = await self.advisor.execute_async(
                self.state["intel"]
            )

            add_agent_result(
                self.state["intel"],
                self.advisor.agent_name,
                result,
            )

            self.state["intel"]["security_recommendations"] = result.get(
                "security_recommendations",
                [],
            )

            self.state["intel"]["roadmap"] = result.get(
                "roadmap",
                [],
            )

            self.state["intel"]["recommendations_count"] = result.get(
                "recommendations_count",
                0,
            )

            self.state["intel"]["confidence"] = result.get(
                "confidence",
                0.0,
            )

            self.state["intel"]["rationale"] = result.get(
                "rationale",
                "",
            )

            self.state["intel"]["report"] = result.get(
                "report",
                "",
            )

            if result.get("status") == "error":
                add_error(
                    self.state["intel"],
                    result.get(
                        "error",
                        "Security recommendation generation failed.",
                    ),
                    self.advisor.agent_name,
                )

        except Exception as exc:
            add_error(
                self.state["intel"],
                str(exc),
                self.advisor.agent_name,
            )

        self.state["intel"]["metrics"]["advisor"] = round(
            time.perf_counter() - step_started,
            3,
        )

        return self.state["intel"]

    # ------------------------------------------------------------------
    # Finalization
    # ------------------------------------------------------------------

    @listen(recommend_security)
    def finalize_intelligence(self) -> Dict[str, Any]:
        """
        Finalize the intelligence record and persist it to SQLite.

        Critical runs remain QUEUED_FOR_REVIEW. Standard runs are completed
        automatically.
        """

        # Read the shared intelligence record directly from Flow state.
        intel = self.state["intel"]

        workflow_started = self.state.get(
            "workflow_started_at"
        )

        if workflow_started is not None:
            total_seconds = round(
                time.perf_counter() - workflow_started,
                3,
            )

            intel["metrics"]["total_seconds"] = total_seconds

        if intel["hitl"].get(
            "required",
            False,
        ):
            final_status = STATUS_REVIEW
        else:
            final_status = STATUS_COMPLETED

        finalize_status(
            intel,
            final_status,
        )

        # Persist the finished intelligence record to the SQLite audit trail.
        record_intel(
            intel
        )

        return intel
