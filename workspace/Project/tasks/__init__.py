"""Task builders — one per agent, each declaring the agent's structured LLM output."""

from tasks.incident_response_task import build_incident_response_task
from tasks.security_recommendation_task import build_security_recommendation_task
from tasks.threat_analysis_task import build_threat_analysis_task
from tasks.threat_detection_task import build_threat_detection_task

__all__ = [
    "build_threat_detection_task",
    "build_threat_analysis_task",
    "build_incident_response_task",
    "build_security_recommendation_task",
]
