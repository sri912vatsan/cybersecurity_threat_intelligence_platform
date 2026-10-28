"""
Base threat agent.

Implement BaseThreatAgent as the abstract base for every specialist: a constructor
that builds the crewai.Agent (stored as crewai_agent), one abstract analyze_async(state),
and a concrete execute_async(state) that retries and never raises.
"""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from crewai import Agent

from core.config import config


class BaseThreatAgent(ABC):
    """
    Abstract base class for all cybersecurity threat-intelligence specialists.

    Each specialist:
    - provides its own agent_name
    - implements analyze_async()
    - uses the CrewAI Agent created by this base class
    - inherits retry and error-handling behavior from execute_async()
    """

    def __init__(
        self,
        role: str,
        goal: str,
        backstory: str,
        llm: Any,
        tools: Optional[List[Any]] = None,
    ) -> None:
        """
        Build the underlying CrewAI agent.

        Args:
            role: Role assigned to the specialist agent.
            goal: Goal the specialist should accomplish.
            backstory: Background/persona used by the LLM.
            llm: CrewAI-compatible LLM instance.
            tools: Deterministic data-provider tools available to the agent.
        """
        self.crewai_agent = Agent(
            role=role,
            goal=goal,
            backstory=backstory,
            llm=llm,
            tools=tools or [],
        )

        # Every concrete specialist must provide its own distinct name.
        self.agent_name: str = self.__class__.__name__

    @abstractmethod
    async def analyze_async(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform the specialist's actual analysis.

        Concrete subclasses implement this method. The method must return
        the specialist's result as a dictionary.
        """
        raise NotImplementedError

    async def execute_async(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the specialist with retry and error handling.

        The method never raises an exception. If analysis succeeds, the
        returned result is stamped with the agent name, success status and
        timestamp.

        If all attempts fail, a structured error result is returned so that
        the CrewAI Flow can continue executing the remaining specialists.
        """
        last_error: Optional[Exception] = None

        for attempt in range(config.max_retries):
            try:
                result = await self.analyze_async(state)

                if not isinstance(result, dict):
                    raise TypeError(
                        f"{self.agent_name}.analyze_async() must return a dict, "
                        f"got {type(result).__name__}"
                    )

                result["agent"] = self.agent_name
                result["status"] = "success"
                result["timestamp"] = self._timestamp()

                return result

            except Exception as exc:
                last_error = exc

                # Do not sleep after the final attempt.
                if attempt < config.max_retries - 1:
                    await asyncio.sleep(config.retry_delay_seconds)

        # All attempts failed. Never propagate the exception.
        return {
            "agent": self.agent_name,
            "status": "error",
            "error": str(last_error) if last_error else "Unknown error",
            "timestamp": self._timestamp(),
        }

    @staticmethod
    def _timestamp() -> str:
        """Return the current UTC timestamp in ISO-8601 format."""
        return datetime.now(timezone.utc).isoformat()
