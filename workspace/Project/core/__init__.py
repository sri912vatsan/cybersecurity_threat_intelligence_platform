"""Core package: configuration + shared constants (config) and the shared intelligence record (state).

Individual constants (statuses, routes, taxonomies, DB schema) are imported by their explicit path, e.g.
``from core.config import STATUS_COMPLETED``; this package re-exports the primary objects and the state
operations for convenience.
"""

from core.config import config, validate_config
from core.state import add_agent_result, add_error, create_intel_state, finalize_status

__all__ = ["config", "validate_config", "create_intel_state", "add_agent_result",
           "finalize_status", "add_error"]
