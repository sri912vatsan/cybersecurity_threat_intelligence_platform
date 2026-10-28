"""
Human-in-the-loop review.

Implement approve_response(record, reviewer_note) and reject_response(
record, reviewer_note): record the reviewer's decision, finalize the status,
and re-record the run.

See the problem description for the statuses and the return contract.
"""

from typing import Any, Dict

from core.config import STATUS_APPROVED, STATUS_REJECTED
from core.state import finalize_status
from utils.database import record_intel


def approve_response(
    record: Dict[str, Any],
    reviewer_note: str = "",
) -> Dict[str, Any]:
    """
    Approve the incident-response plan.

    Records the SOC analyst's approval and reviewer note, changes the
    intelligence record status to APPROVED, persists the updated record,
    and returns it.
    """

    record["hitl"]["decision"] = "APPROVED"
    record["hitl"]["reviewer_note"] = reviewer_note

    finalize_status(
        record,
        STATUS_APPROVED,
    )

    record_intel(record)

    return record


def reject_response(
    record: Dict[str, Any],
    reviewer_note: str = "",
) -> Dict[str, Any]:
    """
    Reject the incident-response plan.

    Records the SOC analyst's rejection and reviewer note, changes the
    intelligence record status to REJECTED, persists the updated record,
    and returns it.
    """

    record["hitl"]["decision"] = "REJECTED"
    record["hitl"]["reviewer_note"] = reviewer_note

    finalize_status(
        record,
        STATUS_REJECTED,
    )

    record_intel(record)

    return record
