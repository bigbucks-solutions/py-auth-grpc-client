"""Pure entitlement decisions evaluated from local snapshot data."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from .entitlements import DenialReason, OrgEntitlements

logger = logging.getLogger(__name__)
Reason = DenialReason


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Optional[Reason]
    enforced: bool


def _decision(snapshot: OrgEntitlements, reason: Optional[Reason]) -> Decision:
    allowed = reason is None or not snapshot.enforced
    if reason is not None and not snapshot.enforced:
        logger.info("Entitlement denial observed: %s", reason.name)
    return Decision(allowed=allowed, reason=reason, enforced=snapshot.enforced)


def check_feature(snapshot: OrgEntitlements, feature: str) -> Decision:
    """Check a feature without performing an RPC."""
    if not snapshot.managed:
        return _decision(snapshot, None)
    if not snapshot.entitled:
        return _decision(snapshot, Reason.NOT_ENTITLED)
    if feature not in snapshot.features:
        return _decision(snapshot, Reason.FEATURE_NOT_IN_PLAN)
    return _decision(snapshot, None)


def check_limit(
    snapshot: OrgEntitlements,
    key: str,
    used: int,
    requested: int = 1,
) -> Decision:
    """Check a cap or quota from a snapshot and caller-counted usage.

    This check takes no locks. Two concurrent creates can both pass with one
    unit left, so exact caps must be re-counted in the creating transaction.
    Negative usage values are treated as zero by the shared rule contract.
    """
    used = max(used, 0)
    requested = max(requested, 0)
    if not snapshot.managed:
        return _decision(snapshot, None)
    if not snapshot.entitled:
        return _decision(snapshot, Reason.NOT_ENTITLED)
    limit = snapshot.limits.get(key)
    if limit is None:
        return _decision(snapshot, Reason.LIMIT_NOT_IN_PLAN)
    if limit.unlimited or used + requested <= limit.limit:
        return _decision(snapshot, None)
    return _decision(snapshot, Reason.LIMIT_EXCEEDED)
