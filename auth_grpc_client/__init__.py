"""Python gRPC client for the Auth service."""

from .client import (
    AuthenticateResult,
    AuthGrpcClient,
    AuthorizeResult,
    PermissionDetail,
    UserOrgRole,
)
from .entitlements import (
    DenialReason,
    EntitlementLimit,
    EntitlementPlan,
    EntitlementsAuthError,
    EntitlementsClient,
    EntitlementsError,
    EntitlementsPermissionError,
    EntitlementsUnavailableError,
    LimitKind,
    OrgEntitlements,
    SubscriptionState,
)
from .rules import Decision, Reason, check_feature, check_limit

__version__ = "0.2.0"

__all__ = [
    "AuthGrpcClient",
    "AuthenticateResult",
    "AuthorizeResult",
    "Decision",
    "DenialReason",
    "EntitlementLimit",
    "EntitlementPlan",
    "EntitlementsAuthError",
    "EntitlementsClient",
    "EntitlementsError",
    "EntitlementsPermissionError",
    "EntitlementsUnavailableError",
    "LimitKind",
    "OrgEntitlements",
    "PermissionDetail",
    "Reason",
    "SubscriptionState",
    "UserOrgRole",
    "__version__",
    "check_feature",
    "check_limit",
]
