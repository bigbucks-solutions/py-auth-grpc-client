"""Python gRPC client for the Auth service."""

from .client import (
    AuthenticateResult,
    AuthGrpcClient,
    AuthorizeResult,
    PermissionDetail,
    UserOrgRole,
)

__version__ = "0.2.0"

__all__ = [
    "AuthGrpcClient",
    "AuthenticateResult",
    "AuthorizeResult",
    "PermissionDetail",
    "UserOrgRole",
    "__version__",
]
