"""High-level Python gRPC client for the Auth service."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Sequence

import grpc

from .generated.auth_pb2 import (
    AuthenticateRequest,
    AuthenticateResponse,
    AuthorizeRequest,
    AuthorizeResponse,
    PermissionDetail as PermissionDetailProto,  # noqa: F401
)
from .generated.auth_pb2_grpc import AuthStub
from .entitlements import EntitlementsClient, OrgEntitlements

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class UserOrgRole:
    """Represents a user's role within an organization."""

    role: str
    org_id: str


@dataclass(frozen=True)
class AuthenticateResult:
    """Result of an Authenticate RPC call."""

    user_id: str
    username: str
    roles: list[UserOrgRole] = field(default_factory=list)


@dataclass(frozen=True)
class PermissionDetail:
    """Details of the permitted permission."""

    resource: str
    scope: str
    action: str


@dataclass(frozen=True)
class AuthorizeResult:
    """Result of an Authorize RPC call."""

    result: bool
    permitted: Optional[PermissionDetail] = None


class AuthGrpcClient:
    """gRPC client for the Auth service.

    Provides ``authenticate`` and ``authorize`` methods that communicate with
    a remote Auth gRPC server.  The JWT token is sent via the ``authorization``
    gRPC metadata header.

    Usage::

        client = AuthGrpcClient("localhost:50051")
        auth_result = client.authenticate(token="my-jwt-token")
        print(auth_result.user_id, auth_result.username)

        authz = client.authorize(
            token="my-jwt-token",
            resource="documents",
            scope="org",
            action="read",
            org_id="org-123",
        )
        print(authz.result)

        # Don't forget to close when done
        client.close()

    Or use as a context-manager::

        with AuthGrpcClient("localhost:50051") as client:
            result = client.authenticate(token="my-jwt-token")
    """

    def __init__(
        self,
        target: str,
        *,
        service_key: Optional[str] = None,
        secure: bool = False,
        timeout: float = 0.5,
        cache_ttl: float = 45.0,
        stale_limit: float = 300.0,
        credentials: Optional[grpc.ChannelCredentials] = None,
        options: Optional[Sequence[tuple[str, str]]] = None,
    ) -> None:
        """Create a new AuthGrpcClient.

        Args:
            target: The ``host:port`` of the Auth gRPC server.
            secure: If ``True``, create a secure channel (TLS).
            credentials: Optional channel credentials for secure connections.
                         If *secure* is ``True`` and no credentials are given,
                         default SSL credentials are used.
            options: Optional gRPC channel options.
        """
        self._target = target
        if secure:
            creds = credentials or grpc.ssl_channel_credentials()
            self._channel = grpc.secure_channel(target, creds, options=options)
        else:
            self._channel = grpc.insecure_channel(target, options=options)
        self._stub = AuthStub(self._channel)
        self._entitlements = EntitlementsClient(
            target,
            service_key=service_key,
            timeout=timeout,
            cache_ttl=cache_ttl,
            stale_limit=stale_limit,
            channel=self._channel,
        )
        logger.debug("AuthGrpcClient connected to %s (secure=%s)", target, secure)

    # -- Context-manager support -----------------------------------------------

    def __enter__(self) -> "AuthGrpcClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.close()

    # -- Public API ------------------------------------------------------------

    def authenticate(
        self,
        token: str,
        *,
        timeout: Optional[float] = None,
        metadata: Optional[Sequence[tuple[str, str]]] = None,
    ) -> AuthenticateResult:
        """Validate a JWT and return the authenticated user's information.

        The token is sent as the ``authorization`` metadata header.

        Args:
            token: The JWT token.
            timeout: Optional RPC deadline in seconds.
            metadata: Additional metadata key-value pairs.

        Returns:
            An ``AuthenticateResult`` with user details and roles.

        Raises:
            grpc.RpcError: If the RPC fails.
        """
        md = list(metadata) if metadata else []
        md.append(("authorization", f"{token}"))

        response: AuthenticateResponse = self._stub.Authenticate(
            AuthenticateRequest(),
            metadata=md,
            timeout=timeout,
        )

        roles = [UserOrgRole(role=r.role, org_id=r.org_id) for r in response.roles]
        return AuthenticateResult(
            user_id=response.user_id,
            username=response.username,
            roles=roles,
        )

    def authorize(
        self,
        token: str,
        *,
        resource: str,
        scope: str,
        action: str,
        org_id: str,
        timeout: Optional[float] = None,
        metadata: Optional[Sequence[tuple[str, str]]] = None,
    ) -> AuthorizeResult:
        """Check whether the authenticated user has a specific permission.

        The token is sent as the ``authorization`` metadata header.

        Args:
            token: The JWT token.
            resource: The resource to check access for.
            scope: The scope of the permission.
            action: The action to perform.
            org_id: The organization ID context.
            timeout: Optional RPC deadline in seconds.
            metadata: Additional metadata key-value pairs.

        Returns:
            An ``AuthorizeResult`` indicating whether access is allowed.

        Raises:
            grpc.RpcError: If the RPC fails.
        """
        md = list(metadata) if metadata else []
        md.append(("authorization", f"{token}"))

        response: AuthorizeResponse = self._stub.Authorize(
            AuthorizeRequest(
                resource=resource,
                scope=scope,
                action=action,
                org_id=org_id,
            ),
            metadata=md,
            timeout=timeout,
        )

        permitted = None
        if response.HasField("permitted"):
            p = response.permitted
            permitted = PermissionDetail(
                resource=p.resource,
                scope=p.scope,
                action=p.action,
            )

        return AuthorizeResult(result=response.result, permitted=permitted)

    def get_entitlements(
        self,
        org_id: str,
        *,
        user_token: Optional[str] = None,
    ) -> OrgEntitlements:
        """Return a cached entitlement snapshot using the shared channel."""
        return self._entitlements.get(org_id, user_token=user_token)

    def get_many_entitlements(self, org_ids: Sequence[str]) -> dict[str, OrgEntitlements]:
        """Fetch entitlement snapshots in service-key batches of 100."""
        return self._entitlements.get_many(org_ids)

    def invalidate_entitlements(self, org_id: str) -> None:
        """Remove one entitlement snapshot from the local cache."""
        self._entitlements.invalidate(org_id)

    def close(self) -> None:
        """Close the underlying gRPC channel."""
        self._channel.close()
        logger.debug("AuthGrpcClient channel to %s closed", self._target)
