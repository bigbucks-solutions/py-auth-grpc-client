"""Typed client for the entitlements.v1 Entitlements service."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Optional, Sequence

import grpc

from .generated import entitlements_pb2 as pb
from .generated.entitlements_pb2_grpc import EntitlementsStub


class SubscriptionState(IntEnum):
    UNSPECIFIED = 0
    NOT_MANAGED = 1
    NONE = 2
    TRIALING = 3
    ACTIVE = 4
    PAST_DUE = 5
    CANCELED = 6
    EXPIRED = 7


class LimitKind(IntEnum):
    UNSPECIFIED = 0
    CAP = 1
    MONTHLY_QUOTA = 2


class DenialReason(IntEnum):
    UNSPECIFIED = 0
    NOT_ENTITLED = 1
    FEATURE_NOT_IN_PLAN = 2
    LIMIT_NOT_IN_PLAN = 3
    LIMIT_EXCEEDED = 4


class EntitlementsError(Exception):
    """Base exception for entitlement client failures."""


class EntitlementsAuthError(EntitlementsError):
    pass


class EntitlementsPermissionError(EntitlementsError):
    pass


class EntitlementsUnavailableError(EntitlementsError):
    pass


@dataclass(frozen=True)
class EntitlementLimit:
    kind: LimitKind
    limit: int
    unlimited: bool
    period_start: Optional[datetime]
    period_end: Optional[datetime]


@dataclass(frozen=True)
class EntitlementPlan:
    price_id: str
    name: str
    tier: str
    quantity: int
    licenses: int
    provider_status: str
    cancel_at_period_end: bool
    current_period_end: Optional[datetime]


@dataclass(frozen=True)
class OrgEntitlements:
    org_id: str
    entitled: bool
    state: SubscriptionState
    provider_status: str
    managed: bool
    enforced: bool
    trial_ends_at: Optional[datetime]
    current_period_start: Optional[datetime]
    current_period_end: Optional[datetime]
    ended_at: Optional[datetime]
    cancel_at_period_end: bool
    features: tuple[str, ...]
    licenses: int
    licenses_used: int
    licenses_available: int
    over_limit: bool
    limits: dict[str, EntitlementLimit]
    plans: tuple[EntitlementPlan, ...]
    resolved_at: Optional[datetime]

    def check_feature(self, feature: str):
        """Evaluate a feature locally without making an RPC."""
        from .rules import check_feature

        return check_feature(self, feature)

    def check_limit(self, key: str, used: int, requested: int = 1):
        """Evaluate a cap or quota locally without making an RPC."""
        from .rules import check_limit

        return check_limit(self, key, used, requested)


@dataclass(frozen=True)
class _CacheEntry:
    snapshot: OrgEntitlements
    cached_at: float


def _enum(enum_type: type[IntEnum], value: int) -> IntEnum:
    try:
        return enum_type(value)
    except ValueError:
        return enum_type(0)


def _timestamp(message: Any, field_name: str) -> Optional[datetime]:
    if not message.HasField(field_name):
        return None
    return getattr(message, field_name).ToDatetime(tzinfo=timezone.utc)


def _limit(value: pb.EntitlementLimit) -> EntitlementLimit:
    return EntitlementLimit(
        kind=_enum(LimitKind, value.kind),
        limit=value.limit,
        unlimited=value.unlimited,
        period_start=_timestamp(value, "period_start"),
        period_end=_timestamp(value, "period_end"),
    )


def _plan(value: pb.EntitlementPlan) -> EntitlementPlan:
    return EntitlementPlan(
        price_id=value.price_id,
        name=value.name,
        tier=value.tier,
        quantity=value.quantity,
        licenses=value.licenses,
        provider_status=value.provider_status,
        cancel_at_period_end=value.cancel_at_period_end,
        current_period_end=_timestamp(value, "current_period_end"),
    )


def _snapshot(value: pb.OrgEntitlements) -> OrgEntitlements:
    return OrgEntitlements(
        org_id=value.org_id,
        entitled=value.entitled,
        state=_enum(SubscriptionState, value.state),
        provider_status=value.provider_status,
        managed=value.managed,
        enforced=value.enforced,
        trial_ends_at=_timestamp(value, "trial_ends_at"),
        current_period_start=_timestamp(value, "current_period_start"),
        current_period_end=_timestamp(value, "current_period_end"),
        ended_at=_timestamp(value, "ended_at"),
        cancel_at_period_end=value.cancel_at_period_end,
        features=frozenset(value.features),
        licenses=value.licenses,
        licenses_used=value.licenses_used,
        licenses_available=value.licenses_available,
        over_limit=value.over_limit,
        limits={key: _limit(item) for key, item in value.limits.items()},
        plans=tuple(_plan(item) for item in value.plans),
        resolved_at=_timestamp(value, "resolved_at"),
    )


class EntitlementsClient:
    """Synchronous client for entitlement snapshots and plan decisions.

    The client only retrieves read-only snapshots. The calling service owns
    usage counting and applies the pure rules in ``auth_grpc_client.rules``.
    """

    def __init__(
        self,
        address: str,
        service_key: Optional[str] = None,
        *,
        secure: bool = False,
        timeout: float = 0.5,
        cache_ttl: float = 45.0,
        stale_limit: float = 300.0,
        credentials: Optional[grpc.ChannelCredentials] = None,
        channel: Optional[grpc.Channel] = None,
        options: Optional[Sequence[tuple[str, str]]] = None,
    ) -> None:
        self._address = address
        self._service_key = (
            service_key if service_key is not None else os.getenv("AUTH_SERVICE_KEY")
        )
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._stale_limit = stale_limit
        self._owns_channel = channel is None
        if channel is None:
            if secure:
                channel = grpc.secure_channel(
                    address,
                    credentials or grpc.ssl_channel_credentials(),
                    options=options,
                )
            else:
                channel = grpc.insecure_channel(address, options=options)
        self._channel = channel
        self._stub = EntitlementsStub(channel)
        self._cache: dict[str, _CacheEntry] = {}
        self._cache_lock = threading.RLock()

    def __enter__(self) -> "EntitlementsClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.close()

    def close(self) -> None:
        if self._owns_channel:
            self._channel.close()

    def _metadata(self, user_token: Optional[str]) -> list[tuple[str, str]]:
        if user_token is not None:
            return [("authorization", user_token)]
        if self._service_key is not None:
            return [("x-service-key", self._service_key)]
        return []

    @staticmethod
    def _validate_org(org_id: str) -> None:
        if not org_id or not org_id.strip():
            raise ValueError("org_id must not be empty")

    def _error(self, rpc: str, org_id: str, error: grpc.RpcError) -> Exception:
        code = error.code()
        message = f"{rpc} failed for org_id={org_id} ({code.name})"
        if code == grpc.StatusCode.UNAUTHENTICATED:
            return EntitlementsAuthError(message)
        if code == grpc.StatusCode.PERMISSION_DENIED:
            return EntitlementsPermissionError(message)
        if code in (
            grpc.StatusCode.UNAVAILABLE,
            grpc.StatusCode.DEADLINE_EXCEEDED,
            grpc.StatusCode.INTERNAL,
        ):
            return EntitlementsUnavailableError(message)
        if code == grpc.StatusCode.INVALID_ARGUMENT:
            return ValueError(message)
        return EntitlementsError(message)

    def _rpc(self, rpc: str, org_id: str, call, *, user_token: Optional[str] = None):
        try:
            return call(metadata=self._metadata(user_token), timeout=self._timeout)
        except grpc.RpcError as error:
            raise self._error(rpc, org_id, error) from error

    def get(self, org_id: str, *, user_token: Optional[str] = None) -> OrgEntitlements:
        """Return a cached snapshot, with bounded stale fallback on outages."""
        self._validate_org(org_id)
        now = time.monotonic()
        if user_token is None:
            with self._cache_lock:
                entry = self._cache.get(org_id)
                if entry and now - entry.cached_at <= self._cache_ttl:
                    return entry.snapshot
        try:
            response = self._rpc(
                "GetEntitlements",
                org_id,
                lambda **kwargs: self._stub.GetEntitlements(
                    pb.GetEntitlementsRequest(org_id=org_id), **kwargs
                ),
                user_token=user_token,
            )
        except EntitlementsUnavailableError:
            if user_token is not None:
                raise
            with self._cache_lock:
                entry = self._cache.get(org_id)
            if entry and now - entry.cached_at <= self._stale_limit:
                return entry.snapshot
            raise
        snapshot = _snapshot(response)
        if user_token is None:
            with self._cache_lock:
                self._cache[org_id] = _CacheEntry(snapshot, time.monotonic())
        return snapshot

    def get_many(self, org_ids: Sequence[str]) -> dict[str, OrgEntitlements]:
        """Fetch service-key snapshots in chunks of at most 100 IDs."""
        if self._service_key is None:
            raise EntitlementsAuthError(
                "BatchGetEntitlements requires a configured service key"
            )
        if not org_ids:
            raise ValueError("org_ids must not be empty")
        if any(not org_id or not org_id.strip() for org_id in org_ids):
            raise ValueError("org_ids must not contain empty IDs")
        org_ids = list(dict.fromkeys(org_ids))
        result: dict[str, OrgEntitlements] = {}
        for start in range(0, len(org_ids), 100):
            chunk = list(org_ids[start : start + 100])
            try:
                response = self._stub.BatchGetEntitlements(
                    pb.BatchGetEntitlementsRequest(org_ids=chunk),
                    metadata=self._metadata(None),
                    timeout=self._timeout,
                )
            except grpc.RpcError as error:
                raise self._error("BatchGetEntitlements", "<batch>", error) from error
            for org_id, value in response.entitlements.items():
                snapshot = _snapshot(value)
                result[org_id] = snapshot
                with self._cache_lock:
                    self._cache[org_id] = _CacheEntry(snapshot, time.monotonic())
        return result

    def invalidate(self, org_id: str) -> None:
        self._validate_org(org_id)
        with self._cache_lock:
            self._cache.pop(org_id, None)
