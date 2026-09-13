from __future__ import annotations

import unittest
from concurrent import futures
from datetime import datetime, timezone

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from auth_grpc_client import (
    DenialReason,
    EntitlementLimit,
    EntitlementsAuthError,
    EntitlementsClient,
    EntitlementsPermissionError,
    EntitlementsUnavailableError,
    LimitKind,
    OrgEntitlements,
    SubscriptionState,
)
from auth_grpc_client.generated import entitlements_pb2 as pb
from auth_grpc_client.generated import entitlements_pb2_grpc as pb_grpc
from auth_grpc_client.rules import check_feature, check_limit


class FakeEntitlements(pb_grpc.EntitlementsServicer):
    def __init__(self) -> None:
        self.metadata: list[tuple[str, ...]] = []
        self.get_calls = 0
        self.batch_sizes: list[int] = []
        self.unavailable = False
        self.status_code = None

    def GetEntitlements(self, request, context):
        self.metadata.append(context.invocation_metadata())
        self.get_calls += 1
        if self.status_code is not None:
            context.abort(self.status_code, "fake status")
        if self.unavailable:
            context.abort(grpc.StatusCode.UNAVAILABLE, "temporarily unavailable")
        resolved = Timestamp(seconds=1_700_000_000)
        return pb.OrgEntitlements(
            org_id=request.org_id,
            entitled=True,
            state=pb.SUBSCRIPTION_STATE_ACTIVE,
            managed=True,
            enforced=True,
            features=["exports"],
            resolved_at=resolved,
            limits={
                "skus": pb.EntitlementLimit(kind=pb.LIMIT_KIND_CAP, limit=3),
                "unlimited": pb.EntitlementLimit(unlimited=True),
            },
        )

    def BatchGetEntitlements(self, request, context):
        self.metadata.append(context.invocation_metadata())
        self.batch_sizes.append(len(request.org_ids))
        return pb.BatchGetEntitlementsResponse(
            entitlements={
                org_id: pb.OrgEntitlements(org_id=org_id) for org_id in request.org_ids
            }
        )


class EntitlementsClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        cls.fake = FakeEntitlements()
        pb_grpc.add_EntitlementsServicer_to_server(cls.fake, cls.server)
        cls.port = cls.server.add_insecure_port("127.0.0.1:0")
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop(None).wait()

    def setUp(self) -> None:
        self.fake.metadata.clear()
        self.fake.get_calls = 0
        self.fake.batch_sizes.clear()
        self.fake.status_code = None
        self.client = EntitlementsClient(
            f"127.0.0.1:{self.port}", service_key="service-key-for-tests", timeout=1
        )

    def tearDown(self) -> None:
        self.client.close()
        self.fake.unavailable = False

    def test_metadata_conversion_and_cache(self) -> None:
        snapshot = self.client.get("org-1")
        self.assertEqual(snapshot.state, SubscriptionState.ACTIVE)
        self.assertEqual(
            snapshot.resolved_at, datetime.fromtimestamp(1_700_000_000, timezone.utc)
        )
        self.assertIsNone(snapshot.trial_ends_at)
        self.assertEqual(snapshot.features, frozenset({"exports"}))
        self.assertTrue(snapshot.limits["unlimited"].unlimited)
        self.assertNotIn("missing", snapshot.limits)
        self.assertEqual(self.client.get("org-1"), snapshot)
        self.assertEqual(self.fake.get_calls, 1)
        self.assertIn(
            ("x-service-key", "service-key-for-tests"), self.fake.metadata[-1]
        )

        user_snapshot = self.client.get("org-2", user_token="user-jwt")
        self.assertEqual(user_snapshot.org_id, "org-2")
        self.assertIn(("authorization", "user-jwt"), self.fake.metadata[-1])
        self.assertNotIn(
            ("x-service-key", "service-key-for-tests"), self.fake.metadata[-1]
        )
        self.client.get("org-2", user_token="user-jwt")
        self.assertEqual(self.fake.get_calls, 3)

    def test_rules_limit_table(self) -> None:
        cases = [
            (False, False, True, None, 10**9, 1, True, None),
            (True, True, False, 100, 0, 1, False, DenialReason.NOT_ENTITLED),
            (True, True, True, None, 0, 1, False, DenialReason.LIMIT_NOT_IN_PLAN),
            (True, True, True, "unlimited", 10**9, 1, True, None),
            (True, True, True, 100, 99, 1, True, None),
            (True, True, True, 100, 100, 1, False, DenialReason.LIMIT_EXCEEDED),
            (True, True, True, 100, 150, 0, False, DenialReason.LIMIT_EXCEEDED),
            (True, True, True, 100, -5, 100, True, None),
            (True, False, True, 100, 100, 1, True, DenialReason.LIMIT_EXCEEDED),
        ]
        for (
            managed,
            enforced,
            entitled,
            limit_value,
            used,
            requested,
            allowed,
            reason,
        ) in cases:
            limit = {}
            if limit_value == "unlimited":
                limit["items"] = pb.EntitlementLimit(unlimited=True)
            elif isinstance(limit_value, int):
                limit["items"] = pb.EntitlementLimit(limit=limit_value)
            snapshot = self._snapshot(managed, enforced, entitled, limit)
            decision = check_limit(snapshot, "items", used, requested)
            self.assertEqual((decision.allowed, decision.reason), (allowed, reason))

    def test_rules_feature_table_and_observe_logging(self) -> None:
        cases = [
            (False, False, True, (), True, None),
            (True, True, False, ("reports",), False, DenialReason.NOT_ENTITLED),
            (True, True, True, ("cloud",), False, DenialReason.FEATURE_NOT_IN_PLAN),
            (True, True, True, ("reports",), True, None),
            (True, False, True, ("cloud",), True, DenialReason.FEATURE_NOT_IN_PLAN),
        ]
        for managed, enforced, entitled, features, allowed, reason in cases:
            snapshot = self._snapshot(managed, enforced, entitled, features=features)
            decision = check_feature(snapshot, "reports")
            self.assertEqual((decision.allowed, decision.reason), (allowed, reason))

        snapshot = self._snapshot(True, False, True, features=())
        with self.assertLogs("auth_grpc_client.rules", level="INFO") as logs:
            decision = check_feature(snapshot, "reports")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, DenialReason.FEATURE_NOT_IN_PLAN)
        self.assertIn("FEATURE_NOT_IN_PLAN", logs.output[0])

    @staticmethod
    def _snapshot(managed, enforced, entitled, limits=None, features=()):
        return OrgEntitlements(
            org_id="org-1",
            entitled=entitled,
            state=SubscriptionState.ACTIVE,
            provider_status="",
            managed=managed,
            enforced=enforced,
            trial_ends_at=None,
            current_period_start=None,
            current_period_end=None,
            ended_at=None,
            cancel_at_period_end=False,
            features=frozenset(features),
            licenses=0,
            licenses_used=0,
            licenses_available=0,
            over_limit=False,
            limits={
                key: EntitlementLimit(
                    kind=LimitKind.CAP,
                    limit=value.limit,
                    unlimited=value.unlimited,
                    period_start=None,
                    period_end=None,
                )
                for key, value in (limits or {}).items()
            },
            plans=(),
            resolved_at=None,
        )

    def test_batch_chunks_and_status_mapping(self) -> None:
        result = self.client.get_many([f"org-{index}" for index in range(250)])
        self.assertEqual(len(result), 250)
        self.assertEqual(self.fake.batch_sizes[-3:], [100, 100, 50])

        no_key = EntitlementsClient(f"127.0.0.1:{self.port}", timeout=1)
        try:
            with self.assertRaises(EntitlementsAuthError):
                no_key.get_many(["org-1"])
        finally:
            no_key.close()

    def test_stale_fallback_and_expiry(self) -> None:
        client = EntitlementsClient(
            f"127.0.0.1:{self.port}",
            service_key="service-key-for-tests",
            timeout=1,
            cache_ttl=0,
            stale_limit=0.2,
        )
        try:
            snapshot = client.get("org-stale")
            self.fake.unavailable = True
            self.assertEqual(client.get("org-stale"), snapshot)
            entry = client._cache["org-stale"]
            client._cache["org-stale"] = type(entry)(
                entry.snapshot, entry.cached_at - 1
            )
            with self.assertRaises(EntitlementsUnavailableError) as raised:
                client.get("org-stale")
            self.assertNotIn("service-key-for-tests", str(raised.exception))
        finally:
            client.close()

    def test_status_mapping_redacts_service_key(self) -> None:
        cases = (
            (grpc.StatusCode.UNAUTHENTICATED, EntitlementsAuthError),
            (grpc.StatusCode.PERMISSION_DENIED, EntitlementsPermissionError),
            (grpc.StatusCode.INTERNAL, EntitlementsUnavailableError),
            (grpc.StatusCode.UNAVAILABLE, EntitlementsUnavailableError),
            (grpc.StatusCode.DEADLINE_EXCEEDED, EntitlementsUnavailableError),
        )
        for status, error_type in cases:
            self.fake.status_code = status
            with self.assertRaises(error_type) as raised:
                self.client.get("org-1")
            self.assertNotIn("service-key-for-tests", str(raised.exception))
            self.fake.status_code = None


if __name__ == "__main__":
    unittest.main()
