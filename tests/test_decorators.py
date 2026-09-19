from __future__ import annotations

import asyncio
import inspect
import unittest
from unittest.mock import patch

from fastapi import Request

from auth_grpc_client import OrgEntitlements, SubscriptionState
from auth_grpc_client import decorators


def _snapshot() -> OrgEntitlements:
    return OrgEntitlements(
        org_id="org-1",
        entitled=True,
        state=SubscriptionState.ACTIVE,
        provider_status="",
        managed=True,
        enforced=True,
        trial_ends_at=None,
        current_period_start=None,
        current_period_end=None,
        ended_at=None,
        cancel_at_period_end=False,
        features=frozenset({"exports"}),
        licenses=0,
        licenses_used=0,
        licenses_available=0,
        over_limit=False,
        limits={},
        plans=(),
        resolved_at=None,
    )


class _FakeClient:
    def __init__(self, snapshot: OrgEntitlements) -> None:
        self.snapshot = snapshot

    def get_entitlements(
        self, org_id: str, *, user_token: str | None = None
    ) -> OrgEntitlements:
        return self.snapshot


class RequireEntitledTests(unittest.TestCase):
    def test_composed_guard_keeps_entitlements_in_injector_signature(self) -> None:
        injector_signatures: list[inspect.Signature] = []
        original = decorators.require_entitlement

        def recording_require_entitlement(*args, **kwargs):
            entitlement_decorator = original(*args, **kwargs)

            def record(fn):
                injector_signatures.append(inspect.signature(fn))
                return entitlement_decorator(fn)

            return record

        async def route(item_id: str) -> str:
            return item_id

        with patch.object(
            decorators, "require_entitlement", recording_require_entitlement
        ):
            decorated = decorators.require_entitled(org_id_value="org-1")(route)

        injector_param = injector_signatures[0].parameters["entitlements"]
        self.assertIs(injector_param.annotation, OrgEntitlements)
        self.assertIs(injector_param.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual(
            list(inspect.signature(decorated).parameters), ["item_id", "request"]
        )

    def test_injects_snapshot_when_route_does_not_declare_entitlements(self) -> None:
        async def route() -> str:
            return "called"

        decorated = decorators.require_entitled(org_id_value="org-1")(route)
        request = Request(
            {
                "type": "http",
                "headers": [(b"authorization", b"Bearer token")],
            }
        )

        with patch.object(decorators, "_client", _FakeClient(_snapshot())):
            result = asyncio.run(decorated(request=request))

        self.assertEqual(result, "called")

    def test_injects_snapshot_when_route_declares_entitlements(self) -> None:
        snapshot = _snapshot()

        async def route(entitlements: OrgEntitlements) -> OrgEntitlements:
            return entitlements

        decorated = decorators.require_entitled(org_id_value="org-1")(route)
        request = Request(
            {
                "type": "http",
                "headers": [(b"authorization", b"Bearer token")],
            }
        )

        with patch.object(decorators, "_client", _FakeClient(snapshot)):
            result = asyncio.run(decorated(request=request))

        self.assertIs(result, snapshot)
        self.assertNotIn("entitlements", inspect.signature(decorated).parameters)


if __name__ == "__main__":
    unittest.main()
