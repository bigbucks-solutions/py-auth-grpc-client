# py-auth-grpc-client

Python gRPC client library for the **Auth** service. Provides `authenticate` and `authorize` RPCs to validate JWTs and check permissions. It also provides `EntitlementsClient` for subscription features and limits.

## Installation

```bash
pip install bigbucks-auth-grpc-client

# With FastAPI decorator support
pip install 'bigbucks-auth-grpc-client[fastapi]'
```

## Regenerate gRPC stubs

```bash
chmod +x generate_stubs.sh
./generate_stubs.sh
```

## Usage

### Standalone client

```python
from auth_grpc_client import AuthGrpcClient

with AuthGrpcClient("localhost:50051") as client:
    auth = client.authenticate(token="your-jwt-token")
    print(auth.user_id, auth.username, auth.roles)

    authz = client.authorize(
        token="your-jwt-token",
        resource="documents",
        scope="org",
        action="read",
        org_id="org-123",
    )
    print(authz.result)  # True / False
```

### FastAPI decorators

Protect your FastAPI routes with `@require_auth` and `@require_authorization` decorators.
Configure the gRPC client once at startup — no need to pass it to each decorator.

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from auth_grpc_client import AuthenticateResult, AuthorizeResult
from auth_grpc_client.decorators import configure_auth, close_auth, require_auth, require_authorization


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_auth("localhost:50051")
    yield
    close_auth()


app = FastAPI(lifespan=lifespan)


# auth is injected only if you declare it
@app.get("/me")
@require_auth
async def get_me(auth: AuthenticateResult):
    return {"user_id": auth.user_id, "username": auth.username}


# pure guard — no auth/authz params needed
@app.get("/ping")
@require_auth
async def ping():
    return {"ok": True}


# authorization with optional auth/authz injection
@app.get("/orgs/{org_id}/documents")
@require_authorization(resource="documents", scope="org", action="read")
async def list_documents(org_id: str, auth: AuthenticateResult):
    return {"org_id": org_id, "user": auth.user_id}
```

> **Note:** You do **not** need to declare `request: Request` — the decorator handles it automatically. The `auth` and `authz` parameters are only injected if your handler declares them.

### Secure (TLS) connection

```python
client = AuthGrpcClient("auth.example.com:443", secure=True)
```

### Entitlements

Use a service key for backend-to-backend calls. The key is read from
`AUTH_SERVICE_KEY` when `service_key` is omitted and is never included in
client errors.

```python
from auth_grpc_client import EntitlementsClient

with EntitlementsClient("127.0.0.1:8080", timeout=0.5) as client:
    snapshot = client.get("org-123")

    # The service counts its own records; rules evaluate the plan locally.
    from auth_grpc_client import check_limit
    decision = check_limit(snapshot, "skus", used=stored_skus)
    if not decision.allowed:
        raise RuntimeError("SKU cap exceeded")

    # Monthly quotas use the server-provided window.
    quota = snapshot.limits.get("invoices")
    if quota and quota.period_start and quota.period_end:
        used = count_invoices("org-123", quota.period_start, quota.period_end)
        decision = check_limit(snapshot, "invoices", used=used)
        if not decision.allowed:
            raise RuntimeError("Monthly invoice quota exceeded")
```

    The auth service only returns entitlement snapshots. It does not count the
    calling service's records and does not make limit decisions. Use
    `check_feature(snapshot, feature)` and `check_limit(snapshot, key, used,
    requested=1)` from `auth_grpc_client.rules` (or the package exports) for pure
    local decisions. Negative usage values are treated as zero. In observe mode,
    denials are logged and returned with `allowed=True` and the denial reason.

    ### FastAPI entitlement injection

    Configure `AuthGrpcClient` once during application startup. It creates the Auth
    and Entitlements stubs on the same gRPC channel. The `require_entitlement`
    decorator reads the request JWT, resolves `org_id`, fetches one cached
    snapshot, and injects it as `entitlements`.

    ```python
    from auth_grpc_client import AuthenticateResult, OrgEntitlements
    from auth_grpc_client.decorators import (
        configure_auth,
        require_auth,
        require_authorization,
        require_entitlement,
    )

    configure_auth("127.0.0.1:8080")

    @app.post("/orgs/{org_id}/invoices")
    @require_auth
    @require_authorization(resource="invoices", scope="org", action="create")
    @require_entitlement
    async def create_invoice(
        org_id: str,
        auth: AuthenticateResult,
        entitlements: OrgEntitlements,
    ):
        limit = entitlements.limits.get("invoices")
        used = count_invoices(org_id, limit.period_start, limit.period_end)
        decision = entitlements.check_limit("invoices", used=used)
        if not decision.allowed:
            raise RuntimeError(decision.reason)
        return {"ok": True}
    ```

    `require_entitlement` performs no authentication or authorization check by
    itself. Stack it with `require_auth` and `require_authorization` when those
    checks are required. The snapshot methods `check_feature` and `check_limit`
    perform no additional gRPC calls.

### Custom credentials

```python
import grpc

creds = grpc.ssl_channel_credentials(
    root_certificates=open("ca.pem", "rb").read(),
)
client = AuthGrpcClient("auth.example.com:443", secure=True, credentials=creds)
```
