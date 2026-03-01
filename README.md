# py-auth-grpc-client

Python gRPC client library for the **Auth** service. Provides `authenticate` and `authorize` RPCs to validate JWTs and check permissions.

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

### Custom credentials

```python
import grpc

creds = grpc.ssl_channel_credentials(
    root_certificates=open("ca.pem", "rb").read(),
)
client = AuthGrpcClient("auth.example.com:443", secure=True, credentials=creds)
```
