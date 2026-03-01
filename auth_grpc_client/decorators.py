"""FastAPI decorator-based authentication and authorization via the Auth gRPC service."""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional, Sequence

import grpc

from .client import AuthenticateResult, AuthGrpcClient, AuthorizeResult  # noqa: F401

try:
    from fastapi import Request
    from fastapi.responses import JSONResponse
except ImportError:
    raise ImportError(
        "FastAPI is required for the decorators module. "
        "Install it with: pip install 'bigbucks-auth-grpc-client[fastapi]'"
    )

# ---------------------------------------------------------------------------
# Module-level client singleton
# ---------------------------------------------------------------------------

_client: Optional[AuthGrpcClient] = None


def configure_auth(
    target: str,
    *,
    secure: bool = False,
    credentials: Optional[grpc.ChannelCredentials] = None,
    options: Optional[Sequence[tuple[str, str]]] = None,
) -> AuthGrpcClient:
    """Initialise the global ``AuthGrpcClient`` used by the decorators.

    Call this **once** at application startup (e.g. in a FastAPI *lifespan*
    or startup event)::

        from auth_grpc_client.decorators import configure_auth

        configure_auth("localhost:50051")

    Args:
        target: The ``host:port`` of the Auth gRPC server.
        secure: If ``True``, create a secure channel (TLS).
        credentials: Optional channel credentials for secure connections.
        options: Optional gRPC channel options.

    Returns:
        The ``AuthGrpcClient`` instance that was created.
    """
    global _client
    _client = AuthGrpcClient(
        target, secure=secure, credentials=credentials, options=options
    )
    return _client


def close_auth() -> None:
    """Close the global ``AuthGrpcClient``. Call on app shutdown."""
    global _client
    if _client is not None:
        _client.close()
        _client = None


def _get_client() -> AuthGrpcClient:
    if _client is None:
        raise RuntimeError(
            "Auth client not configured. Call configure_auth('host:port') at startup."
        )
    return _client


def _extract_token(request: Request) -> Optional[str]:
    """Extract the Bearer token from the Authorization header."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def require_auth(fn: Callable) -> Callable:
    """Decorator that authenticates the request via the Auth gRPC service.

    Extracts the JWT from the ``Authorization: Bearer <token>`` header, calls
    the gRPC ``Authenticate`` RPC, and optionally injects ``AuthenticateResult``
    into the handler if an ``auth`` parameter is declared.

    Returns a ``401`` JSON response if the token is missing or invalid.

    Requires ``configure_auth()`` to have been called at startup.

    Usage::

        from auth_grpc_client.decorators import configure_auth, require_auth

        configure_auth("localhost:50051")

        # auth is injected if you declare it
        @app.get("/me")
        @require_auth
        async def get_me(auth: AuthenticateResult):
            return {"user_id": auth.user_id, "username": auth.username}

        # or skip it if you just need the guard
        @app.get("/ping")
        @require_auth
        async def ping():
            return {"ok": True}
    """
    sig = inspect.signature(fn)
    wants_auth = "auth" in sig.parameters
    wants_request = any(
        p.annotation is Request or p.name == "request" for p in sig.parameters.values()
    )

    @functools.wraps(fn)
    async def wrapper(*args: Any, request: Request, **kwargs: Any) -> Any:
        client = _get_client()
        token = _extract_token(request)
        if not token:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"},
            )
        try:
            auth_result = client.authenticate(token=token)
        except Exception:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication failed"},
            )
        if wants_auth:
            kwargs["auth"] = auth_result
        if wants_request:
            kwargs["request"] = request
        return await _call(fn, *args, **kwargs)

    wrapper.__signature__ = _build_signature(fn, drop={"auth"}, add_request=True)
    return wrapper


def require_authorization(
    *,
    resource: str,
    scope: str,
    action: str,
    org_id_param: Optional[str] = "org_id",
    org_id_value: Optional[str] = None,
) -> Callable:
    """Decorator that authenticates *and* authorizes the request.

    After a successful ``Authenticate`` call the decorator also calls the
    ``Authorize`` RPC.  The ``org_id`` is resolved in order:

    1. A literal value passed via *org_id_value*.
    2. A path / query parameter whose name matches *org_id_param* (default
       ``"org_id"``).

    Optionally injects ``auth`` (``AuthenticateResult``) and/or ``authz``
    (``AuthorizeResult``) into the handler if declared.  Returns ``401`` for
    authentication failures and ``403`` when authorization is denied.

    Requires ``configure_auth()`` to have been called at startup.

    Usage::

        @app.get("/orgs/{org_id}/documents")
        @require_authorization(resource="documents", scope="org", action="read")
        async def list_documents(org_id: str, auth: AuthenticateResult):
            ...

        # or without any injected params — pure guard
        @app.delete("/orgs/{org_id}/documents/{doc_id}")
        @require_authorization(resource="documents", scope="org", action="delete")
        async def delete_document(org_id: str, doc_id: str):
            ...

    Args:
        resource: The resource to check access for.
        scope: The scope of the permission.
        action: The action to perform.
        org_id_param: Name of the path/query parameter that carries the org ID.
        org_id_value: A fixed org ID value (takes precedence over the param).
    """

    def decorator(fn: Callable) -> Callable:
        sig = inspect.signature(fn)
        wants_auth = "auth" in sig.parameters
        wants_authz = "authz" in sig.parameters
        wants_request = any(
            p.annotation is Request or p.name == "request"
            for p in sig.parameters.values()
        )

        @functools.wraps(fn)
        async def wrapper(*args: Any, request: Request, **kwargs: Any) -> Any:
            client = _get_client()
            token = _extract_token(request)
            if not token:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing or invalid Authorization header"},
                )

            # --- Authenticate ---
            try:
                auth_result = client.authenticate(token=token)
            except Exception:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication failed"},
                )

            # --- Resolve org_id ---
            resolved_org_id = org_id_value
            if resolved_org_id is None and org_id_param:
                resolved_org_id = (
                    kwargs.get(org_id_param)
                    or request.path_params.get(org_id_param)
                    or request.query_params.get(org_id_param, "")
                )

            # --- Authorize ---
            try:
                authz_result = client.authorize(
                    token=token,
                    resource=resource,
                    scope=scope,
                    action=action,
                    org_id=resolved_org_id or "",
                )
            except Exception:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Authorization check failed"},
                )

            if not authz_result.result:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Forbidden"},
                )

            if wants_auth:
                kwargs["auth"] = auth_result
            if wants_authz:
                kwargs["authz"] = authz_result
            if wants_request:
                kwargs["request"] = request
            return await _call(fn, *args, **kwargs)

        wrapper.__signature__ = _build_signature(
            fn, drop={"auth", "authz"}, add_request=True
        )
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_signature(
    fn: Callable,
    *,
    drop: set[str],
    add_request: bool = False,
) -> inspect.Signature:
    """Build the signature FastAPI will inspect.

    - Removes params listed in *drop* (``auth``, ``authz``) so FastAPI
      doesn't try to resolve them as query params.
    - If *add_request* is ``True`` and the original function doesn't already
      have a ``request: Request`` parameter, one is appended so FastAPI
      injects the ``Request`` object automatically.
    """
    sig = inspect.signature(fn)
    has_request = any(
        p.annotation is Request or p.name == "request" for p in sig.parameters.values()
    )
    params = [p for p in sig.parameters.values() if p.name not in drop]

    if add_request and not has_request:
        params.append(
            inspect.Parameter(
                "request",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Request,
            )
        )

    return sig.replace(parameters=params)


async def _call(fn: Callable, *args: Any, **kwargs: Any) -> Any:
    """Call *fn*, awaiting it if it's a coroutine function."""
    if inspect.iscoroutinefunction(fn):
        return await fn(*args, **kwargs)
    return fn(*args, **kwargs)
