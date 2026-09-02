"""Single enforcement point for authentication and security headers.

This is a pure ASGI middleware rather than a set of endpoint dependencies for
two reasons:

* it covers ``websocket`` scopes as well as ``http`` ones, so the noVNC
  framebuffer bridge is guarded by exactly the same check as the REST API, and
* nothing can be added to the app later and accidentally end up public - the
  public surface is an explicit allowlist, and everything else is closed.
"""
from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable
from urllib.parse import parse_qs

from app.security import SESSION_COOKIE_NAME, RateLimiter, SessionStore, tokens_equal

_LOGGER = logging.getLogger(__name__)

#: Query parameters that used to carry the API key. They are now refused
#: outright: a credential in a URL ends up in browser history, proxy logs and
#: ``Referer`` headers, and the whole point of the session cookie is to avoid
#: that.
_REJECTED_QUERY_PARAMS = ("api_key", "apikey", "api-key", "token")

#: Paths reachable without credentials.
#:
#: ``/`` renders either the unlock form or the UI depending on whether the
#: caller is authenticated, and ``POST /api/session`` is how a browser trades
#: the token for a session cookie, so both have to be reachable.
PUBLIC_PATHS: frozenset[str] = frozenset({"/api/health", "/", "/favicon.ico"})
PUBLIC_POST_PATHS: frozenset[str] = frozenset({"/api/session"})

_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    # Nothing this service serves may be cached: responses carry Google session
    # cookies, session state and the authentication UI.
    (b"cache-control", b"no-store, no-cache, must-revalidate, max-age=0"),
    (b"pragma", b"no-cache"),
    (b"expires", b"0"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    # Home Assistant ingress renders the add-on inside a same-origin iframe, so
    # framing must be allowed for the same origin but nothing else.
    (b"x-frame-options", b"SAMEORIGIN"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"permissions-policy", b"geolocation=(), camera=(), microphone=()"),
)

# The app's own pages carry a nonce for their single inline script, so no
# inline script source is allowed wholesale.
_APP_CSP = (
    b"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; "
    b"script-src 'strict-dynamic' 'nonce-{nonce}'; connect-src 'self'; "
    b"form-action 'none'; frame-ancestors 'self'; base-uri 'none'"
)

# noVNC is a third-party bundle with its own inline handlers and workers, so it
# gets a wider - but still same-origin - policy. Notably it may not reach any
# external host, and may not be framed by anything but Home Assistant itself.
_VNC_CSP = (
    b"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    b"style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
    b"connect-src 'self' ws: wss:; worker-src 'self' blob:; "
    b"frame-ancestors 'self'; base-uri 'none'"
)


@dataclass
class AuthOutcome:
    """Result of authenticating one request."""

    authenticated: bool
    status: int = 401
    detail: str = "Authentication required"
    retry_after: int = 0


class AuthGuard:
    """Decides whether a request carries valid credentials."""

    def __init__(
        self,
        token: str,
        sessions: SessionStore,
        rate_limiter: RateLimiter,
        ingress_trusted: bool = False,
    ) -> None:
        self._token = token
        self.sessions = sessions
        self.rate_limiter = rate_limiter
        self._ingress_trusted = ingress_trusted

    @property
    def ingress_trusted(self) -> bool:
        """Whether ingress requests count as an authenticated UI session."""
        return self._ingress_trusted

    def is_ingress(self, headers: dict[str, str]) -> bool:
        """Whether the request arrived through the Supervisor's ingress proxy.

        The Supervisor authenticates the Home Assistant user before proxying
        and sets ``X-Ingress-Path``. This is only honoured when the add-on
        started with ``INGRESS_TRUSTED=1``, which ``run.sh`` exports solely when
        the host port is *not* published - otherwise the header could simply be
        forged by anyone who can reach the port directly.
        """
        return self._ingress_trusted and "x-ingress-path" in headers

    def verify_token(self, candidate: str | None) -> bool:
        """Constant-time check of a presented token."""
        return tokens_equal(candidate, self._token)

    def authenticate(
        self,
        headers: dict[str, str],
        cookies: dict[str, str],
        client_key: str,
    ) -> AuthOutcome:
        """Authenticate a request from its headers and cookies."""
        if self.is_ingress(headers):
            return AuthOutcome(True)

        if self.sessions.is_valid(cookies.get(SESSION_COOKIE_NAME)):
            return AuthOutcome(True)

        presented = headers.get("x-api-key")
        if presented is not None:
            decision = self.rate_limiter.check(client_key)
            if not decision.allowed:
                return AuthOutcome(
                    False,
                    status=429,
                    detail="Too many authentication attempts",
                    retry_after=decision.retry_after,
                )
            if self.verify_token(presented):
                self.rate_limiter.reset(client_key)
                return AuthOutcome(True)
            self.rate_limiter.record_failure(client_key)
            # Deliberately never logs the presented value.
            _LOGGER.warning(
                "Rejected a request with an invalid X-API-Key from %s", client_key
            )
            return AuthOutcome(False, status=403, detail="Invalid API token")

        return AuthOutcome(
            False,
            status=401,
            detail=(
                "Authentication required: send the service token in the "
                "X-API-Key header"
            ),
        )


def _parse_cookies(raw: str) -> dict[str, str]:
    """Parse a Cookie header without pulling in http.cookies' quirks."""
    jar: dict[str, str] = {}
    for part in raw.split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            jar[name] = value
    return jar


def _client_key(scope: dict) -> str:
    """Rate-limiting key for a connection: its peer address."""
    client = scope.get("client")
    if client and client[0]:
        return str(client[0])
    return "unknown"


class SecurityMiddleware:
    """Enforces authentication and attaches security headers."""

    def __init__(
        self,
        app: Callable,
        guard: AuthGuard,
        public_paths: Iterable[str] = PUBLIC_PATHS,
        public_post_paths: Iterable[str] = PUBLIC_POST_PATHS,
    ) -> None:
        self.app = app
        self.guard = guard
        self._public_paths = frozenset(public_paths)
        self._public_post_paths = frozenset(public_post_paths)

    def _is_public(self, scope: dict) -> bool:
        path = scope.get("path", "")
        if scope.get("method") == "POST" and path in self._public_post_paths:
            return True
        return path in self._public_paths

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        cookies = _parse_cookies(headers.get("cookie", ""))
        client_key = _client_key(scope)

        # A credential in the query string is refused rather than honoured, so
        # a legacy `?api_key=` configuration fails loudly instead of quietly
        # leaking the token into logs and history.
        query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
        offending = [name for name in _REJECTED_QUERY_PARAMS if name in query]
        if offending:
            _LOGGER.warning(
                "Refused a request carrying a credential in the query string "
                "(%s) from %s; use the X-API-Key header instead",
                ", ".join(offending),
                client_key,
            )
            await self._reject(
                scope,
                send,
                400,
                "API tokens must not be passed in the URL. Send the token in "
                "the X-API-Key header, or unlock the web UI once via "
                "POST /api/session.",
            )
            return

        state = scope.setdefault("state", {})
        state["csp_nonce"] = secrets.token_urlsafe(16)
        outcome = self.guard.authenticate(headers, cookies, client_key)
        state["authenticated"] = outcome.authenticated
        state["ingress_path"] = headers.get("x-ingress-path", "")

        if not outcome.authenticated and not self._is_public(scope):
            await self._reject(
                scope, send, outcome.status, outcome.detail, outcome.retry_after
            )
            return

        await self.app(scope, receive, self._wrap_send(scope, send))

    def _wrap_send(self, scope: dict, send: Callable) -> Callable[[dict], Awaitable]:
        """Attach the security headers to every HTTP response."""
        if scope["type"] != "http":
            return send

        path = scope.get("path", "")

        async def wrapped(message: dict) -> None:
            if message["type"] == "http.response.start":
                existing = {key.lower() for key, _ in message.get("headers", [])}
                headers = list(message.get("headers", []))
                for key, value in _SECURITY_HEADERS:
                    if key not in existing:
                        headers.append((key, value))
                if b"content-security-policy" not in existing:
                    headers.append((b"content-security-policy", self._csp(path, scope)))
                message = {**message, "headers": headers}
            await send(message)

        return wrapped

    @staticmethod
    def _csp(path: str, scope: dict) -> bytes:
        """Pick the content security policy for a response."""
        if path.startswith("/vnc"):
            return _VNC_CSP
        nonce = (scope.get("state") or {}).get("csp_nonce", "")
        return _APP_CSP.replace(b"{nonce}", nonce.encode("latin-1"))

    async def _reject(
        self,
        scope: dict,
        send: Callable,
        status: int,
        detail: str,
        retry_after: int = 0,
    ) -> None:
        """Close the connection with an error, for HTTP and WebSocket alike."""
        if scope["type"] == "websocket":
            # 1008 = policy violation. A browser cannot attach an X-API-Key
            # header to a handshake, so an unauthenticated framebuffer request
            # means the UI session cookie is missing or expired.
            await send({"type": "websocket.close", "code": 1008})
            return

        body = json.dumps({"detail": detail}).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("latin-1")),
            *_SECURITY_HEADERS,
        ]
        if retry_after:
            headers.append((b"retry-after", str(retry_after).encode("latin-1")))
        await send(
            {"type": "http.response.start", "status": status, "headers": headers}
        )
        await send({"type": "http.response.body", "body": body})
