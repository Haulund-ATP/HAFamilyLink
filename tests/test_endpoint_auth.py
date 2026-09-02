"""Endpoint authentication tests for the auth service.

These are the tests that would have caught the original weaknesses: an open
``/api/cookies`` in standalone mode, an ``/api/cookies/check`` that was never
protected at all, and a token accepted from the query string.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app
from app.security import SESSION_COOKIE_NAME

TOKEN = "test-token-that-is-long-enough-1234"

#: Every endpoint that must refuse an unauthenticated caller.
PROTECTED_ENDPOINTS = [
    ("POST", "/api/auth/start"),
    ("GET", "/api/auth/status/abc123"),
    ("GET", "/api/cookies"),
    ("DELETE", "/api/cookies"),
    ("GET", "/api/cookies/check"),
]


def build_app(share_dir, **overrides):
    """Create an app instance against a temporary share directory."""
    config = Config(
        share_dir=str(share_dir),
        api_token=TOKEN,
        # No noVNC assets or display script on a test machine.
        novnc_root=str(share_dir / "novnc-absent"),
        display_stack_script=str(share_dir / "no-display-stack"),
        **overrides,
    )
    return create_app(config)


@pytest.fixture
def client(share_dir):
    """A TestClient that does not run the lifespan (no Playwright needed)."""
    return TestClient(build_app(share_dir))


class TestPublicSurface:
    def test_health_is_public(self, client):
        response = client.get("/api/health")

        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_health_is_not_cached(self, client):
        response = client.get("/api/health")

        assert "no-store" in response.headers["cache-control"]

    def test_index_is_reachable_and_shows_the_unlock_form(self, client):
        response = client.get("/")

        assert response.status_code == 200
        assert "api/session" in response.text
        # The unlock page must not contain the credential it asks for.
        assert TOKEN not in response.text

    def test_health_is_the_only_public_api(self, client):
        """Any /api path other than health and session must be closed."""
        for method, path in PROTECTED_ENDPOINTS:
            response = client.request(method, path)
            assert response.status_code in (401, 403), (method, path)


class TestProtectedSurface:
    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_missing_credentials_are_refused(self, client, method, path):
        response = client.request(method, path)

        assert response.status_code == 401

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_wrong_token_is_refused(self, client, method, path):
        response = client.request(method, path, headers={"X-API-Key": "wrong"})

        assert response.status_code == 403

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_correct_token_passes_the_gate(self, client, method, path):
        response = client.request(method, path, headers={"X-API-Key": TOKEN})

        # 503 is the browser manager being absent without a lifespan run; what
        # matters here is that the request was not rejected by the auth gate.
        assert response.status_code not in (401, 403)

    def test_empty_token_header_is_refused(self, client):
        response = client.get("/api/cookies", headers={"X-API-Key": ""})

        assert response.status_code == 403


class TestQueryStringCredentialsAreRefused:
    """A token in a URL leaks through history, proxy logs and Referer."""

    @pytest.mark.parametrize("param", ["api_key", "apikey", "api-key", "token"])
    def test_credential_in_query_string_is_rejected(self, client, param):
        response = client.get(f"/api/cookies?{param}={TOKEN}")

        assert response.status_code == 400
        assert "X-API-Key" in response.json()["detail"]

    def test_query_credential_is_rejected_even_when_correct(self, client):
        """The legacy ?api_key= form must not work, valid value or not."""
        response = client.get(f"/api/cookies?api_key={TOKEN}")

        assert response.status_code == 400

    def test_query_credential_is_rejected_on_public_paths_too(self, client):
        response = client.get(f"/?api_key={TOKEN}")

        assert response.status_code == 400


class TestSessionCookieFlow:
    def test_token_is_exchanged_for_an_httponly_cookie(self, client):
        response = client.post("/api/session", json={"token": TOKEN})

        assert response.status_code == 200
        cookie = response.headers["set-cookie"]
        assert SESSION_COOKIE_NAME in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie.replace("Strict", "strict")

    def test_session_cookie_authenticates_subsequent_requests(self, client):
        client.post("/api/session", json={"token": TOKEN})

        response = client.get("/api/cookies")

        assert response.status_code not in (401, 403)

    def test_index_renders_the_app_once_unlocked(self, client):
        client.post("/api/session", json={"token": TOKEN})

        response = client.get("/")

        assert "api/auth/start" in response.text
        assert TOKEN not in response.text

    def test_wrong_token_does_not_mint_a_session(self, client):
        response = client.post("/api/session", json={"token": "nope"})

        assert response.status_code == 403
        assert "set-cookie" not in response.headers

    def test_forged_cookie_is_refused(self, client):
        client.cookies.set(SESSION_COOKIE_NAME, "forged-session-value")

        response = client.get("/api/cookies")

        assert response.status_code == 401

    def test_session_can_be_revoked(self, client):
        client.post("/api/session", json={"token": TOKEN})
        assert client.get("/api/cookies").status_code not in (401, 403)

        client.delete("/api/session")

        assert client.get("/api/cookies").status_code == 401

    def test_unlock_attempts_are_rate_limited(self, client):
        for _ in range(10):
            client.post("/api/session", json={"token": "wrong"})

        response = client.post("/api/session", json={"token": "wrong"})

        assert response.status_code == 429
        assert int(response.headers["retry-after"]) > 0

    def test_rate_limit_also_covers_the_header_path(self, client):
        for _ in range(10):
            client.get("/api/cookies", headers={"X-API-Key": "wrong"})

        response = client.get("/api/cookies", headers={"X-API-Key": "wrong"})

        assert response.status_code == 429


class TestIngressTrust:
    """Ingress counts as authenticated only when the port is not published."""

    def test_ingress_header_is_trusted_when_enabled(self, share_dir):
        client = TestClient(build_app(share_dir, ingress_trusted=True))

        response = client.get(
            "/api/cookies", headers={"X-Ingress-Path": "/api/hassio_ingress/tok"}
        )

        assert response.status_code not in (401, 403)

    def test_ingress_header_is_ignored_when_the_port_is_published(self, client):
        """Otherwise anyone reaching the port could simply forge the header."""
        response = client.get(
            "/api/cookies", headers={"X-Ingress-Path": "/api/hassio_ingress/tok"}
        )

        assert response.status_code == 401

    def test_ingress_ui_builds_a_prefixed_novnc_link(self, share_dir):
        client = TestClient(build_app(share_dir, ingress_trusted=True))

        response = client.get(
            "/", headers={"X-Ingress-Path": "/api/hassio_ingress/tok"}
        )

        assert "/api/hassio_ingress/tok/vnc/vnc.html" in response.text
        assert "path=api/hassio_ingress/tok/vnc/websockify" in response.text


class TestSecurityHeaders:
    def test_responses_are_never_cached(self, client):
        client.post("/api/session", json={"token": TOKEN})

        for path in ("/", "/api/cookies", "/api/cookies/check"):
            headers = client.get(path).headers
            assert "no-store" in headers["cache-control"], path
            assert headers["pragma"] == "no-cache", path

    def test_hardening_headers_are_present(self, client):
        headers = client.get("/").headers

        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["x-frame-options"] == "SAMEORIGIN"
        assert "frame-ancestors 'self'" in headers["content-security-policy"]

    def test_inline_script_is_nonce_protected(self, client):
        response = client.get("/")

        csp = response.headers["content-security-policy"]
        assert "nonce-" in csp
        nonce = csp.split("nonce-", 1)[1].split("'", 1)[0]
        assert f'nonce="{nonce}"' in response.text

    def test_nonce_differs_per_response(self, client):
        first = client.get("/").headers["content-security-policy"]
        second = client.get("/").headers["content-security-policy"]

        assert first != second

    def test_no_cross_origin_access_is_granted(self, client):
        response = client.get(
            "/api/health", headers={"Origin": "http://evil.example"}
        )

        assert "access-control-allow-origin" not in response.headers


class TestFailClosedStartup:
    def test_app_refuses_to_build_without_a_usable_token(self, tmp_path):
        from app.security import TokenError

        blocker = tmp_path / "share"
        blocker.write_text("this is a file, not a directory")

        with pytest.raises(TokenError):
            create_app(Config(share_dir=str(blocker / "familylink")))

    def test_generated_token_is_used_when_none_is_configured(self, share_dir):
        app = create_app(
            Config(
                share_dir=str(share_dir),
                novnc_root=str(share_dir / "absent"),
                display_stack_script=str(share_dir / "absent"),
            )
        )
        generated = (share_dir / "api_key").read_text().strip()
        client = TestClient(app)

        assert client.get(
            "/api/cookies", headers={"X-API-Key": generated}
        ).status_code not in (401, 403)
        assert client.get(
            "/api/cookies", headers={"X-API-Key": "other"}
        ).status_code == 403
