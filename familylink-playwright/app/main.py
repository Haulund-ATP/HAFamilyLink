"""Main FastAPI application for Family Link Auth."""
from __future__ import annotations

import html
import json
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import redaction
from app.auth.browser import BrowserAuthManager
from app.config import Config, get_config
from app.display import DisplayStack
from app.middleware import AuthGuard, SecurityMiddleware
from app.security import (
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    RateLimiter,
    SessionStore,
    load_or_create_api_token,
)
from app.storage.file_storage import (
    CookiesCorrupted,
    CookiesExpired,
    SharedStorage,
)
from app.translations import get_translations
from app.vnc_proxy import SingleObserverGuard, relay

SERVICE_VERSION = "2.0.0"

_LOGGER = logging.getLogger(__name__)


class SessionRequest(BaseModel):
    """Body of ``POST /api/session``."""

    token: str = Field(min_length=1, max_length=512)


def _configure_logging(config: Config) -> None:
    """Configure logging and install the redaction filter before anything logs."""
    logging.basicConfig(
        level=config.log_level.upper(),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
        force=True,
    )
    redaction.install()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Start and stop the browser automation around the served lifetime.

    Starlette 1.x removed ``@app.on_event``, so startup and shutdown live in
    one lifespan handler.
    """
    config: Config = app.state.config
    _LOGGER.info("Starting Family Link Auth Service v%s", SERVICE_VERSION)
    _LOGGER.info(
        "Configuration: log_level=%s, auth_timeout=%ss, session_duration=%ss, "
        "cookie_allowlist_mode=%s, addon_mode=%s, ingress_trusted=%s",
        config.log_level,
        config.auth_timeout,
        config.session_duration,
        config.cookie_allowlist_mode,
        config.addon_mode,
        config.ingress_trusted,
    )
    if config.cookie_allowlist_mode == "legacy":
        _LOGGER.warning(
            "cookie_allowlist_mode=legacy: every google.com cookie will be "
            "persisted, not just the ones Family Link needs. Use this only if "
            "strict mode fails on your Google region, and switch back afterwards."
        )
    if not config.addon_mode and not config.api_token:
        _LOGGER.info(
            "Standalone mode: the web UI is unlocked once with the token in "
            "%s/api_key, and the Home Assistant integration sends it as the "
            "X-API-Key header.",
            config.share_dir,
        )

    try:
        app.state.browser_manager = BrowserAuthManager(
            auth_timeout=config.auth_timeout,
            language=config.language,
            timezone=config.timezone,
            storage=app.state.storage,
            display_stack=app.state.display,
            allowlist_mode=config.cookie_allowlist_mode,
        )
        await app.state.browser_manager.initialize()
        _LOGGER.info("Service started successfully")
    except Exception as err:
        _LOGGER.error("Failed to start service: %s", err)
        raise

    try:
        yield
    finally:
        _LOGGER.info("Shutting down Family Link Auth Service")
        manager = app.state.browser_manager
        if manager is not None:
            await manager.cleanup()
        else:
            await app.state.display.stop()
        app.state.sessions.clear()


def create_app(config: Config | None = None) -> FastAPI:
    """Build the application.

    Raises:
        TokenError: when the API token cannot be generated, persisted or
            loaded. This propagates out of application startup on purpose: an
            auth service that cannot establish its own credential must not come
            up serving Google session cookies to anyone who asks.
    """
    config = config or get_config()
    _configure_logging(config)

    # Fail closed. Nothing below runs if the credential cannot be established.
    token = load_or_create_api_token(config.share_dir, config.api_token or None)
    redaction.register_secret(token)

    app = FastAPI(
        lifespan=_lifespan,
        title="Google Family Link Auth Service",
        description="Authentication service for Google Family Link integration",
        version=SERVICE_VERSION,
        # The interactive docs would enumerate the protected endpoints on an
        # otherwise minimal attack surface, and nothing consumes them.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = config
    app.state.token = token
    app.state.sessions = SessionStore()
    app.state.rate_limiter = RateLimiter()
    app.state.storage = SharedStorage(
        config.share_dir,
        session_duration=config.session_duration,
        allowlist_mode=config.cookie_allowlist_mode,
    )
    app.state.display = DisplayStack(config.display_stack_script)
    app.state.observer = SingleObserverGuard()
    app.state.browser_manager = None

    guard = AuthGuard(
        token=token,
        sessions=app.state.sessions,
        rate_limiter=app.state.rate_limiter,
        ingress_trusted=config.ingress_trusted,
    )
    app.state.guard = guard

    # No CORS middleware: the UI is served from this same origin and the Home
    # Assistant integration is a server-side client, so a cross-origin policy
    # would only widen what a browser on the LAN is allowed to do with the
    # session cookie.
    app.add_middleware(SecurityMiddleware, guard=guard)

    _register_routes(app)
    _mount_novnc(app, config)
    return app


def _mount_novnc(app: FastAPI, config: Config) -> None:
    """Serve the noVNC client from this app instead of a separate open port."""
    novnc_root = Path(config.novnc_root)
    if not novnc_root.is_dir():
        _LOGGER.warning(
            "noVNC assets not found at %s; the browser view will be "
            "unavailable",
            novnc_root,
        )
        return
    # Mounted behind SecurityMiddleware, so these assets are only served to an
    # authenticated session - unlike the old standalone websockify server.
    app.mount(
        "/vnc",
        StaticFiles(directory=str(novnc_root), html=True),
        name="novnc",
    )


def _register_routes(app: FastAPI) -> None:
    """Attach every route to ``app``."""

    config: Config = app.state.config

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    @app.get("/api/health")
    async def health_check() -> dict:
        """Health check endpoint - the only unauthenticated API."""
        return {
            "status": "healthy",
            "service": "familylink-auth",
            "version": SERVICE_VERSION,
        }

    @app.post("/api/session")
    async def create_session(body: SessionRequest, request: Request) -> JSONResponse:
        """Trade the service token for a short-lived httpOnly session cookie.

        The browser UI needs this because a WebSocket handshake cannot carry an
        ``X-API-Key`` header, and because a token in the URL would leak through
        history and logs. The token itself is never stored client-side.
        """
        client_key = _client_key(request)
        decision = app.state.rate_limiter.check(client_key)
        if not decision.allowed:
            return JSONResponse(
                {"detail": "Too many authentication attempts"},
                status_code=429,
                headers={"Retry-After": str(decision.retry_after)},
            )
        if not app.state.guard.verify_token(body.token):
            app.state.rate_limiter.record_failure(client_key)
            _LOGGER.warning("Rejected an invalid unlock attempt from %s", client_key)
            return JSONResponse({"detail": "Invalid API token"}, status_code=403)

        app.state.rate_limiter.reset(client_key)
        session_id = app.state.sessions.create()
        response = JSONResponse({"status": "ok", "expires_in": SESSION_TTL_SECONDS})
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="strict",
            # Scope the cookie to the ingress prefix when there is one, so it is
            # not sent with unrelated Home Assistant requests.
            path=_cookie_path(request),
            secure=request.url.scheme == "https",
        )
        return response

    @app.delete("/api/session")
    async def destroy_session(request: Request) -> JSONResponse:
        """Revoke the caller's UI session."""
        app.state.sessions.revoke(request.cookies.get(SESSION_COOKIE_NAME))
        response = JSONResponse({"status": "ok"})
        response.delete_cookie(SESSION_COOKIE_NAME, path=_cookie_path(request))
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        """Serve the authentication interface, or the unlock form."""
        translations = get_translations(config.language)
        nonce = request.scope.get("state", {}).get("csp_nonce", "")
        if not request.scope.get("state", {}).get("authenticated"):
            return HTMLResponse(_render_unlock(translations, nonce))
        return HTMLResponse(
            _render_app(translations, nonce, _ingress_path(request))
        )

    # ------------------------------------------------------------------
    # Protected surface (SecurityMiddleware closes everything not listed as
    # public, so these need no per-route dependency)
    # ------------------------------------------------------------------

    @app.post("/api/auth/start")
    async def start_authentication() -> dict:
        """Start browser authentication flow."""
        manager = app.state.browser_manager
        if manager is None:
            raise HTTPException(status_code=503, detail="Service not ready")
        try:
            session_id = await manager.start_auth_session()
        except RuntimeError as err:
            raise HTTPException(status_code=409, detail=str(err)) from err
        except Exception as err:
            _LOGGER.error(
                "Failed to start auth: %s: %s", type(err).__name__, err,
                exc_info=True,
            )
            raise HTTPException(
                status_code=500, detail="Authentication start failed"
            ) from err
        _LOGGER.info("Started auth session: %s", session_id)
        return {
            "session_id": session_id,
            "status": "started",
            "message": "Authentication session started",
        }

    @app.get("/api/auth/status/{session_id}")
    async def check_auth_status(session_id: str) -> dict:
        """Check authentication status."""
        manager = app.state.browser_manager
        if manager is None:
            raise HTTPException(status_code=503, detail="Service not ready")
        return await manager.get_session_status(session_id)

    @app.get("/api/cookies/check")
    async def check_cookies() -> dict:
        """Report whether a usable session is stored, without returning it."""
        return await app.state.storage.metadata()

    @app.get("/api/cookies")
    async def get_cookies() -> dict:
        """Retrieve stored cookies (for the Home Assistant integration)."""
        try:
            cookies = await app.state.storage.load_cookies()
        except CookiesExpired as err:
            # 410 Gone, distinct from 404: the session existed, outlived its
            # configured lifetime and has been deleted. The integration turns
            # this into a re-authentication prompt.
            raise HTTPException(
                status_code=410,
                detail={"status": "expired", "message": str(err)},
            ) from err
        except CookiesCorrupted as err:
            raise HTTPException(
                status_code=410,
                detail={"status": "corrupted", "message": str(err)},
            ) from err
        except FileNotFoundError as err:
            raise HTTPException(status_code=404, detail="No cookies found") from err
        except Exception as err:
            _LOGGER.error("Failed to load cookies: %s", err)
            raise HTTPException(
                status_code=500, detail="Failed to load cookies"
            ) from err
        return {"cookies": cookies, "status": "success", "count": len(cookies)}

    @app.delete("/api/cookies")
    async def delete_cookies() -> dict:
        """Delete stored cookies."""
        try:
            await app.state.storage.clear_cookies()
        except Exception as err:
            _LOGGER.error("Failed to delete cookies: %s", err)
            raise HTTPException(
                status_code=500, detail="Failed to delete cookies"
            ) from err
        # The values are gone from disk; stop scrubbing them from log lines too.
        redaction.forget_secrets()
        redaction.register_secret(app.state.token)
        return {"status": "success", "message": "Cookies deleted"}

    @app.websocket("/vnc/websockify")
    async def vnc_websocket(websocket: WebSocket) -> None:
        """Relay the browser view, admitting a single observer at a time."""
        observer = app.state.observer
        if not await observer.acquire():
            _LOGGER.warning(
                "Refused a second framebuffer observer while one is connected"
            )
            await websocket.close(code=1013)  # try again later
            return
        try:
            await relay(websocket, config.vnc_host, config.vnc_port)
        finally:
            await observer.release()


def _client_key(request: Request) -> str:
    """Rate-limiting key for an HTTP request."""
    return request.client.host if request.client else "unknown"


def _ingress_path(request: Request) -> str:
    """The Supervisor ingress prefix for this request, or an empty string."""
    return request.scope.get("state", {}).get("ingress_path", "") or ""


def _cookie_path(request: Request) -> str:
    """Scope the session cookie as narrowly as the deployment allows."""
    ingress = _ingress_path(request)
    return ingress if ingress.startswith("/") else "/"


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------

_STYLE = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center;
            justify-content: center; padding: 20px;
        }
        .container {
            background: white; border-radius: 16px; padding: 40px;
            max-width: 520px; width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; line-height: 1.5; }
        .status { padding: 15px; border-radius: 8px; margin-bottom: 20px; display: none; }
        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .status.info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        button {
            width: 100%; padding: 16px; background: #667eea; color: white;
            border: none; border-radius: 8px; font-size: 16px; font-weight: 600;
            cursor: pointer; transition: background 0.2s;
        }
        button:hover:not(:disabled) { background: #5568d3; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        input[type=password] {
            width: 100%; padding: 14px; margin-bottom: 12px; font-size: 15px;
            border: 1px solid #ccc; border-radius: 8px; font-family: monospace;
        }
        .instructions { background: #f8f9fa; border-radius: 8px; padding: 20px; margin-top: 20px; }
        .instructions h3 { color: #333; margin-bottom: 10px; font-size: 16px; }
        .instructions ol { margin-left: 20px; color: #666; font-size: 14px; line-height: 1.8; }
        .info-box {
            background: #e7f3ff; border-left: 4px solid #2196F3; padding: 15px;
            margin-top: 20px; border-radius: 4px; font-size: 14px; color: #1976D2;
        }
        .novnc-link {
            display: inline-block; margin-top: 10px; padding: 8px 16px;
            background: #2196F3; color: white; text-decoration: none;
            border-radius: 6px; font-weight: 500; font-size: 14px;
        }
        .novnc-link:hover { background: #1976D2; }
        .novnc-hint { margin-top: 8px; font-size: 12px; color: #666; }
        code { background: #eef1f5; padding: 1px 5px; border-radius: 3px; }
"""


def _render_unlock(t: dict, nonce: str) -> str:
    """The token-entry page shown to an unauthenticated browser.

    The token is posted once to ``/api/session`` and exchanged for an httpOnly
    cookie; it is never placed in a URL and never persisted by the page.
    """
    return f"""<!DOCTYPE html>
<html lang="{html.escape(t['html_lang'])}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(t['title'])}</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="container">
  <h1>&#128274; {html.escape(t['unlock_title'])}</h1>
  <p class="subtitle">{t['unlock_help']}</p>
  <div id="status" class="status"></div>
  <form id="unlock" autocomplete="off">
    <input type="password" id="token" name="token" autocomplete="off"
           placeholder="{html.escape(t['unlock_placeholder'])}" required>
    <button type="submit">{html.escape(t['unlock_button'])}</button>
  </form>
</div>
<script nonce="{nonce}">
const T = {{
  invalid: {_js(t['unlock_invalid'])},
  limited: {_js(t['unlock_rate_limited'])}
}};
document.getElementById('unlock').addEventListener('submit', async (event) => {{
  event.preventDefault();
  const field = document.getElementById('token');
  const status = document.getElementById('status');
  const show = (message, kind) => {{
    status.textContent = message;
    status.className = 'status ' + kind;
    status.style.display = 'block';
  }};
  try {{
    const response = await fetch('api/session', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{token: field.value}})
    }});
    field.value = '';
    if (response.ok) {{
      window.location.reload();
      return;
    }}
    show(response.status === 429 ? T.limited : T.invalid, 'error');
  }} catch (err) {{
    show(T.invalid, 'error');
  }}
}});
</script>
</body>
</html>"""


def _render_app(t: dict, nonce: str, ingress_path: str) -> str:
    """The authentication UI shown to an authenticated session."""
    prefix = ingress_path.rstrip("/")
    # noVNC builds its WebSocket URL from the host plus this root-relative
    # path, so the ingress prefix has to be handed to it explicitly.
    ws_path = f"{prefix}/vnc/websockify".lstrip("/")
    novnc_url = (
        f"{prefix}/vnc/vnc.html?autoconnect=true&resize=scale"
        f"&path={ws_path}"
    )
    return f"""<!DOCTYPE html>
<html lang="{html.escape(t['html_lang'])}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(t['title'])}</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="container">
  <h1>&#128274; Google Family Link</h1>
  <p class="subtitle">{html.escape(t['subtitle'])}</p>

  <div id="status" class="status"></div>

  <button id="authButton">{html.escape(t['start_auth'])}</button>

  <div class="instructions">
    <h3>&#128203; {html.escape(t['instructions_title'])}</h3>
    <ol>
      <li>{html.escape(t['instruction_1'])}</li>
      <li>{html.escape(t['instruction_2'])}</li>
      <li>{html.escape(t['instruction_3'])}</li>
      <li>{html.escape(t['instruction_4'])}</li>
      <li>{html.escape(t['instruction_5'])}</li>
      <li>{html.escape(t['instruction_6'])}</li>
      <li>{html.escape(t['instruction_7'])}</li>
    </ol>
  </div>

  <div class="info-box">
    &#128161; <strong>Note:</strong> {html.escape(t['info_note'])}<br>
    <a id="novnc-link" class="novnc-link" href="{html.escape(novnc_url)}"
       target="_blank" rel="noopener">&#128421; {html.escape(t['novnc_link_text'])}</a>
    <div class="novnc-hint">{html.escape(t['novnc_hint'])}</div>
  </div>
</div>
<script nonce="{nonce}">
const T = {{
  starting: {_js(t['starting'])},
  waiting: {_js(t['waiting'])},
  auth_starting: {_js(t['auth_starting'])},
  browser_open: {_js(t['browser_open'])},
  start_failed: {_js(t['start_failed'])},
  retry: {_js(t['retry'])},
  auth_success: {_js(t['auth_success'])},
  auth_completed: {_js(t['auth_completed'])},
  auth_timeout: {_js(t['auth_timeout'])},
  retry_auth: {_js(t['retry_auth'])},
  auth_error: {_js(t['auth_error'])},
  unknown_error: {_js(t['unknown_error'])},
  cookies_exist: {_js(t['cookies_exist'])},
  session_expired: {_js(t['session_expired'])},
  start_error: {_js(t['start_error'])}
}};

let sessionId = null;
let statusCheckInterval = null;

function showStatus(message, kind) {{
  const status = document.getElementById('status');
  status.textContent = message;
  status.className = 'status ' + kind;
  status.style.display = 'block';
}}

// Credentials travel as the httpOnly session cookie set by /api/session, so
// no token is present anywhere in this page or in any URL it builds.
async function startAuth() {{
  const button = document.getElementById('authButton');
  button.disabled = true;
  button.textContent = T.starting;
  try {{
    showStatus(T.auth_starting, 'info');
    const response = await fetch('api/auth/start', {{method: 'POST'}});
    if (!response.ok) {{
      throw new Error(T.start_error);
    }}
    const data = await response.json();
    sessionId = data.session_id;
    showStatus(T.browser_open, 'info');
    button.textContent = T.waiting;
    statusCheckInterval = setInterval(checkAuthStatus, 2000);
  }} catch (error) {{
    showStatus(T.start_failed + error.message, 'error');
    button.disabled = false;
    button.textContent = T.retry;
  }}
}}

async function checkAuthStatus() {{
  if (!sessionId) return;
  try {{
    const response = await fetch('api/auth/status/' + encodeURIComponent(sessionId));
    const data = await response.json();
    const button = document.getElementById('authButton');
    if (data.status === 'completed') {{
      clearInterval(statusCheckInterval);
      showStatus(T.auth_success.replace('{{count}}', data.cookie_count), 'success');
      button.textContent = T.auth_completed;
    }} else if (data.status === 'timeout') {{
      clearInterval(statusCheckInterval);
      showStatus(T.auth_timeout, 'error');
      button.disabled = false;
      button.textContent = T.retry_auth;
    }} else if (data.status === 'error') {{
      clearInterval(statusCheckInterval);
      showStatus(T.auth_error + (data.error || T.unknown_error), 'error');
      button.disabled = false;
      button.textContent = T.retry_auth;
    }}
  }} catch (error) {{
    // Transient poll failure; the next tick retries.
  }}
}}

document.getElementById('authButton').addEventListener('click', startAuth);

window.addEventListener('load', async () => {{
  try {{
    const response = await fetch('api/cookies/check');
    if (!response.ok) return;
    const data = await response.json();
    if (data.exists && !data.expired) {{
      showStatus(T.cookies_exist, 'success');
    }} else if (data.exists && data.expired) {{
      showStatus(T.session_expired, 'info');
    }}
  }} catch (error) {{
    // Ignore errors on the initial check.
  }}
}});
</script>
</body>
</html>"""


def _js(value: str) -> str:
    """Embed a translation string in JavaScript as a JSON literal.

    Using JSON rather than raw interpolation keeps a translation containing a
    quote or a backslash from breaking - or escaping - the script block.
    """
    return json.dumps(value)


# Built at import time so a token problem stops the process before it serves a
# single request.
app = create_app()


if __name__ == "__main__":
    _config = app.state.config
    uvicorn.run(
        app,
        host=_config.host,
        port=_config.port,
        log_level=_config.log_level.lower(),
    )
