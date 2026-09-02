"""Client to read cookies from Family Link Auth add-on or standalone container."""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

import aiohttp
from cryptography.fernet import Fernet

from homeassistant.core import HomeAssistant

from .. import redact
from ..const import LOGGER_NAME

_LOGGER = logging.getLogger(LOGGER_NAME)

# Addon slug suffix (the hash prefix is derived from the repository URL)
_ADDON_SLUG_SUFFIX = "familylink-playwright"
_ADDON_PORT = 8099

# Default URL for local add-on (Home Assistant OS/Supervised)
DEFAULT_AUTH_URL = "http://localhost:8099"

#: Query parameters that used to carry the API key in the configured URL.
_LEGACY_TOKEN_PARAMS = ("api_key", "api_token", "token")


def split_legacy_auth_url(auth_url: str | None) -> tuple[str | None, str | None]:
    """Split a legacy ``http://host:8099?api_key=...`` URL.

    Returns ``(base_url, token)``. The auth service now refuses a token in the
    query string outright, so an existing configuration has to be migrated
    rather than passed through: the token moves to its own field and is sent as
    the ``X-API-Key`` header.
    """
    if not auth_url:
        return None, None
    parts = urlsplit(auth_url.strip())
    if not parts.query:
        return auth_url.strip().rstrip("/") or None, None
    params = parse_qs(parts.query)
    token: str | None = None
    for name in _LEGACY_TOKEN_PARAMS:
        values = params.get(name)
        if values and values[0]:
            token = values[0]
            break
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")).rstrip("/")
    return base or None, token


class CookiesExpiredError(Exception):
    """The auth service reports the stored Google session has expired."""


class AddonCookieClient:
    """Client to read cookies from add-on via API or shared storage."""

    SHARE_DIR = Path("/share/familylink")
    COOKIE_FILE = "cookies.enc"
    KEY_FILE = ".key"
    API_KEY_FILE = "api_key"  # Written by the auth add-on, protects the API

    def __init__(
        self,
        hass: HomeAssistant,
        auth_url: str | None = None,
        api_token: str | None = None,
    ):
        """Initialize addon cookie client.

        Args:
            hass: Home Assistant instance
            auth_url: Optional URL for the auth server (for Docker standalone
                mode). A legacy ``?api_key=`` query parameter is split off and
                treated as the token; it is never sent in a URL.
            api_token: The auth service token, sent as the ``X-API-Key``
                header. When omitted it is read from the shared directory,
                which is how add-on installations need no configuration.
        """
        self.hass = hass
        base_url, legacy_token = split_legacy_auth_url(auth_url)
        self.auth_url = base_url
        self._api_token = (api_token or legacy_token or "").strip() or None
        self.migrated_legacy_token = bool(legacy_token and not api_token)
        redact.register_secret(self._api_token)
        self.storage_path = self.SHARE_DIR / self.COOKIE_FILE
        self.key_file = self.SHARE_DIR / self.KEY_FILE
        self.api_key_file = self.SHARE_DIR / self.API_KEY_FILE
        self._detected_url: str | None = None
        self._supervisor_url_resolved = False
        self.last_fetch_status: int | None = None  # HTTP status of last fetch
        self.reauth_required = False  # Set when the service reports expiry

    @property
    def api_token(self) -> str | None:
        """The token this client will present, if any."""
        return self._api_token

    async def _get_api_token(self) -> str | None:
        """Resolve the token protecting the auth server's endpoints.

        Priority: the configured token, then the key file the add-on writes to
        the shared directory (which is what makes add-on setups zero-config).
        """
        if self._api_token:
            return self._api_token

        def _read_key_file() -> str | None:
            try:
                return self.api_key_file.read_text().strip() or None
            except OSError:
                return None

        token = await self.hass.async_add_executor_job(_read_key_file)
        redact.register_secret(token)
        return token

    async def _resolve_addon_url(self) -> str | None:
        """Resolve addon URL via Supervisor API.

        On HAOS, addon containers are not reachable via localhost.
        Each addon gets a Docker DNS hostname derived from its slug
        (underscores replaced with hyphens).
        """
        token = os.environ.get("SUPERVISOR_TOKEN")
        if not token:
            return None
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://supervisor/addons",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    addons = data.get("data", {}).get("addons", [])
                    for addon in addons:
                        slug = addon.get("slug", "")
                        if (
                            slug.endswith(f"_{_ADDON_SLUG_SUFFIX}")
                            and addon.get("state") == "started"
                        ):
                            hostname = slug.replace("_", "-")
                            url = f"http://{hostname}:{_ADDON_PORT}"
                            _LOGGER.debug("Resolved addon URL via Supervisor: %s", url)
                            return url
        except Exception as err:
            _LOGGER.debug("Could not resolve addon URL via Supervisor: %s", err)
        return None

    async def _get_addon_url(self) -> str | None:
        """Get the Supervisor-resolved addon URL, caching the lookup.

        Returns the resolved Docker hostname URL, or None when the addon
        cannot be discovered via the Supervisor (non-HAOS setups).
        """
        if not self._supervisor_url_resolved:
            self._supervisor_url_resolved = True
            resolved = await self._resolve_addon_url()
            if resolved:
                self._detected_url = resolved
                _LOGGER.info("Addon URL resolved via Supervisor: %s", resolved)
        return self._detected_url

    async def _fetch_cookies_from_url(self, url: str) -> list[dict[str, Any]] | None:
        """Fetch cookies from auth server API.

        Args:
            url: Base URL of the auth server (e.g., http://localhost:8099)

        Returns:
            List of cookies, or None when they could not be fetched.

        Raises:
            CookiesExpiredError: the service reports the stored session has
                expired or is unusable, and has deleted it.
        """
        base = url.rstrip("/")
        api_url = f"{base}/api/cookies"
        self.last_fetch_status = None
        token = await self._get_api_token()
        headers = {"X-API-Key": token} if token else {}
        # Log the URL without its query string: an older configuration may
        # still carry a credential there, and a logged URL must never be one.
        safe_url = redact.redact_url(api_url)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    api_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    self.last_fetch_status = response.status
                    if response.status == 200:
                        data = await response.json()
                        cookies = data.get("cookies", [])
                        redact.register_cookie_secrets(cookies)
                        self.reauth_required = False
                        _LOGGER.info(
                            "Loaded %d cookies from the auth service", len(cookies)
                        )
                        return cookies
                    if response.status == 404:
                        _LOGGER.debug("No cookies found at %s", safe_url)
                        return None
                    if response.status == 410:
                        # The service enforced session_duration, deleted the
                        # stored session and is telling us to re-authenticate.
                        self.reauth_required = True
                        raise CookiesExpiredError(
                            "The stored Google session has expired and was "
                            "deleted by the auth service. Re-authenticate with "
                            "the Family Link Auth add-on."
                        )
                    if response.status in (401, 403):
                        _LOGGER.warning(
                            "The auth service at %s rejected the request (%s). "
                            "Enter the service token in the integration's "
                            "options; for an add-on install it is read "
                            "automatically from %s, and for a standalone "
                            "container it is in the api_key file of the data "
                            "directory. Do not put it in the URL.",
                            redact.redact_url(base),
                            response.status,
                            self.api_key_file,
                        )
                        return None
                    if response.status == 429:
                        _LOGGER.warning(
                            "The auth service is rate-limiting authentication "
                            "attempts; the configured token is probably wrong."
                        )
                        return None
                    _LOGGER.debug(
                        "API returned status %s from %s", response.status, safe_url
                    )
                    return None
        except CookiesExpiredError:
            raise
        except aiohttp.ClientError as err:
            _LOGGER.debug("Failed to connect to %s: %s", safe_url, err)
            return None
        except Exception as err:
            _LOGGER.debug("Error fetching cookies from %s: %s", safe_url, err)
            return None

    async def _check_url_available(self, url: str) -> bool:
        """Check if auth server API is available at URL."""
        health_url = f"{url.rstrip('/')}/api/health"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    health_url, timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    return response.status == 200
        except Exception:
            return False

    async def check_token(self, url: str) -> bool:
        """Whether the configured token is accepted by the auth service.

        Uses ``/api/cookies/check``, which reports session metadata but never
        returns a cookie value, so a config-flow validation cannot leak the
        session it is validating access to.
        """
        check_url = f"{url.rstrip('/')}/api/cookies/check"
        token = await self._get_api_token()
        headers = {"X-API-Key": token} if token else {}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    check_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    self.last_fetch_status = response.status
                    return response.status == 200
        except Exception as err:
            _LOGGER.debug(
                "Token check against %s failed: %s", redact.redact_url(check_url), err
            )
            return False

    async def session_metadata(self, url: str | None = None) -> dict[str, Any] | None:
        """Return the auth service's session metadata, or None."""
        target = url or self._detected_url or self.auth_url or DEFAULT_AUTH_URL
        check_url = f"{target.rstrip('/')}/api/cookies/check"
        token = await self._get_api_token()
        headers = {"X-API-Key": token} if token else {}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    check_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status != 200:
                        return None
                    return await response.json()
        except Exception:
            return None

    async def _get_encryption_key(self) -> bytes:
        """Get encryption key (must match add-on key)."""
        if not await self.hass.async_add_executor_job(self.key_file.exists):
            raise FileNotFoundError(
                "Encryption key not found. Make sure the Family Link Auth "
                "add-on is installed and has been used at least once."
            )
        return await self.hass.async_add_executor_job(self.key_file.read_bytes)

    async def _load_cookies_from_file(self) -> list[dict[str, Any]] | None:
        """Load cookies from the encrypted file (fallback when the API is down).

        The stored envelope carries the session expiry, which is enforced here
        too: the file fallback must not become a way to keep using a session
        the service would already have refused.
        """
        if not await self.hass.async_add_executor_job(self.storage_path.exists):
            _LOGGER.debug("No cookies found in shared storage")
            return None

        try:
            encrypted = await self.hass.async_add_executor_job(
                self.storage_path.read_bytes
            )
            key = await self._get_encryption_key()
            decrypted = Fernet(key).decrypt(encrypted)
            data = json.loads(decrypted.decode())
        except Exception as err:
            _LOGGER.error("Failed to load cookies from file: %s", err)
            return None

        expires_at = data.get("expires_at")
        if isinstance(expires_at, (int, float)):
            if time.time() >= expires_at:
                self.reauth_required = True
                raise CookiesExpiredError(
                    "The stored Google session has expired. Re-authenticate "
                    "with the Family Link Auth add-on."
                )

        cookies = data.get("cookies", [])
        redact.register_cookie_secrets(cookies)
        _LOGGER.info("Loaded %d cookies from file", len(cookies))
        return cookies

    async def _file_available(self) -> bool:
        """Check if cookie file is available."""
        storage_exists = await self.hass.async_add_executor_job(
            self.storage_path.exists
        )
        key_exists = await self.hass.async_add_executor_job(self.key_file.exists)
        return storage_exists and key_exists

    async def detect_auth_source(self) -> tuple[str, str | None]:
        """Detect available authentication source.

        Returns:
            Tuple of (source_type, url_or_none):
            - ("api", "http://...") if API is available
            - ("file", None) if file is available
            - ("none", None) if nothing is available
        """
        # 1. If custom URL is configured, check it first
        if self.auth_url:
            if await self._check_url_available(self.auth_url):
                self._detected_url = self.auth_url
                return ("api", self.auth_url)

        # 2. Resolve addon URL via Supervisor API (Docker hostname, HAOS)
        supervisor_url = await self._get_addon_url()
        if supervisor_url and await self._check_url_available(supervisor_url):
            self._detected_url = supervisor_url
            _LOGGER.info("Addon detected via Supervisor at %s", supervisor_url)
            return ("api", supervisor_url)

        # 3. Try default local URL (standalone / Docker Compose)
        if await self._check_url_available(DEFAULT_AUTH_URL):
            self._detected_url = DEFAULT_AUTH_URL
            return ("api", DEFAULT_AUTH_URL)

        # 4. Fallback to file
        if await self._file_available():
            return ("file", None)

        # 5. Nothing available
        return ("none", None)

    async def load_cookies(self) -> list[dict[str, Any]] | None:
        """Load cookies using best available method.

        Priority:
        1. Custom URL (if configured)
        2. Supervisor-resolved addon URL (HAOS installations)
        3. Default local API (localhost:8099)
        4. File fallback (/share/familylink/)

        Raises:
            CookiesExpiredError: the stored session outlived its configured
                lifetime; re-authentication is required.
        """
        # 1. If custom URL is configured, use it
        if self.auth_url:
            cookies = await self._fetch_cookies_from_url(self.auth_url)
            if cookies is not None:
                return cookies
            _LOGGER.warning(
                "Failed to load cookies from the configured auth URL %s",
                redact.redact_url(self.auth_url),
            )

        # 2. Try the Supervisor-resolved addon URL (HAOS installations)
        resolved_url = await self._get_addon_url()
        if resolved_url and resolved_url != self.auth_url:
            cookies = await self._fetch_cookies_from_url(resolved_url)
            if cookies is not None:
                return cookies

        # 3. Try default local API (standalone / Docker Compose)
        if self.auth_url != DEFAULT_AUTH_URL:
            cookies = await self._fetch_cookies_from_url(DEFAULT_AUTH_URL)
            if cookies is not None:
                return cookies

        # 4. Fallback to file
        _LOGGER.debug("API not available, trying file fallback")
        return await self._load_cookies_from_file()

    async def cookies_available(self) -> bool:
        """Check if cookies are available from any source."""
        source_type, _ = await self.detect_auth_source()
        if source_type == "none":
            return False

        try:
            cookies = await self.load_cookies()
        except CookiesExpiredError:
            return False
        return cookies is not None and len(cookies) > 0

    async def clear_cookies(self) -> None:
        """Clear stored cookies (file only, API doesn't support this)."""
        if await self.hass.async_add_executor_job(self.storage_path.exists):
            await self.hass.async_add_executor_job(self.storage_path.unlink)
            _LOGGER.info("Cleared addon cookies")
        redact.forget_secrets()
        redact.register_secret(self._api_token)
