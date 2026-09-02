"""Configuration management for the add-on."""
from __future__ import annotations

import os

from pydantic import BaseModel

# Bounds mirrored from the add-on schema (``int(3600,604800)``) so the
# standalone container, which has no Supervisor to validate its options,
# enforces exactly the same limits.
MIN_SESSION_DURATION = 3600
MAX_SESSION_DURATION = 604800
DEFAULT_SESSION_DURATION = 86400

MIN_AUTH_TIMEOUT = 60
MAX_AUTH_TIMEOUT = 600
DEFAULT_AUTH_TIMEOUT = 300


class Config(BaseModel):
    """Application configuration."""

    log_level: str = "info"
    auth_timeout: int = DEFAULT_AUTH_TIMEOUT
    session_duration: int = DEFAULT_SESSION_DURATION
    # Binds every interface inside the container on purpose: the
    # Supervisor's ingress proxy and the Home Assistant integration reach
    # the service on the container's own address, not on loopback. What
    # limits exposure is the absence of a host port mapping (see
    # config.json "ports") plus authentication on every endpoint - not the
    # bind address.
    host: str = "0.0.0.0"  # noqa: S104  # nosec B104 - see comment above
    port: int = 8099

    # Paths
    share_dir: str = "/share/familylink"
    cookie_file: str = "cookies.enc"
    key_file: str = ".key"

    # Browser settings
    browser_timeout: int = 300000  # 5 minutes in milliseconds
    browser_navigation_timeout: int = 30000  # 30 seconds
    language: str = "en-US"  # Browser locale (e.g., fr-FR, en-GB, de-DE)
    timezone: str = "Europe/Paris"  # Browser timezone (e.g., America/New_York)

    # Deployment mode
    # Supervisor-managed add-on run (HA OS / Supervised). run.sh exports
    # ADDON_MODE=1; the Supervisor also injects SUPERVISOR_TOKEN.
    addon_mode: bool = False
    # Set only when the add-on is reached exclusively through Home Assistant
    # ingress, i.e. the host port is NOT published. In that case the Supervisor
    # has already authenticated the Home Assistant user before proxying, so an
    # ingress request counts as an authenticated UI session.
    ingress_trusted: bool = False

    # Operator-provided API token. Empty means "generate and persist one".
    api_token: str = ""

    # Cookie minimisation. "strict" persists only the allowlisted Google
    # authentication cookies; "legacy" keeps the historical behaviour of
    # persisting every google.com cookie and exists purely as an escape hatch
    # for regional Google variations the allowlist has not been tested against.
    cookie_allowlist_mode: str = "strict"

    # noVNC assets shipped by the distribution package.
    novnc_root: str = "/usr/share/novnc"
    # The VNC server the in-process bridge relays to. Bound to loopback inside
    # the container and never published.
    vnc_host: str = "127.0.0.1"
    vnc_port: int = 5900
    # Script controlling the on-demand display stack (Xvnc + window manager).
    display_stack_script: str = "/usr/local/bin/display-stack.sh"


def _safe_int(value: str | None, default: int) -> int:
    """Safely convert string to int with fallback."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return default


def _clamp(value: int, low: int, high: int) -> int:
    """Clamp a duration into its documented range."""
    return max(low, min(high, value))


def _env_flag(name: str) -> bool:
    """Read a boolean environment flag."""
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def get_config() -> Config:
    """Get configuration from environment variables."""
    session_duration = _clamp(
        _safe_int(os.getenv("SESSION_DURATION"), DEFAULT_SESSION_DURATION),
        MIN_SESSION_DURATION,
        MAX_SESSION_DURATION,
    )
    auth_timeout = _clamp(
        _safe_int(os.getenv("AUTH_TIMEOUT"), DEFAULT_AUTH_TIMEOUT),
        MIN_AUTH_TIMEOUT,
        MAX_AUTH_TIMEOUT,
    )
    allowlist_mode = os.getenv("COOKIE_ALLOWLIST_MODE", "strict").strip().lower()
    if allowlist_mode not in ("strict", "legacy"):
        allowlist_mode = "strict"
    return Config(
        log_level=os.getenv("LOG_LEVEL", "info"),
        auth_timeout=auth_timeout,
        session_duration=session_duration,
        language=os.getenv("LANGUAGE", "en-US"),
        timezone=os.getenv("TIMEZONE", "Europe/Paris"),
        addon_mode=bool(os.getenv("SUPERVISOR_TOKEN")) or _env_flag("ADDON_MODE"),
        ingress_trusted=_env_flag("INGRESS_TRUSTED"),
        # API_KEY is the historical name and stays supported; API_TOKEN reads
        # better now that it is no longer passed as a URL parameter.
        api_token=os.getenv("API_TOKEN") or os.getenv("API_KEY", ""),
        cookie_allowlist_mode=allowlist_mode,
        share_dir=os.getenv("SHARE_DIR", "/share/familylink"),
    )
