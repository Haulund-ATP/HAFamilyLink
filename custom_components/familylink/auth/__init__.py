"""Authentication module for Google Family Link integration."""
from __future__ import annotations

from .addon_client import AddonCookieClient, CookiesExpiredError, split_legacy_auth_url

__all__ = ["AddonCookieClient", "CookiesExpiredError", "split_legacy_auth_url"]
