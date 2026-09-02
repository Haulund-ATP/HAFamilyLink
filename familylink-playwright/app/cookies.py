"""Minimisation and validation of the Google cookies this service persists.

The authentication browser ends up holding every cookie a Google login sets -
Search preferences, YouTube, Ads personalisation, consent state, per-product
session identifiers. None of that is needed to call the Family Link
(kidsmanagement) API, but all of it was previously encrypted, written to
``/share`` and handed to the integration, widening the blast radius of a leak
far beyond Family Link itself.

Only the cookies below are persisted in the default ``strict`` mode. The
authoritative requirement is small: ``SAPISID`` (or its ``__Secure-*PAPISID``
equivalents) is what the ``SAPISIDHASH`` authorisation header is derived from,
and the session identifiers alongside it are what Google's cookie
authentication validates.

Regional Google deployments and account types have not all been verified, which
is why ``legacy`` mode still exists as a documented escape hatch.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

_LOGGER = logging.getLogger(__name__)

#: Cookie names required to authenticate against the kidsmanagement API.
#:
#: ``SAPISID``/``__Secure-*PAPISID`` feed the ``SAPISIDHASH`` header;
#: ``SID``/``__Secure-*PSID`` plus ``HSID``/``SSID``/``APISID`` are the session
#: identifiers Google validates; the ``*PSIDTS``/``SIDCC`` family carries the
#: rotating session-binding values Google refreshes and rejects requests
#: without on newer accounts.
REQUIRED_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        "SID",
        "HSID",
        "SSID",
        "APISID",
        "SAPISID",
        "SIDCC",
        "__Secure-1PSID",
        "__Secure-3PSID",
        "__Secure-1PAPISID",
        "__Secure-3PAPISID",
        "__Secure-1PSIDTS",
        "__Secure-3PSIDTS",
        "__Secure-1PSIDCC",
        "__Secure-3PSIDCC",
    }
)

#: The subset without which authentication cannot work at all. Used to warn
#: early rather than persisting a set that will fail on first API call.
CORE_COOKIE_NAMES: frozenset[str] = frozenset({"SAPISID", "SID"})

#: Domains a persisted cookie may belong to. Cookies scoped to unrelated
#: Google products (youtube.com, google.<cctld> regional hosts) are dropped.
ALLOWED_COOKIE_DOMAINS: tuple[str, ...] = (
    "google.com",
    "accounts.google.com",
    "families.google.com",
    "familylink.google.com",
)

#: Cookie metadata worth preserving. The security-relevant flags
#: (``secure``, ``httpOnly``, ``sameSite``) are kept so a cookie is never
#: replayed with weaker protection than Google set it with.
_PRESERVED_FIELDS: tuple[str, ...] = (
    "name",
    "value",
    "domain",
    "path",
    "expires",
    "httpOnly",
    "secure",
    "sameSite",
)


def _normalise_domain(domain: str) -> str:
    """Strip the leading dot and lowercase a cookie domain."""
    return (domain or "").strip().lower().lstrip(".")


def domain_allowed(domain: str) -> bool:
    """Whether a cookie domain is in the allowlist (exact host or subdomain)."""
    normalised = _normalise_domain(domain)
    if not normalised:
        return False
    return any(
        normalised == allowed or normalised.endswith(f".{allowed}")
        for allowed in ALLOWED_COOKIE_DOMAINS
    )


def _strip_metadata(cookie: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields needed to replay a cookie safely."""
    return {key: cookie[key] for key in _PRESERVED_FIELDS if key in cookie}


def filter_cookies(
    cookies: Iterable[dict[str, Any]],
    mode: str = "strict",
) -> list[dict[str, Any]]:
    """Return the cookies worth persisting.

    In ``strict`` mode only allowlisted names on allowlisted domains survive.
    In ``legacy`` mode the historical behaviour is kept: every cookie on an
    allowlisted domain is persisted, regardless of name.

    Cookie *values* are never logged - only names and counts.
    """
    kept: list[dict[str, Any]] = []
    dropped_names: set[str] = set()
    for cookie in cookies:
        name = (cookie.get("name") or "").strip()
        if not name or not cookie.get("value"):
            continue
        if not domain_allowed(cookie.get("domain", "")):
            dropped_names.add(name)
            continue
        if mode != "legacy" and name not in REQUIRED_COOKIE_NAMES:
            dropped_names.add(name)
            continue
        kept.append(_strip_metadata(cookie))

    if dropped_names:
        _LOGGER.info(
            "Cookie minimisation dropped %d cookie name(s) not needed for "
            "Family Link: %s",
            len(dropped_names),
            ", ".join(sorted(dropped_names)),
        )
    missing_core = CORE_COOKIE_NAMES - {c["name"] for c in kept}
    if missing_core:
        _LOGGER.warning(
            "The captured session is missing core cookie(s) %s; Family Link "
            "API calls will most likely fail. Set the add-on option "
            "cookie_allowlist_mode to 'legacy' and report the issue if this "
            "persists on your Google region.",
            ", ".join(sorted(missing_core)),
        )
    return kept


def cookie_names(cookies: Iterable[dict[str, Any]]) -> list[str]:
    """Names only - safe to log."""
    return sorted({(c.get("name") or "?") for c in cookies})


def scrub(cookies: Iterable[dict[str, Any]] | None) -> None:
    """Best-effort overwrite of cookie values held in memory.

    Python strings are immutable and the interpreter may have interned or
    copied a value already, so this cannot guarantee the bytes are gone. It
    does remove the last live reference this process holds, which is what
    shortens the window in which a heap dump or a swap file would contain the
    session. Documented as best-effort rather than a guarantee.
    """
    if not cookies:
        return
    for cookie in cookies:
        if isinstance(cookie, dict) and "value" in cookie:
            cookie["value"] = ""
