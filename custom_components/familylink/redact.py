"""Central log redaction for the Google Family Link integration.

This integration handles two categories of data that must never reach a log
file, a diagnostics download or a shared "here is my log" paste:

* **Credentials** - Google session cookies, the ``SAPISIDHASH`` authorisation
  value derived from ``SAPISID``, and the auth service's API token.
* **Child data** - live coordinates, saved-place names and addresses, device
  identifiers and account identifiers of a supervised child.

Rather than trusting every call site, a logging filter is installed on the
integration's logger and scrubs each record before it is formatted. Call sites
that build a message from raw API data additionally use :func:`redact_response`
so a Google response is never logged in full.
"""
from __future__ import annotations

import logging
import re
import traceback
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***REDACTED***"

#: Query parameters that must never survive into a log line.
_SENSITIVE_QUERY_PARAMS = (
    "api_key",
    "apikey",
    "api-key",
    "token",
    "access_token",
    "key",
    "password",
)

#: Keys whose values are stripped from any structure passed to
#: :func:`redact_mapping` - used for config-entry diagnostics.
SENSITIVE_CONFIG_KEYS = frozenset(
    {"api_token", "api_key", "token", "cookies", "password", "auth_url"}
)

#: Keys carrying child location or identity data.
_LOCATION_KEYS = frozenset(
    {
        "latitude",
        "longitude",
        "accuracy",
        "place_id",
        "place_name",
        "place_address",
        "source_device_id",
    }
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(" + "|".join(_SENSITIVE_QUERY_PARAMS) + r")=[^\s&\"'#]+"
        ),
        r"\1=" + REDACTED,
    ),
    (
        re.compile(
            r"(?i)\b(x-api-key|authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+"
        ),
        r"\1: " + REDACTED,
    ),
    (re.compile(r"(?i)\bSAPISIDHASH\s+\S+"), "SAPISIDHASH " + REDACTED),
    (
        re.compile(
            r"(?i)\b(__Secure-\d+PSIDTS|__Secure-\d+PSID|__Secure-\d+PAPISID|"
            r"SAPISID|APISID|HSID|SSID|SIDCC|LSID|SID)\s*[:=]\s*[^\s;,\"']+"
        ),
        r"\1=" + REDACTED,
    ),
    # A bare coordinate pair, however it is spelled: "(55.6761, 12.5683)",
    # "lat=55.6761", "latitude: 55.6761".
    (
        re.compile(
            r"(?i)\b(lat|latitude|lon|lng|longitude)\s*[:=]\s*-?\d+\.\d+"
        ),
        r"\1=" + REDACTED,
    ),
    # A coordinate pair in either delimiter. Google's protobuf-style JSON
    # returns the child's position as a bare array - [55.676098,12.568337] -
    # so brackets matter as much as parentheses.
    (
        re.compile(
            r"([\[(])\s*-?\d{1,3}\.\d{3,}\s*,\s*-?\d{1,3}\.\d{3,}\s*([\])])"
        ),
        r"" + REDACTED + r"",
    ),
)

_MIN_SECRET_LENGTH = 8
_secrets: set[str] = set()

#: Personally identifying values - a supervised child's display name and
#: account id. These are matched on word boundaries rather than as substrings,
#: because a short name would otherwise be masked inside unrelated words.
_MIN_IDENTIFIER_LENGTH = 2
_identifiers: dict[str, re.Pattern[str]] = {}


def register_secret(value: str | None) -> None:
    """Register an exact value to scrub from every future log record."""
    if value and len(value) >= _MIN_SECRET_LENGTH:
        _secrets.add(value)


def register_identifier(value: str | None) -> None:
    """Register a child name or account id to scrub from log records.

    The integration logs a child's name in many places to make debugging a
    multi-child family tractable. Rather than rewriting every one of those call
    sites into something unreadable, the identifiers are registered here once
    they are discovered and masked centrally on the way out.
    """
    if not value:
        return
    text = str(value).strip()
    if len(text) < _MIN_IDENTIFIER_LENGTH or text in _identifiers:
        return
    _identifiers[text] = re.compile(rf"(?<![\w-]){re.escape(text)}(?![\w-])")


def register_children(children: list[dict[str, Any]] | None) -> None:
    """Register the names and ids of every supervised child."""
    for child in children or []:
        if not isinstance(child, dict):
            continue
        register_identifier(child.get("name"))
        register_identifier(child.get("id"))


def register_cookie_secrets(cookies: list[dict[str, Any]] | None) -> None:
    """Register every cookie value so none can leak through any log line."""
    for cookie in cookies or []:
        register_secret(cookie.get("value"))


def forget_secrets() -> None:
    """Drop all registered secrets and identifiers."""
    _secrets.clear()
    _identifiers.clear()


def redact(text: str) -> str:
    """Return ``text`` with credentials, coordinates and secrets masked."""
    if not text:
        return text
    for value in _secrets:
        if value in text:
            text = text.replace(value, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    for pattern in _identifiers.values():
        text = pattern.sub(REDACTED, text)
    return text


def redact_url(url: str) -> str:
    """Return ``url`` without its query string or fragment.

    Google's endpoints put continuation tokens and identifiers in the query, and
    the auth-service URL historically carried ``?api_key=``, so the whole query
    is dropped rather than filtered parameter by parameter.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    return redact(urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))


def redact_response(body: str | None, limit: int = 200) -> str:
    """Summarise an API response body for a log line.

    Google's responses embed the child's identifiers, device names and - for
    the location endpoint - coordinates and the address of a saved place.
    Logging one in full puts all of that in the Home Assistant log, so the body
    is redacted *and* truncated to a short prefix that is still enough to
    recognise an error shape.
    """
    if not body:
        return "<empty>"
    redacted = redact(body)
    if len(redacted) > limit:
        return f"{redacted[:limit]}... [truncated, {len(body)} bytes total]"
    return redacted


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Copy ``data`` with sensitive and location values replaced."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        lowered = str(key).lower()
        if lowered in SENSITIVE_CONFIG_KEYS or lowered in _LOCATION_KEYS:
            result[key] = REDACTED
        elif isinstance(value, dict):
            result[key] = redact_mapping(value)
        elif isinstance(value, str):
            result[key] = redact(value)
        else:
            result[key] = value
    return result


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs secrets from the message and its arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Interpolate before redacting, then drop the arguments.
        #
        # Redacting the format string on its own is not safe: a message like
        # "token=%s" contains a credential-shaped fragment, so masking it
        # removes the %s placeholder while the argument is still present, and
        # the record then raises TypeError when a handler formats it. Rendering
        # first also means a secret that only appears in an argument is
        # covered by every pattern, not just by exact-value matching.
        if record.args:
            try:
                record.msg = record.getMessage()
            except (TypeError, ValueError):  # pragma: no cover - malformed call
                record.msg = str(record.msg)
            record.args = ()
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        else:
            record.msg = redact(str(record.msg))
        # A traceback is the most common accidental leak: an exception message
        # routinely embeds the value that caused it. At filter time the
        # traceback still lives in ``exc_info`` - ``exc_text`` is only
        # populated later, by the formatter - so it is rendered here, redacted,
        # and cached in ``exc_text``. ``exc_info`` is then cleared so no
        # handler can re-render the unredacted original.
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = "".join(
                    traceback.format_exception(*record.exc_info)
                ).rstrip()
            record.exc_info = None
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True


_installed = False


def install(logger_name: str) -> None:
    """Install the redacting filter on the integration's logger.

    Attached to the logger itself rather than to a handler, because Home
    Assistant owns the handlers and a filter added there would affect every
    other integration's log records too.

    A logger's filters only apply to records emitted *on that logger*, not to
    records propagated up from children - which is why every module in this
    integration logs through ``logging.getLogger(LOGGER_NAME)`` rather than
    ``__name__``.
    """
    global _installed
    if _installed:
        return
    logging.getLogger(logger_name).addFilter(RedactingFilter())
    _installed = True
