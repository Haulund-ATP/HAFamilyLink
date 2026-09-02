"""Central log redaction for the Family Link auth service.

Everything this service handles is sensitive: Google session cookies, the
SAPISID value they are derived from, and the API token that guards them. Rather
than trusting every call site to remember that, a logging filter is installed on
the root logger and scrubs the record right before it is formatted.

Two mechanisms work together:

* **Pattern redaction** catches the shapes secrets take - ``Cookie:`` headers,
  ``api_key=`` query parameters, ``SAPISIDHASH`` values, ``X-API-Key``.
* **Exact-value redaction** catches everything else: values registered with
  :func:`register_secret` are replaced wherever they appear, so a cookie value
  cannot leak through a message shape nobody anticipated.
"""
from __future__ import annotations

import logging
import re
import traceback
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***REDACTED***"

# Query parameters that must never survive into a log line.
_SENSITIVE_QUERY_PARAMS = frozenset(
    {"api_key", "apikey", "api-key", "token", "access_token", "password", "pw", "key"}
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Credential-bearing query parameters, in a URL or on their own.
    (
        re.compile(
            r"(?i)\b(" + "|".join(_SENSITIVE_QUERY_PARAMS) + r")=[^\s&\"'#]+",
        ),
        r"\1=" + REDACTED,
    ),
    # Header-style secrets, however they are spelled.
    (
        re.compile(r"(?i)\b(x-api-key|authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+"),
        r"\1: " + REDACTED,
    ),
    # Google's SAPISIDHASH authorisation value and the cookies behind it.
    (re.compile(r"(?i)\bSAPISIDHASH\s+\S+"), "SAPISIDHASH " + REDACTED),
    (
        re.compile(
            r"(?i)\b(__Secure-\d+PSIDTS|__Secure-\d+PSID|__Secure-\d+PAPISID|"
            r"SAPISID|APISID|HSID|SSID|SIDCC|LSID|SID)\s*[:=]\s*[^\s;,\"']+"
        ),
        r"\1=" + REDACTED,
    ),
)

# Exact secret values registered at runtime (API token, cookie values).
# Short values are ignored: masking a 3-character string would redact ordinary
# words out of every log line without protecting anything meaningful.
_MIN_SECRET_LENGTH = 8
_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    """Register an exact value to scrub from every future log record."""
    if value and len(value) >= _MIN_SECRET_LENGTH:
        _secrets.add(value)


def forget_secrets() -> None:
    """Drop all registered secrets (used by tests and on cookie deletion)."""
    _secrets.clear()


def redact(text: str) -> str:
    """Return ``text`` with credentials and registered secrets masked."""
    if not text:
        return text
    for value in _secrets:
        if value in text:
            text = text.replace(value, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_url(url: str) -> str:
    """Return ``url`` with its query and fragment removed.

    Used wherever a URL reaches a log line. Dropping the whole query is
    deliberate: an allowlist of safe parameters would have to be maintained in
    step with every endpoint, and no logged URL in this service needs one.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    if not parts.query and not parts.fragment:
        return redact(url)
    return redact(urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))


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


def install(logger: logging.Logger | None = None) -> RedactingFilter:
    """Install the redacting filter on ``logger`` (root logger by default).

    The filter is attached to the handlers rather than the logger, because a
    filter on a logger is not consulted for records propagated from child
    loggers - and uvicorn, Playwright and this app all log through children.
    """
    target = logger if logger is not None else logging.getLogger()
    log_filter = RedactingFilter()
    for handler in target.handlers:
        handler.addFilter(log_filter)
    target.addFilter(log_filter)
    return log_filter
