"""Security primitives for the Family Link auth service.

One consistent authentication mechanism guards every endpoint except
``/api/health``:

* a **bearer token** presented in the ``X-API-Key`` header - used by the Home
  Assistant integration, and
* an **httpOnly session cookie** minted from that same token by
  ``POST /api/session`` - used by the browser UI, because a browser cannot
  attach custom headers to a WebSocket handshake (noVNC) and because putting
  the token in a URL would leak it through history, logs and ``Referer``.

The token is never accepted from a query string, never written to a log and
never embedded in a page.
"""
from __future__ import annotations

import errno
import hmac
import logging
import os
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

# Minimum entropy we accept for an operator-provided token. 16 characters of
# mixed input is already weak; anything shorter is refused outright rather than
# silently protecting nothing.
MIN_TOKEN_LENGTH = 16

# secrets.token_urlsafe(32) -> 43 characters, ~256 bits.
_GENERATED_TOKEN_BYTES = 32

API_KEY_FILENAME = "api_key"
SESSION_COOKIE_NAME = "familylink_session"

# A UI session is short-lived: long enough to complete a Google login and 2FA,
# short enough that a forgotten browser tab is not a standing credential.
SESSION_TTL_SECONDS = 3600


class TokenError(RuntimeError):
    """Raised when the API token cannot be generated, persisted or loaded.

    The service fails closed on this: an auth service that cannot establish its
    own credential must not start serving Google session cookies.
    """


def _assert_not_symlink(path: Path) -> None:
    """Refuse to follow a symlink planted where a secret file belongs."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise TokenError(
            f"{path} is a symbolic link; refusing to read or overwrite a "
            "secret through it"
        )
    if not stat.S_ISREG(st.st_mode):
        raise TokenError(f"{path} exists but is not a regular file")


def read_secret_file(path: Path) -> str | None:
    """Read a secret file without following symlinks. None when absent/empty."""
    _assert_not_symlink(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.EMLINK):
            raise TokenError(f"{path} is a symbolic link; refusing to read it") from err
        raise
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError as err:  # pragma: no cover - filesystem failure
        raise TokenError(f"Could not read {path}: {err.strerror}") from err


def write_secret_file(path: Path, content: str) -> None:
    """Atomically write a 0600 secret file, never through a symlink.

    The temporary file is created with ``O_EXCL`` and mode 0600 in the target
    directory, so the secret is never briefly world-readable and never lands on
    a different filesystem where ``os.replace`` would not be atomic.
    """
    _assert_not_symlink(path)
    directory = path.parent
    tmp_path = directory / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(tmp_path, flags, 0o600)
    except OSError as err:
        raise TokenError(
            f"Could not create a temporary file in {directory}: {err.strerror}"
        ) from err
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except OSError as err:
        raise TokenError(f"Could not write {path}: {err.strerror}") from err
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    try:
        os.chmod(path, 0o600)
    except OSError as err:  # pragma: no cover - filesystem failure
        raise TokenError(
            f"Could not set permissions on {path}: {err.strerror}"
        ) from err


def load_or_create_api_token(
    share_dir: str | os.PathLike,
    env_token: str | None = None,
) -> str:
    """Return the service's API token, generating and persisting one if needed.

    Fails closed by raising :class:`TokenError` - never returns ``None`` and
    never falls back to an unauthenticated service. This is deliberately the
    same code path for add-on and standalone installations so there is exactly
    one credential mechanism to reason about.
    """
    if env_token:
        token = env_token.strip()
        if len(token) < MIN_TOKEN_LENGTH:
            raise TokenError(
                "The configured API token is too short: at least "
                f"{MIN_TOKEN_LENGTH} characters are required. Generate one "
                "with `openssl rand -base64 32`."
            )
        return token

    directory = Path(share_dir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    except OSError as err:
        raise TokenError(
            f"Could not prepare the secret directory {directory}: {err.strerror}"
        ) from err

    key_path = directory / API_KEY_FILENAME
    existing = read_secret_file(key_path)
    if existing:
        if len(existing) < MIN_TOKEN_LENGTH:
            raise TokenError(
                f"The token stored in {key_path} is too short to be safe. "
                "Delete the file to have a new one generated."
            )
        try:
            os.chmod(key_path, 0o600)
        except OSError as err:  # pragma: no cover - filesystem failure
            raise TokenError(
                f"Could not tighten permissions on {key_path}: {err.strerror}"
            ) from err
        return existing

    token = secrets.token_urlsafe(_GENERATED_TOKEN_BYTES)
    write_secret_file(key_path, token)
    # Deliberately logs the path, never the value.
    _LOGGER.info("Generated a new API token and stored it at %s (mode 0600)", key_path)
    return token


def tokens_equal(candidate: str | None, expected: str) -> bool:
    """Constant-time token comparison that tolerates a missing candidate."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of a rate-limit check."""

    allowed: bool
    retry_after: int = 0


class RateLimiter:
    """Sliding-window limiter bounding authentication retries per client.

    Guessing the token is infeasible, but an unbounded retry loop is still a
    free CPU and log-noise amplifier, and a bounded limiter is what turns a
    brute-force attempt into an obvious, slow failure.
    """

    def __init__(self, max_attempts: int = 10, window_seconds: int = 60) -> None:
        self._max_attempts = max_attempts
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> list[float]:
        recent = [t for t in self._attempts.get(key, []) if now - t < self._window]
        if recent:
            self._attempts[key] = recent
        else:
            self._attempts.pop(key, None)
        return recent

    def check(self, key: str, now: float | None = None) -> RateLimitDecision:
        """Report whether ``key`` may attempt authentication right now."""
        now = time.monotonic() if now is None else now
        recent = self._prune(key, now)
        if len(recent) >= self._max_attempts:
            retry_after = max(1, int(self._window - (now - recent[0])) + 1)
            return RateLimitDecision(allowed=False, retry_after=retry_after)
        return RateLimitDecision(allowed=True)

    def record_failure(self, key: str, now: float | None = None) -> None:
        """Count a failed authentication attempt against ``key``."""
        now = time.monotonic() if now is None else now
        recent = self._prune(key, now)
        recent.append(now)
        self._attempts[key] = recent

    def reset(self, key: str) -> None:
        """Forget a client's failures after it authenticates successfully."""
        self._attempts.pop(key, None)


class SessionStore:
    """In-memory browser sessions minted from the API token.

    Sessions live only in this process: restarting the add-on invalidates every
    UI session, which is the desired behaviour for a credential that exists
    purely to carry a login flow.
    """

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, float] = {}

    def create(self, now: float | None = None) -> str:
        """Mint a new opaque session id."""
        now = time.time() if now is None else now
        self._purge(now)
        session_id = secrets.token_urlsafe(32)
        self._sessions[session_id] = now + self._ttl
        return session_id

    def is_valid(self, session_id: str | None, now: float | None = None) -> bool:
        """Return whether ``session_id`` is a live session."""
        if not session_id:
            return False
        now = time.time() if now is None else now
        self._purge(now)
        # Compare against every stored id with a constant-time primitive so a
        # timing side channel cannot confirm a guessed prefix.
        found = False
        for known, expires_at in self._sessions.items():
            if hmac.compare_digest(known, session_id) and expires_at > now:
                found = True
        return found

    def revoke(self, session_id: str | None) -> None:
        """Drop a single session."""
        if session_id:
            self._sessions.pop(session_id, None)

    def clear(self) -> None:
        """Drop every session."""
        self._sessions.clear()

    def _purge(self, now: float) -> None:
        expired = [
            sid for sid, expires_at in self._sessions.items() if expires_at <= now
        ]
        for sid in expired:
            del self._sessions[sid]
