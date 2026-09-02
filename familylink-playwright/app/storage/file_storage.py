"""File-based storage for cookies with authenticated encryption.

Fernet gives authenticated encryption (AES-CBC + HMAC), so a tampered
ciphertext is rejected rather than silently decrypted. What it does *not* give
is protection against anyone who can read the whole directory: the key lives
next to the ciphertext, because the add-on and the Home Assistant integration
have no other shared secret channel. Read access to ``/share/familylink``
therefore yields both halves, and the encryption only protects against a leak
of the cookie file alone (a backup, a snapshot, a stray copy). This is stated
plainly in the documentation rather than implied to be more.

The stored envelope carries the session lifetime, so ``session_duration`` is
enforced on read instead of being a documented setting that did nothing.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from cryptography.fernet import Fernet, InvalidToken

from app import cookies as cookie_rules
from app.security import TokenError, read_secret_file, write_secret_file

_LOGGER = logging.getLogger(__name__)

#: Envelope version. v1 had only an informational ``timestamp``; v2 records the
#: creation and expiry instants that ``session_duration`` is enforced against.
ENVELOPE_VERSION = 2


class CookiesExpired(Exception):
    """Raised when the stored session has outlived ``session_duration``."""


class CookiesCorrupted(Exception):
    """Raised when the stored session cannot be decrypted or parsed."""


class SharedStorage:
    """Manages cookie storage in Home Assistant shared directory."""

    def __init__(
        self,
        share_dir: str = "/share/familylink",
        session_duration: int = 86400,
        allowlist_mode: str = "strict",
    ):
        """Initialize storage manager."""
        self.share_dir = Path(share_dir)
        self.storage_path = self.share_dir / "cookies.enc"
        self.key_file = self.share_dir / ".key"
        self.session_duration = session_duration
        self.allowlist_mode = allowlist_mode

        # Ensure directory exists BEFORE generating the key file in it
        # - HA add-ons share /share via mapped volume
        self.share_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.share_dir, 0o700)

        self._encryption_key = self._get_encryption_key()

    def _get_encryption_key(self) -> bytes:
        """Get or create encryption key, refusing to follow a symlink."""
        existing = read_secret_file(self.key_file)
        if existing:
            return existing.encode("utf-8")

        key = Fernet.generate_key()
        write_secret_file(self.key_file, key.decode("utf-8"))
        _LOGGER.info("Generated new encryption key")
        return key

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def _write_encrypted(self, payload: bytes) -> None:
        """Atomically write the ciphertext with 0600, never via a symlink.

        The temporary file is created ``O_EXCL`` with mode 0600 in the target
        directory: an attacker cannot pre-create it, it is never briefly
        world-readable, and ``os.replace`` within one directory is atomic, so a
        crash mid-write leaves the previous session intact rather than a
        truncated file that would look like corruption.
        """
        self._assert_regular_file(self.storage_path)
        tmp_path = self.share_dir / f".cookies.enc.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(tmp_path, flags, 0o600)
        except FileExistsError:
            os.unlink(tmp_path)
            fd = os.open(tmp_path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.storage_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        os.chmod(self.storage_path, 0o600)

    @staticmethod
    def _assert_regular_file(path: Path) -> None:
        """Refuse to overwrite anything that is not a plain file."""
        try:
            st = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise TokenError(
                f"{path} is a symbolic link; refusing to write the cookie "
                "store through it"
            )
        if not stat.S_ISREG(st.st_mode):
            raise TokenError(f"{path} exists but is not a regular file")

    async def save_cookies(self, cookies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Minimise, stamp and save cookies to the encrypted store.

        Returns the metadata that was recorded, so callers can report the
        expiry without decrypting the file again.
        """
        minimised = cookie_rules.filter_cookies(cookies, self.allowlist_mode)
        if not minimised:
            raise ValueError(
                "No Family Link cookies remained after minimisation; refusing "
                "to store an unusable session"
            )

        now = time.time()
        metadata = {
            "created_at": now,
            "created_at_iso": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "expires_at": now + self.session_duration,
            "session_duration": self.session_duration,
        }
        data = {
            "cookies": minimised,
            "version": ENVELOPE_VERSION,
            # Kept for readers of the v1 envelope.
            "timestamp": metadata["created_at_iso"],
            **metadata,
        }

        try:
            fernet = Fernet(self._encryption_key)
            encrypted = fernet.encrypt(json.dumps(data).encode("utf-8"))
            self._write_encrypted(encrypted)
        except Exception as err:
            _LOGGER.error("Failed to save cookies: %s", err)
            raise

        _LOGGER.info(
            "Saved %d cookies (%s) to shared storage; session expires %s",
            len(minimised),
            ", ".join(cookie_rules.cookie_names(minimised)),
            datetime.fromtimestamp(metadata["expires_at"], timezone.utc).isoformat(),
        )
        return metadata

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def _read_envelope(self) -> Dict[str, Any]:
        """Decrypt and parse the store, or raise CookiesCorrupted."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.storage_path, flags)
        except FileNotFoundError:
            raise FileNotFoundError("No cookies found") from None
        except OSError as err:
            if err.errno in (errno.ELOOP, errno.EMLINK):
                raise CookiesCorrupted(
                    "The cookie store is a symbolic link; refusing to read it"
                ) from err
            raise
        with os.fdopen(fd, "rb") as handle:
            encrypted = handle.read()

        try:
            decrypted = Fernet(self._encryption_key).decrypt(encrypted)
            envelope = json.loads(decrypted.decode("utf-8"))
        except InvalidToken as err:
            raise CookiesCorrupted(
                "Cookie file is corrupted or the encryption key has changed"
            ) from err
        except (ValueError, UnicodeDecodeError) as err:
            raise CookiesCorrupted("Cookie file is not valid JSON") from err
        if not isinstance(envelope, dict):
            raise CookiesCorrupted("Cookie file has an unexpected structure")
        return envelope

    def _resolve_expiry(self, envelope: Dict[str, Any]) -> tuple[float, float]:
        """Return ``(created_at, expires_at)`` for any envelope version.

        A v1 envelope has only an ISO ``timestamp``; its expiry is derived from
        the currently configured ``session_duration``. An envelope whose
        timestamps are missing or unparseable is treated as expired rather than
        as eternally valid - the failure mode has to be re-authentication, not
        an unbounded session.
        """
        created_at = envelope.get("created_at")
        expires_at = envelope.get("expires_at")
        if isinstance(created_at, (int, float)) and isinstance(
            expires_at, (int, float)
        ):
            return float(created_at), float(expires_at)

        raw_timestamp = envelope.get("timestamp")
        if isinstance(raw_timestamp, str):
            try:
                parsed = datetime.fromisoformat(raw_timestamp)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                legacy_created = parsed.timestamp()
                _LOGGER.info(
                    "Upgrading a legacy cookie envelope: expiry derived from "
                    "its creation time and the configured session_duration"
                )
                return legacy_created, legacy_created + self.session_duration
            except (ValueError, OverflowError, OSError):
                pass

        _LOGGER.warning(
            "Stored session has no usable creation timestamp; treating it as "
            "expired so a fresh authentication is required"
        )
        return 0.0, 0.0

    async def load_cookies(self, now: float | None = None) -> List[Dict[str, Any]]:
        """Load cookies, enforcing the configured session lifetime.

        Raises:
            FileNotFoundError: nothing stored.
            CookiesExpired: the local session lifetime has elapsed. The store
                is deleted first, so an expired session cannot be replayed.
            CookiesCorrupted: undecryptable or unparseable; the store is
                deleted so the next authentication starts clean.
        """
        now = time.time() if now is None else now
        try:
            envelope = self._read_envelope()
        except CookiesCorrupted as err:
            _LOGGER.error("%s - deleting the store; please re-authenticate", err)
            await self.clear_cookies()
            raise

        _created_at, expires_at = self._resolve_expiry(envelope)
        if now >= expires_at:
            _LOGGER.warning(
                "Stored Google session reached its configured lifetime "
                "(session_duration=%ss) - deleting it and requiring "
                "re-authentication",
                self.session_duration,
            )
            await self.clear_cookies()
            raise CookiesExpired(
                "The stored Google session has expired. Re-authenticate with "
                "the Family Link Auth add-on."
            )

        raw = envelope.get("cookies") or []
        if not isinstance(raw, list):
            _LOGGER.error("Cookie store has an unexpected structure - deleting it")
            await self.clear_cookies()
            raise CookiesCorrupted("Cookie file has an unexpected structure")

        # Re-apply the allowlist on read as well, so a store written by an
        # older version is minimised before it leaves this process.
        cookies = cookie_rules.filter_cookies(raw, self.allowlist_mode)
        _LOGGER.info("Loaded %d cookies from shared storage", len(cookies))
        return cookies

    async def metadata(self, now: float | None = None) -> Dict[str, Any]:
        """Describe the stored session without returning any cookie value."""
        now = time.time() if now is None else now
        if not self.storage_path.exists():
            return {"exists": False, "expired": False, "reauth_required": True}
        try:
            envelope = self._read_envelope()
        except CookiesCorrupted:
            return {
                "exists": True,
                "expired": True,
                "corrupted": True,
                "reauth_required": True,
            }
        created_at, expires_at = self._resolve_expiry(envelope)
        expired = now >= expires_at
        return {
            "exists": True,
            "expired": expired,
            "reauth_required": expired,
            "created_at": created_at or None,
            "expires_at": expires_at or None,
            "expires_in": max(0, int(expires_at - now)) if expires_at else 0,
            "cookie_count": len(envelope.get("cookies") or []),
            "version": envelope.get("version", 1),
        }

    async def clear_cookies(self) -> None:
        """Remove the stored session."""
        removed = False
        try:
            self.storage_path.unlink()
            removed = True
        except FileNotFoundError:
            pass
        except OSError as err:
            _LOGGER.error("Could not delete the cookie store: %s", err.strerror)
            raise
        if removed:
            _LOGGER.info("Cleared stored cookies")

    async def check_exists(self, now: float | None = None) -> bool:
        """Whether a usable (non-expired) session is stored."""
        info = await self.metadata(now)
        return bool(info.get("exists")) and not info.get("expired")
