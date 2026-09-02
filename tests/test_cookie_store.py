"""Cookie minimisation, lifetime enforcement and storage-safety tests."""
from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
import time

import pytest
from cryptography.fernet import Fernet

from app import cookies as cookie_rules
from app.storage.file_storage import (
    CookiesCorrupted,
    CookiesExpired,
    SharedStorage,
)

POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file modes are only meaningful on POSIX"
)


def google_cookie(name: str, domain: str = ".google.com", **extra):
    """A Playwright-shaped cookie dict."""
    return {
        "name": name,
        "value": f"value-of-{name}",
        "domain": domain,
        "path": "/",
        "expires": 2000000000,
        "httpOnly": True,
        "secure": True,
        "sameSite": "None",
        **extra,
    }


def full_session():
    """A realistic capture: Family Link cookies plus unrelated Google ones."""
    return [
        google_cookie("SID"),
        google_cookie("HSID"),
        google_cookie("SSID"),
        google_cookie("APISID"),
        google_cookie("SAPISID"),
        google_cookie("__Secure-1PSID"),
        google_cookie("__Secure-3PSIDTS"),
        # Unrelated to Family Link:
        google_cookie("NID"),
        google_cookie("SEARCH_SAMESITE"),
        google_cookie("AEC"),
        google_cookie("1P_JAR"),
        google_cookie("CONSENT"),
        google_cookie("OTZ"),
        google_cookie("VISITOR_INFO1_LIVE", domain=".youtube.com"),
        google_cookie("SID", domain=".google.com.au"),
    ]


class TestCookieAllowlist:
    def test_strict_mode_keeps_only_family_link_cookies(self):
        kept = cookie_rules.filter_cookies(full_session(), "strict")

        names = {c["name"] for c in kept}
        assert names == {
            "SID",
            "HSID",
            "SSID",
            "APISID",
            "SAPISID",
            "__Secure-1PSID",
            "__Secure-3PSIDTS",
        }

    def test_strict_mode_drops_unrelated_google_cookies(self):
        kept = cookie_rules.filter_cookies(full_session(), "strict")

        names = {c["name"] for c in kept}
        for unrelated in ("NID", "CONSENT", "1P_JAR", "AEC", "OTZ"):
            assert unrelated not in names

    def test_cookies_from_other_domains_are_dropped(self):
        kept = cookie_rules.filter_cookies(
            [google_cookie("SAPISID", domain=".youtube.com")], "strict"
        )

        assert kept == []

    def test_regional_google_domains_are_dropped(self):
        kept = cookie_rules.filter_cookies(
            [google_cookie("SID", domain=".google.com.au")], "strict"
        )

        assert kept == []

    def test_subdomains_of_allowed_hosts_are_kept(self):
        kept = cookie_rules.filter_cookies(
            [google_cookie("SAPISID", domain="accounts.google.com")], "strict"
        )

        assert len(kept) == 1

    def test_legacy_mode_is_the_documented_escape_hatch(self):
        kept = cookie_rules.filter_cookies(full_session(), "legacy")

        names = {c["name"] for c in kept}
        assert "NID" in names
        assert "CONSENT" in names
        # Even the escape hatch stays inside the domain allowlist.
        assert not any(c["domain"].endswith("youtube.com") for c in kept)

    def test_security_metadata_is_preserved(self):
        kept = cookie_rules.filter_cookies([google_cookie("SAPISID")], "strict")

        cookie = kept[0]
        assert cookie["secure"] is True
        assert cookie["httpOnly"] is True
        assert cookie["sameSite"] == "None"
        assert cookie["expires"] == 2000000000

    def test_unknown_metadata_is_not_carried_along(self):
        kept = cookie_rules.filter_cookies(
            [google_cookie("SAPISID", session=True, priority="High")], "strict"
        )

        assert "priority" not in kept[0]
        assert "session" not in kept[0]

    def test_valueless_cookies_are_ignored(self):
        kept = cookie_rules.filter_cookies(
            [{"name": "SAPISID", "value": "", "domain": ".google.com"}], "strict"
        )

        assert kept == []

    def test_missing_core_cookies_are_warned_about(self, caplog):
        with caplog.at_level("WARNING"):
            cookie_rules.filter_cookies([google_cookie("HSID")], "strict")

        assert "core cookie" in caplog.text
        assert "SAPISID" in caplog.text

    def test_no_cookie_value_is_ever_logged(self, caplog):
        with caplog.at_level("DEBUG"):
            cookie_rules.filter_cookies(full_session(), "strict")

        for cookie in full_session():
            assert cookie["value"] not in caplog.text

    def test_scrub_drops_values(self):
        cookies = [google_cookie("SAPISID")]
        cookie_rules.scrub(cookies)

        assert cookies[0]["value"] == ""


class TestCookieLifetime:
    def test_saved_session_records_creation_and_expiry(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)

        metadata = asyncio.run(storage.save_cookies(full_session()))

        assert metadata["expires_at"] == pytest.approx(
            metadata["created_at"] + 3600, abs=1
        )

    def test_session_within_its_lifetime_loads(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        cookies = asyncio.run(storage.load_cookies(now=time.time() + 3000))

        assert {c["name"] for c in cookies} >= {"SAPISID", "SID"}

    def test_expired_session_is_refused(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        with pytest.raises(CookiesExpired):
            asyncio.run(storage.load_cookies(now=time.time() + 3601))

    def test_expired_session_is_deleted_not_just_refused(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        with pytest.raises(CookiesExpired):
            asyncio.run(storage.load_cookies(now=time.time() + 7200))

        assert not storage.storage_path.exists()

    def test_clock_boundary_exactly_at_expiry_is_expired(self, share_dir):
        """At expires_at the session is over: the check is >=, not >."""
        storage = SharedStorage(str(share_dir), session_duration=3600)
        metadata = asyncio.run(storage.save_cookies(full_session()))

        with pytest.raises(CookiesExpired):
            asyncio.run(storage.load_cookies(now=metadata["expires_at"]))

    def test_one_second_before_expiry_still_loads(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        metadata = asyncio.run(storage.save_cookies(full_session()))

        cookies = asyncio.run(
            storage.load_cookies(now=metadata["expires_at"] - 1)
        )

        assert cookies

    def test_metadata_reports_expiry_without_returning_cookies(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        info = asyncio.run(storage.metadata())

        assert info["exists"] is True
        assert info["expired"] is False
        assert info["expires_in"] > 0
        assert "cookies" not in info

    def test_metadata_reports_an_expired_session(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        info = asyncio.run(storage.metadata(now=time.time() + 7200))

        assert info["expired"] is True
        assert info["reauth_required"] is True

    def test_check_exists_is_false_for_an_expired_session(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        assert asyncio.run(storage.check_exists(now=time.time() + 7200)) is False

    def test_refuses_to_store_a_session_with_nothing_usable(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)

        with pytest.raises(ValueError):
            asyncio.run(
                storage.save_cookies([google_cookie("NID", domain=".youtube.com")])
            )


class TestLegacyAndCorruptedEnvelopes:
    def _write_envelope(self, storage: SharedStorage, payload: dict) -> None:
        encrypted = Fernet(storage._encryption_key).encrypt(
            json.dumps(payload).encode()
        )
        storage.storage_path.write_bytes(encrypted)

    def test_v1_envelope_expiry_is_derived_from_its_timestamp(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        self._write_envelope(
            storage,
            {
                "cookies": [google_cookie("SAPISID"), google_cookie("SID")],
                "version": "1.0",
                "timestamp": "2020-01-01T00:00:00+00:00",
            },
        )

        with pytest.raises(CookiesExpired):
            asyncio.run(storage.load_cookies())

    def test_recent_v1_envelope_still_loads(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=86400)
        from datetime import datetime, timezone

        self._write_envelope(
            storage,
            {
                "cookies": [google_cookie("SAPISID"), google_cookie("SID")],
                "version": "1.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

        cookies = asyncio.run(storage.load_cookies())

        assert {c["name"] for c in cookies} == {"SAPISID", "SID"}

    def test_envelope_without_any_timestamp_is_treated_as_expired(self, share_dir):
        """Fail closed: an undatable session must not live forever."""
        storage = SharedStorage(str(share_dir), session_duration=3600)
        self._write_envelope(storage, {"cookies": [google_cookie("SAPISID")]})

        with pytest.raises(CookiesExpired):
            asyncio.run(storage.load_cookies())

    def test_unparseable_timestamp_is_treated_as_expired(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        self._write_envelope(
            storage,
            {"cookies": [google_cookie("SAPISID")], "timestamp": "not-a-date"},
        )

        with pytest.raises(CookiesExpired):
            asyncio.run(storage.load_cookies())

    def test_corrupted_ciphertext_is_reported_and_deleted(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))
        storage.storage_path.write_bytes(b"this is not a Fernet token")

        with pytest.raises(CookiesCorrupted):
            asyncio.run(storage.load_cookies())

        assert not storage.storage_path.exists()

    def test_envelope_with_a_wrong_shape_is_deleted(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        self._write_envelope(
            storage, {"cookies": "not-a-list", "created_at": time.time(),
                      "expires_at": time.time() + 3600}
        )

        with pytest.raises(CookiesCorrupted):
            asyncio.run(storage.load_cookies())

        assert not storage.storage_path.exists()

    def test_metadata_flags_a_corrupted_store(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        storage.storage_path.write_bytes(b"garbage")

        info = asyncio.run(storage.metadata())

        assert info["corrupted"] is True
        assert info["reauth_required"] is True

    def test_a_store_written_before_the_allowlist_is_minimised_on_read(
        self, share_dir
    ):
        storage = SharedStorage(str(share_dir), session_duration=86400)
        self._write_envelope(
            storage,
            {
                "cookies": full_session(),
                "created_at": time.time(),
                "expires_at": time.time() + 86400,
                "version": 2,
            },
        )

        cookies = asyncio.run(storage.load_cookies())

        assert "NID" not in {c["name"] for c in cookies}


class TestStorageFileSafety:
    @POSIX_ONLY
    def test_cookie_file_is_owner_only(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        assert stat.S_IMODE(storage.storage_path.stat().st_mode) == 0o600

    @POSIX_ONLY
    def test_key_file_is_owner_only(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)

        assert stat.S_IMODE(storage.key_file.stat().st_mode) == 0o600

    @POSIX_ONLY
    def test_directory_is_owner_only(self, share_dir):
        SharedStorage(str(share_dir), session_duration=3600)

        assert stat.S_IMODE(share_dir.stat().st_mode) == 0o700

    def test_write_leaves_no_temporary_file_behind(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        temp_files = [p.name for p in share_dir.iterdir() if ".tmp" in p.name]
        assert temp_files == []

    def test_overwrite_replaces_the_previous_session(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))
        first = storage.storage_path.read_bytes()

        asyncio.run(storage.save_cookies(full_session()))

        assert storage.storage_path.read_bytes() != first
        assert asyncio.run(storage.load_cookies())

    @pytest.mark.skipif(
        not hasattr(os, "symlink") or sys.platform == "win32",
        reason="requires POSIX symlinks",
    )
    def test_refuses_to_write_the_store_through_a_symlink(self, share_dir, tmp_path):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        victim = tmp_path / "victim"
        victim.write_text("original")
        storage.storage_path.symlink_to(victim)

        with pytest.raises(Exception):
            asyncio.run(storage.save_cookies(full_session()))

        assert victim.read_text() == "original"

    def test_clear_removes_the_store(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        asyncio.run(storage.clear_cookies())

        assert not storage.storage_path.exists()
        assert asyncio.run(storage.check_exists()) is False

    def test_clear_on_an_empty_store_is_not_an_error(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)

        asyncio.run(storage.clear_cookies())

    def test_missing_store_raises_file_not_found(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)

        with pytest.raises(FileNotFoundError):
            asyncio.run(storage.load_cookies())

    def test_stored_bytes_are_not_plaintext(self, share_dir):
        storage = SharedStorage(str(share_dir), session_duration=3600)
        asyncio.run(storage.save_cookies(full_session()))

        raw = storage.storage_path.read_bytes()

        assert b"SAPISID" not in raw
        assert b"value-of-SAPISID" not in raw
