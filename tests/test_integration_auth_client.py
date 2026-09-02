"""Tests for the Home Assistant integration's auth client.

The focus is the migration path: an existing installation configured as
``http://host:8099?api_key=<key>`` has to keep working after the auth service
starts refusing credentials in the query string.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet

from custom_components.familylink import redact
from custom_components.familylink.auth.addon_client import (
    AddonCookieClient,
    CookiesExpiredError,
    split_legacy_auth_url,
)

LEGACY_KEY = "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY"


class FakeHass:
    """The slice of HomeAssistant this client actually uses."""

    async def async_add_executor_job(self, func, *args):
        return func(*args)


@pytest.fixture
def hass():
    return FakeHass()


@pytest.fixture(autouse=True)
def clean_secrets():
    redact.forget_secrets()
    yield
    redact.forget_secrets()


class TestLegacyUrlMigration:
    def test_splits_the_key_out_of_the_url(self):
        base, token = split_legacy_auth_url(f"http://host:8099?api_key={LEGACY_KEY}")

        assert base == "http://host:8099"
        assert token == LEGACY_KEY

    def test_a_clean_url_is_left_alone(self):
        base, token = split_legacy_auth_url("http://host:8099")

        assert base == "http://host:8099"
        assert token is None

    def test_a_trailing_slash_is_normalised(self):
        base, _ = split_legacy_auth_url("http://host:8099/")

        assert base == "http://host:8099"

    @pytest.mark.parametrize("param", ["api_key", "api_token", "token"])
    def test_every_historical_parameter_name_is_recognised(self, param):
        base, token = split_legacy_auth_url(f"http://host:8099?{param}=abc123")

        assert base == "http://host:8099"
        assert token == "abc123"

    def test_unrelated_query_parameters_do_not_become_a_token(self):
        base, token = split_legacy_auth_url("http://host:8099?debug=1")

        assert base == "http://host:8099"
        assert token is None

    def test_no_url_configured(self):
        assert split_legacy_auth_url(None) == (None, None)
        assert split_legacy_auth_url("") == (None, None)

    def test_the_client_migrates_a_legacy_url_on_construction(self, hass):
        client = AddonCookieClient(hass, auth_url=f"http://host:8099?api_key={LEGACY_KEY}")

        assert client.auth_url == "http://host:8099"
        assert client.api_token == LEGACY_KEY
        assert client.migrated_legacy_token is True

    def test_an_explicit_token_wins_over_one_in_the_url(self, hass):
        client = AddonCookieClient(
            hass,
            auth_url=f"http://host:8099?api_key={LEGACY_KEY}",
            api_token="explicit-token-value",
        )

        assert client.api_token == "explicit-token-value"
        assert client.migrated_legacy_token is False

    def test_the_stored_url_never_carries_the_credential(self, hass):
        client = AddonCookieClient(hass, auth_url=f"http://host:8099?api_key={LEGACY_KEY}")

        assert LEGACY_KEY not in client.auth_url

    def test_the_migrated_token_is_registered_for_redaction(self, hass):
        AddonCookieClient(hass, auth_url=f"http://host:8099?api_key={LEGACY_KEY}")

        assert LEGACY_KEY not in redact.redact(f"using {LEGACY_KEY}")


class TestTokenDiscovery:
    def test_the_token_is_read_from_the_shared_directory(self, hass, share_dir):
        (share_dir / "api_key").write_text("token-from-the-shared-directory\n")
        client = AddonCookieClient(hass)
        client.api_key_file = share_dir / "api_key"

        assert asyncio.run(client._get_api_token()) == (
            "token-from-the-shared-directory"
        )

    def test_a_configured_token_takes_precedence(self, hass, share_dir):
        (share_dir / "api_key").write_text("file-token")
        client = AddonCookieClient(hass, api_token="configured-token")
        client.api_key_file = share_dir / "api_key"

        assert asyncio.run(client._get_api_token()) == "configured-token"

    def test_a_missing_key_file_yields_no_token(self, hass, share_dir):
        client = AddonCookieClient(hass)
        client.api_key_file = share_dir / "absent"

        assert asyncio.run(client._get_api_token()) is None

    def test_an_empty_key_file_yields_no_token(self, hass, share_dir):
        (share_dir / "api_key").write_text("   \n")
        client = AddonCookieClient(hass)
        client.api_key_file = share_dir / "api_key"

        assert asyncio.run(client._get_api_token()) is None

    def test_a_discovered_token_is_registered_for_redaction(self, hass, share_dir):
        (share_dir / "api_key").write_text(LEGACY_KEY)
        client = AddonCookieClient(hass)
        client.api_key_file = share_dir / "api_key"

        asyncio.run(client._get_api_token())

        assert LEGACY_KEY not in redact.redact(f"token {LEGACY_KEY}")


class TestFileFallbackExpiry:
    """The file fallback must not outlive the service's own expiry check."""

    def _write_store(self, share_dir, envelope):
        key = Fernet.generate_key()
        (share_dir / ".key").write_bytes(key)
        (share_dir / "cookies.enc").write_bytes(
            Fernet(key).encrypt(json.dumps(envelope).encode())
        )

    def _client(self, hass, share_dir):
        client = AddonCookieClient(hass)
        client.storage_path = share_dir / "cookies.enc"
        client.key_file = share_dir / ".key"
        client.api_key_file = share_dir / "api_key"
        return client

    def test_a_live_session_loads(self, hass, share_dir):
        self._write_store(
            share_dir,
            {
                "cookies": [{"name": "SAPISID", "value": "v"}],
                "created_at": time.time(),
                "expires_at": time.time() + 3600,
            },
        )
        client = self._client(hass, share_dir)

        cookies = asyncio.run(client._load_cookies_from_file())

        assert cookies == [{"name": "SAPISID", "value": "v"}]

    def test_an_expired_session_is_refused(self, hass, share_dir):
        self._write_store(
            share_dir,
            {
                "cookies": [{"name": "SAPISID", "value": "v"}],
                "created_at": time.time() - 7200,
                "expires_at": time.time() - 3600,
            },
        )
        client = self._client(hass, share_dir)

        with pytest.raises(CookiesExpiredError):
            asyncio.run(client._load_cookies_from_file())

        assert client.reauth_required is True

    def test_a_legacy_envelope_without_expiry_still_loads(self, hass, share_dir):
        """v1 stores have no expires_at; the service enforces the lifetime."""
        self._write_store(
            share_dir,
            {
                "cookies": [{"name": "SAPISID", "value": "v"}],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": "1.0",
            },
        )
        client = self._client(hass, share_dir)

        assert asyncio.run(client._load_cookies_from_file()) is not None

    def test_a_corrupted_store_does_not_raise_out_of_the_fallback(
        self, hass, share_dir
    ):
        (share_dir / ".key").write_bytes(Fernet.generate_key())
        (share_dir / "cookies.enc").write_bytes(b"not a fernet token")
        client = self._client(hass, share_dir)

        assert asyncio.run(client._load_cookies_from_file()) is None

    def test_cookie_values_from_the_file_are_registered_for_redaction(
        self, hass, share_dir
    ):
        self._write_store(
            share_dir,
            {
                "cookies": [{"name": "SAPISID", "value": LEGACY_KEY}],
                "created_at": time.time(),
                "expires_at": time.time() + 3600,
            },
        )
        client = self._client(hass, share_dir)

        asyncio.run(client._load_cookies_from_file())

        assert LEGACY_KEY not in redact.redact(f"cookie {LEGACY_KEY}")


class TestNoCredentialsInLogs:
    def test_a_legacy_url_is_never_logged_with_its_credential(self, hass, caplog):
        logger = logging.getLogger("custom_components.familylink")
        logger.addFilter(redact.RedactingFilter())
        client = AddonCookieClient(hass, auth_url=f"http://host:8099?api_key={LEGACY_KEY}")

        with caplog.at_level(logging.DEBUG, logger="custom_components.familylink"):
            logger.warning(
                "Failed to load cookies from the configured auth URL %s",
                redact.redact_url(f"http://host:8099?api_key={LEGACY_KEY}"),
            )

        assert LEGACY_KEY not in caplog.text
        assert client.api_token == LEGACY_KEY

    def test_redact_url_strips_the_credential(self):
        result = redact.redact_url(f"http://host:8099/api/cookies?api_key={LEGACY_KEY}")

        assert result == "http://host:8099/api/cookies"
