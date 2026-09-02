"""Configuration validation for the auth service.

The standalone container has no Supervisor to validate its options, so the
bounds documented in the add-on schema have to be enforced in the application
as well - otherwise ``SESSION_DURATION=0`` would silently disable the cookie
lifetime the add-on promises to enforce.
"""
from __future__ import annotations

import pytest

from app.config import (
    MAX_AUTH_TIMEOUT,
    MAX_SESSION_DURATION,
    MIN_AUTH_TIMEOUT,
    MIN_SESSION_DURATION,
    get_config,
)

ENV_VARS = (
    "LOG_LEVEL",
    "AUTH_TIMEOUT",
    "SESSION_DURATION",
    "LANGUAGE",
    "TIMEZONE",
    "ADDON_MODE",
    "SUPERVISOR_TOKEN",
    "INGRESS_TRUSTED",
    "API_TOKEN",
    "API_KEY",
    "COOKIE_ALLOWLIST_MODE",
    "SHARE_DIR",
)


@pytest.fixture
def clean_env(monkeypatch):
    """A process environment with none of the service's variables set."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class TestSessionDuration:
    def test_default(self, clean_env):
        assert get_config().session_duration == 86400

    def test_valid_value_is_honoured(self, clean_env):
        clean_env.setenv("SESSION_DURATION", "7200")

        assert get_config().session_duration == 7200

    def test_zero_is_raised_to_the_minimum(self, clean_env):
        """A session lifetime of zero would break every install; refuse it."""
        clean_env.setenv("SESSION_DURATION", "0")

        assert get_config().session_duration == MIN_SESSION_DURATION

    def test_absurdly_large_value_is_capped(self, clean_env):
        clean_env.setenv("SESSION_DURATION", "999999999")

        assert get_config().session_duration == MAX_SESSION_DURATION

    def test_negative_value_is_raised_to_the_minimum(self, clean_env):
        clean_env.setenv("SESSION_DURATION", "-1")

        assert get_config().session_duration == MIN_SESSION_DURATION

    def test_garbage_falls_back_to_the_default(self, clean_env):
        clean_env.setenv("SESSION_DURATION", "forever")

        assert get_config().session_duration == 86400


class TestAuthTimeout:
    def test_bounds_are_enforced(self, clean_env):
        clean_env.setenv("AUTH_TIMEOUT", "1")
        assert get_config().auth_timeout == MIN_AUTH_TIMEOUT

        clean_env.setenv("AUTH_TIMEOUT", "99999")
        assert get_config().auth_timeout == MAX_AUTH_TIMEOUT


class TestCookieAllowlistMode:
    def test_defaults_to_strict(self, clean_env):
        assert get_config().cookie_allowlist_mode == "strict"

    def test_legacy_is_accepted(self, clean_env):
        clean_env.setenv("COOKIE_ALLOWLIST_MODE", "legacy")

        assert get_config().cookie_allowlist_mode == "legacy"

    def test_unknown_mode_falls_back_to_strict(self, clean_env):
        """Fail closed: an unrecognised mode must not widen what is stored."""
        clean_env.setenv("COOKIE_ALLOWLIST_MODE", "everything")

        assert get_config().cookie_allowlist_mode == "strict"

    def test_case_and_whitespace_are_tolerated(self, clean_env):
        clean_env.setenv("COOKIE_ALLOWLIST_MODE", " LEGACY ")

        assert get_config().cookie_allowlist_mode == "legacy"


class TestDeploymentMode:
    def test_standalone_is_the_default(self, clean_env):
        config = get_config()

        assert config.addon_mode is False
        assert config.ingress_trusted is False

    def test_supervisor_token_marks_an_addon_run(self, clean_env):
        clean_env.setenv("SUPERVISOR_TOKEN", "supervisor-provided")

        assert get_config().addon_mode is True

    def test_addon_mode_flag_marks_an_addon_run(self, clean_env):
        clean_env.setenv("ADDON_MODE", "1")

        assert get_config().addon_mode is True

    def test_ingress_trust_is_opt_in(self, clean_env):
        clean_env.setenv("INGRESS_TRUSTED", "1")

        assert get_config().ingress_trusted is True

    def test_ingress_trust_is_off_when_the_port_is_published(self, clean_env):
        """run.sh exports 0 whenever a host port mapping exists."""
        clean_env.setenv("INGRESS_TRUSTED", "0")

        assert get_config().ingress_trusted is False


class TestTokenSource:
    def test_no_token_configured(self, clean_env):
        assert get_config().api_token == ""

    def test_api_token_is_read(self, clean_env):
        clean_env.setenv("API_TOKEN", "x" * 32)

        assert get_config().api_token == "x" * 32

    def test_legacy_api_key_variable_is_still_supported(self, clean_env):
        clean_env.setenv("API_KEY", "y" * 32)

        assert get_config().api_token == "y" * 32

    def test_api_token_wins_over_the_legacy_name(self, clean_env):
        clean_env.setenv("API_KEY", "y" * 32)
        clean_env.setenv("API_TOKEN", "z" * 32)

        assert get_config().api_token == "z" * 32
