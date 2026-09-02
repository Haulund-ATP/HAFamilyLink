"""Tests proving that secrets and child data do not reach log output.

Both redaction modules are covered: the add-on service's (``app.redaction``)
and the integration's (``custom_components.familylink.redact``), which also
handles child names, account ids and coordinates.
"""
from __future__ import annotations

import logging

import pytest

from app import redaction as addon_redaction
from custom_components.familylink import redact as ha_redact

REAL_SAPISID = "ZmFrZS1zYXBpc2lkLXZhbHVlLWZvci10ZXN0aW5n"
REAL_TOKEN = "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY"


@pytest.fixture(autouse=True)
def clean_registries():
    """Each test starts with an empty secret registry."""
    addon_redaction.forget_secrets()
    ha_redact.forget_secrets()
    yield
    addon_redaction.forget_secrets()
    ha_redact.forget_secrets()


class TestAddonRedaction:
    def test_registered_secret_is_masked(self):
        addon_redaction.register_secret(REAL_TOKEN)

        assert REAL_TOKEN not in addon_redaction.redact(
            f"presented token {REAL_TOKEN} for /api/cookies"
        )

    def test_api_key_query_parameter_is_masked(self):
        result = addon_redaction.redact("GET /api/cookies?api_key=hunter2secret")

        assert "hunter2secret" not in result
        assert addon_redaction.REDACTED in result

    def test_cookie_header_is_masked(self):
        result = addon_redaction.redact(f"Cookie: SAPISID={REAL_SAPISID}; SID=abc")

        assert REAL_SAPISID not in result

    def test_x_api_key_header_is_masked(self):
        result = addon_redaction.redact(f"X-API-Key: {REAL_TOKEN}")

        assert REAL_TOKEN not in result

    def test_sapisidhash_authorisation_is_masked(self):
        result = addon_redaction.redact(
            "Authorization: SAPISIDHASH 1700000000_deadbeefdeadbeefdeadbeef"
        )

        assert "deadbeef" not in result

    def test_named_google_cookies_are_masked(self):
        for name in ("SAPISID", "HSID", "SSID", "APISID", "__Secure-1PSID"):
            result = addon_redaction.redact(f"{name}={REAL_SAPISID}")
            assert REAL_SAPISID not in result, name

    def test_url_query_is_dropped(self):
        result = addon_redaction.redact_url(
            "http://host:8099/api/cookies?api_key=hunter2&x=1"
        )

        assert result == "http://host:8099/api/cookies"

    def test_short_values_are_not_registered(self):
        """Masking a 3-character string would redact ordinary words."""
        addon_redaction.register_secret("abc")

        assert addon_redaction.redact("abc def") == "abc def"

    def test_filter_scrubs_a_real_log_record(self, caplog):
        logger = logging.getLogger("familylink-test-addon")
        logger.propagate = True
        addon_redaction.register_secret(REAL_TOKEN)
        logger.addFilter(addon_redaction.RedactingFilter())

        with caplog.at_level(logging.INFO, logger="familylink-test-addon"):
            logger.info("token=%s", REAL_TOKEN)
            logger.info(f"inline {REAL_TOKEN}")

        assert REAL_TOKEN not in caplog.text

    def test_filter_scrubs_exception_text(self, caplog):
        logger = logging.getLogger("familylink-test-addon-exc")
        addon_redaction.register_secret(REAL_TOKEN)
        logger.addFilter(addon_redaction.RedactingFilter())

        with caplog.at_level(logging.ERROR, logger="familylink-test-addon-exc"):
            try:
                raise RuntimeError(f"failed with {REAL_TOKEN}")
            except RuntimeError:
                logger.exception("boom")

        assert REAL_TOKEN not in caplog.text


class TestIntegrationRedaction:
    def test_coordinates_in_a_tuple_are_masked(self):
        result = ha_redact.redact("Refreshed location: (55.676098, 12.568337)")

        assert "55.676098" not in result
        assert "12.568337" not in result

    def test_named_coordinates_are_masked(self):
        result = ha_redact.redact("latitude=55.676098 longitude=12.568337")

        assert "55.676098" not in result
        assert "12.568337" not in result

    def test_child_name_is_masked_once_registered(self):
        ha_redact.register_identifier("Ingrid")

        result = ha_redact.redact("Creating sensors for Ingrid")

        assert "Ingrid" not in result

    def test_child_name_is_masked_with_possessive(self):
        ha_redact.register_identifier("Ingrid")

        result = ha_redact.redact("Creating buttons for Ingrid's devices")

        assert "Ingrid" not in result

    def test_account_id_is_masked(self):
        ha_redact.register_identifier("117445566778899001122")

        result = ha_redact.redact("Enabling daily limit for 117445566778899001122")

        assert "117445566778899001122" not in result

    def test_registering_children_covers_names_and_ids(self):
        ha_redact.register_children(
            [{"id": "117445566778899001122", "name": "Ingrid"}]
        )

        result = ha_redact.redact("child Ingrid (117445566778899001122)")

        assert "Ingrid" not in result
        assert "117445566778899001122" not in result

    def test_a_registered_name_does_not_mangle_unrelated_words(self):
        """Word boundaries: 'Max' must not redact the middle of 'maximum'."""
        ha_redact.register_identifier("Max")

        assert "maximum" in ha_redact.redact("reached the maximum")

    def test_google_response_body_is_redacted_and_truncated(self):
        body = (
            '[[null,"1700000000"],["117445566778899001122",1,'
            '[[55.676098,12.568337],1700000000,12,null,'
            '["place-id","Home","Rådhuspladsen 1, København"]]]]'
        )

        result = ha_redact.redact_response(body, limit=60)

        assert "55.676098" not in result
        assert "truncated" in result
        assert len(result) < len(body) + 60

    def test_empty_response_body(self):
        assert ha_redact.redact_response(None) == "<empty>"
        assert ha_redact.redact_response("") == "<empty>"

    def test_cookie_values_are_registered_from_a_cookie_list(self):
        ha_redact.register_cookie_secrets(
            [{"name": "SAPISID", "value": REAL_SAPISID}]
        )

        assert REAL_SAPISID not in ha_redact.redact(f"header {REAL_SAPISID}")

    def test_config_mapping_is_redacted(self):
        result = ha_redact.redact_mapping(
            {
                "auth_url": "http://host:8099",
                "api_token": REAL_TOKEN,
                "update_interval": 60,
                "nested": {"latitude": 55.6, "name": "ok"},
            }
        )

        assert result["api_token"] == ha_redact.REDACTED
        assert result["auth_url"] == ha_redact.REDACTED
        assert result["update_interval"] == 60
        assert result["nested"]["latitude"] == ha_redact.REDACTED

    def test_api_token_is_masked_in_a_url(self):
        result = ha_redact.redact_url(f"http://host:8099?api_key={REAL_TOKEN}")

        assert REAL_TOKEN not in result

    def test_filter_scrubs_location_from_a_real_log_record(self, caplog):
        logger = logging.getLogger("familylink-test-ha")
        logger.addFilter(ha_redact.RedactingFilter())
        ha_redact.register_children([{"id": "117445566778899001122", "name": "Ingrid"}])

        with caplog.at_level(logging.INFO, logger="familylink-test-ha"):
            logger.info(
                "Successfully refreshed location for Ingrid: (55.676098, 12.568337)"
            )

        assert "Ingrid" not in caplog.text
        assert "55.676098" not in caplog.text
        assert "117445566778899001122" not in caplog.text
