"""Config flow for Google Family Link integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .const import (
	CONF_API_TOKEN,
	CONF_AUTH_URL,
	CONF_ENABLE_LOCATION_TRACKING,
	CONF_TIMEOUT,
	CONF_UPDATE_INTERVAL,
	DEFAULT_TIMEOUT,
	DEFAULT_UPDATE_INTERVAL,
	DOMAIN,
	INTEGRATION_NAME,
	LOGGER_NAME,
)
from .exceptions import AuthenticationError

_LOGGER = logging.getLogger(LOGGER_NAME)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
	"""Validate the user input allows us to connect."""
	from .auth.addon_client import AddonCookieClient, CookiesExpiredError

	auth_url = data.get(CONF_AUTH_URL)
	api_token = data.get(CONF_API_TOKEN)

	try:
		addon_client = AddonCookieClient(hass, auth_url=auth_url, api_token=api_token)

		cookies = await addon_client.load_cookies()

		if not cookies:
			raise AuthenticationError(
				"No cookies found. Please authenticate first using the Family Link Auth add-on or container."
			)

		# Deliberately does not return the cookies: they are re-read from the
		# auth service on every setup, and putting a live Google session into
		# the config entry would persist it in .storage in clear text.
		return {
			"title": data.get(CONF_NAME, INTEGRATION_NAME),
			"cookie_count": len(cookies),
		}

	except CookiesExpiredError as err:
		_LOGGER.warning("Stored session has expired: %s", err)
		raise SessionExpired from err
	except AuthenticationError as err:
		_LOGGER.error("Authentication failed: %s", err)
		raise InvalidAuth from err
	except Exception as err:
		_LOGGER.exception("Unexpected error during validation")
		raise CannotConnect from err


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
	"""Handle a config flow for Google Family Link."""

	# Version 2 moved the auth-service token out of the URL into its own
	# field; see async_migrate_entry in __init__.py.
	VERSION = 2

	def __init__(self) -> None:
		"""Initialize config flow."""
		self._detected_source: str | None = None
		self._detected_url: str | None = None
		self._api_token: str | None = None

	@staticmethod
	def async_get_options_flow(
		config_entry: config_entries.ConfigEntry,
	) -> config_entries.OptionsFlow:
		"""Get the options flow for this handler."""
		return OptionsFlowHandler()

	async def async_step_user(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Handle the initial step - present a menu to choose how to connect."""
		from .auth.addon_client import AddonCookieClient

		# Detect available auth source (only used as a hint for the "auto" branch)
		addon_client = AddonCookieClient(self.hass)
		source_type, detected_url = await addon_client.detect_auth_source()

		self._detected_source = source_type
		self._detected_url = detected_url

		_LOGGER.debug("Detected auth source: %s, URL: %s", source_type, detected_url)

		# Always let the user choose between auto-detection and manual URL.
		# This is critical for Docker standalone setups where localhost-based
		# detection cannot reach the auth container running on another host.
		return self.async_show_menu(
			step_id="user",
			menu_options=["auto_detect", "manual_url"],
		)

	async def async_step_auto_detect(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Use the auto-detected authentication source."""
		if self._detected_source == "none":
			# Nothing was detected, fall back to the manual URL form
			return await self.async_step_manual_url()
		return await self.async_step_configure(user_input)

	async def async_step_manual_url(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Handle manual URL configuration for Docker standalone."""
		errors: dict[str, str] = {}

		if user_input is not None:
			from .auth.addon_client import AddonCookieClient, CookiesExpiredError

			auth_url = user_input.get(CONF_AUTH_URL, "").strip()
			api_token = (user_input.get(CONF_API_TOKEN) or "").strip()

			if not auth_url:
				errors["base"] = "url_required"
			elif "?" in auth_url and not api_token:
				# Migrate a pasted legacy URL rather than rejecting it: the
				# token moves to its own field and is sent as a header.
				client = AddonCookieClient(self.hass, auth_url=auth_url)
				auth_url = client.auth_url or auth_url
				api_token = client.api_token or ""
				_LOGGER.info(
					"Moved the API token out of the pasted URL into the "
					"dedicated token field"
				)

			if not errors:
				addon_client = AddonCookieClient(
					self.hass, auth_url=auth_url, api_token=api_token or None
				)
				base_url = addon_client.auth_url or auth_url

				if not await addon_client._check_url_available(base_url):
					errors["base"] = "cannot_connect"
				elif not await addon_client.check_token(base_url):
					errors["base"] = "invalid_api_key"
				else:
					try:
						cookies = await addon_client._fetch_cookies_from_url(base_url)
					except CookiesExpiredError:
						errors["base"] = "session_expired"
					else:
						if cookies:
							self._detected_url = base_url
							self._api_token = api_token or None
							return await self.async_step_configure(
								None, auth_url=base_url, api_token=api_token or None
							)
						errors["base"] = "no_cookies"

		# Show URL input form. The token is a separate, masked field: it must
		# never be appended to the URL.
		return self.async_show_form(
			step_id="manual_url",
			data_schema=vol.Schema({
				vol.Required(CONF_AUTH_URL, default="http://192.168.1.x:8099"): str,
				vol.Optional(CONF_API_TOKEN, default=""): str,
			}),
			errors=errors,
			description_placeholders={
				"default_url": "http://localhost:8099",
			},
		)

	async def async_step_configure(
		self,
		user_input: dict[str, Any] | None = None,
		auth_url: str | None = None,
		api_token: str | None = None,
	) -> FlowResult:
		"""Handle configuration step."""
		errors: dict[str, str] = {}

		# Use passed values or the ones remembered from an earlier step
		if auth_url is None:
			auth_url = self._detected_url
		if api_token is None:
			api_token = self._api_token

		if user_input is not None:
			if auth_url:
				user_input[CONF_AUTH_URL] = auth_url
			if api_token:
				user_input[CONF_API_TOKEN] = api_token

			try:
				info = await validate_input(self.hass, user_input)
				# Prevent duplicate entries for the same auth source
				unique_id = auth_url or "familylink_default"
				await self.async_set_unique_id(unique_id)
				self._abort_if_unique_id_configured()
				return self.async_create_entry(title=info["title"], data=user_input)

			except CannotConnect:
				errors["base"] = "cannot_connect"
			except SessionExpired:
				errors["base"] = "session_expired"
			except InvalidAuth:
				errors["base"] = "invalid_auth"
			except Exception:
				_LOGGER.exception("Unexpected exception")
				errors["base"] = "unknown"

		# Build schema
		schema = vol.Schema({
			vol.Required(CONF_NAME, default=INTEGRATION_NAME): str,
			vol.Optional(CONF_UPDATE_INTERVAL, default=DEFAULT_UPDATE_INTERVAL): vol.All(
				vol.Coerce(int), vol.Range(min=30, max=3600)
			),
			vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): vol.All(
				vol.Coerce(int), vol.Range(min=10, max=120)
			),
			vol.Optional(CONF_ENABLE_LOCATION_TRACKING, default=False): bool,
		})

		# Add description about detected source. The URL is shown without any
		# query string so a legacy credential cannot be displayed back.
		description_placeholders = {}
		if self._detected_source == "api":
			description_placeholders["auth_source"] = f"API ({self._detected_url})"
		elif self._detected_source == "file":
			description_placeholders["auth_source"] = "Local file (/share/familylink/)"
		else:
			description_placeholders["auth_source"] = auth_url or "Manual URL"

		return self.async_show_form(
			step_id="configure",
			data_schema=schema,
			errors=errors,
			description_placeholders=description_placeholders,
		)

	async def async_step_reauth(
		self, entry_data: dict[str, Any]
	) -> FlowResult:
		"""Handle re-authentication after the stored session expired."""
		return await self.async_step_reauth_confirm()

	async def async_step_reauth_confirm(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Confirm that the user has re-authenticated with the add-on."""
		errors: dict[str, str] = {}
		entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])

		if user_input is not None and entry is not None:
			data = dict(entry.data)
			token = (user_input.get(CONF_API_TOKEN) or "").strip()
			if token:
				data[CONF_API_TOKEN] = token
			try:
				await validate_input(self.hass, data)
			except SessionExpired:
				errors["base"] = "session_expired"
			except InvalidAuth:
				errors["base"] = "invalid_auth"
			except CannotConnect:
				errors["base"] = "cannot_connect"
			else:
				self.hass.config_entries.async_update_entry(entry, data=data)
				await self.hass.config_entries.async_reload(entry.entry_id)
				return self.async_abort(reason="reauth_successful")

		return self.async_show_form(
			step_id="reauth_confirm",
			data_schema=vol.Schema({
				vol.Optional(CONF_API_TOKEN, default=""): str,
			}),
			errors=errors,
		)

	async def async_step_import(self, import_info: dict[str, Any]) -> FlowResult:
		"""Handle import from configuration.yaml."""
		await self.async_set_unique_id(DOMAIN)
		self._abort_if_unique_id_configured()

		try:
			info = await validate_input(self.hass, import_info)
			return self.async_create_entry(title=info["title"], data=import_info)
		except (CannotConnect, InvalidAuth, SessionExpired):
			return self.async_abort(reason="invalid_config")


class CannotConnect(HomeAssistantError):
	"""Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
	"""Error to indicate there is invalid auth."""


class SessionExpired(HomeAssistantError):
	"""Error to indicate the stored Google session has expired."""


class OptionsFlowHandler(config_entries.OptionsFlow):
	"""Handle options flow for Family Link."""

	async def async_step_init(
		self, user_input: dict[str, Any] | None = None
	) -> FlowResult:
		"""Manage the options."""
		if user_input is not None:
			# An empty token field means "keep the stored one" rather than
			# "clear it", so the secret does not have to be retyped to change
			# an unrelated option.
			if not (user_input.get(CONF_API_TOKEN) or "").strip():
				user_input.pop(CONF_API_TOKEN, None)
			return self.async_create_entry(title="", data=user_input)

		# Get current values from config entry data (options first, then data)
		current_options = self.config_entry.options
		current_data = self.config_entry.data

		return self.async_show_form(
			step_id="init",
			data_schema=vol.Schema({
				vol.Optional(
					CONF_UPDATE_INTERVAL,
					default=current_options.get(
						CONF_UPDATE_INTERVAL,
						current_data.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)
					),
				): vol.All(vol.Coerce(int), vol.Range(min=30, max=3600)),
				vol.Optional(
					CONF_TIMEOUT,
					default=current_options.get(
						CONF_TIMEOUT,
						current_data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT)
					),
				): vol.All(vol.Coerce(int), vol.Range(min=10, max=120)),
				vol.Optional(
					CONF_ENABLE_LOCATION_TRACKING,
					default=current_options.get(
						CONF_ENABLE_LOCATION_TRACKING,
						current_data.get(CONF_ENABLE_LOCATION_TRACKING, False)
					),
				): bool,
				# Never pre-filled with the stored value: an options form is
				# rendered in the browser, and a secret that is sent back out
				# to be displayed is a secret in one more place.
				vol.Optional(CONF_API_TOKEN, default=""): str,
			}),
		)
