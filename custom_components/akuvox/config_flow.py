"""Config flow for Akuvox (login/password only)."""
from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN,
    DEFAULT_TOKEN,
    DEFAULT_APP_TOKEN,
    LOGGER,
    LOCATIONS_DICT,
    COUNTRY_PHONE,
    SUBDOMAINS_LIST,
)
from .api import AkuvoxApiClient
from .coordinator import AkuvoxDataUpdateCoordinator


class AkuvoxFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Akuvox."""

    VERSION = 1

    akuvox_api_client: AkuvoxApiClient | None = None
    data: dict = {}

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
        """Return the options flow."""
        return AkuvoxOptionsFlowHandler(config_entry)

    async def async_step_user(self, user_input: dict | None = None):
        """Step for entering login credentials."""
        errors: dict[str, str] = {}

        # Init API client (reuse from coordinator if exists)
        if self.akuvox_api_client is None:
            coordinator: AkuvoxDataUpdateCoordinator | None = None
            if DOMAIN in self.hass.data:
                for _key, value in self.hass.data[DOMAIN].items():
                    coordinator = value
            if coordinator:
                self.akuvox_api_client = coordinator.client
            else:
                self.akuvox_api_client = AkuvoxApiClient(
                    session=async_get_clientsession(self.hass),
                    hass=self.hass,
                    entry=None,
                )

        schema = vol.Schema({
            vol.Required("email"): str,
            vol.Required("password"): str,
            vol.Optional("subdomain", default="ecloud"): str,
        })

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        user_input.setdefault("subdomain", "ecloud")
        email = user_input["email"].strip()
        password = user_input["password"]
        
        if not email or not password:
            errors["base"] = "missing_credentials"
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        try:
            # Login with email/password
            login_data = await self.akuvox_api_client.async_login_password(email, password)
            if not login_data or "token" not in login_data:
                errors["base"] = "auth_failed"
                return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

            # Optionally get servers_list before retrieving user data
            await self.akuvox_api_client.async_make_servers_list_request()

            # Retrieve user/device data
            await self.akuvox_api_client.async_retrieve_user_data()
            devices_json = self.akuvox_api_client.get_devices_json() or {}

            # Prepare entry data
            self.data = {
                "email": email,
                "subdomain": subdomain,
                "token": login_data.get("token"),
                "refresh_token": login_data.get("refresh_token"),
                "token_valid": login_data.get("token_valid"),
                **devices_json,
            }

            # Ensure unique ID by email
            await self.async_set_unique_id(email.lower())
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=f"Akuvox ({email})",
                data=self.data,
            )

        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Login failed: %s", exc)
            errors["base"] = "auth_failed"
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)


class AkuvoxOptionsFlowHandler(config_entries.OptionsFlow):
    """Options flow to change login/password after install."""

    def __init__(self, config_entry: config_entries.ConfigEntry):
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        errors: dict[str, str] = {}
        current_email = self.config_entry.data.get("email", "")

        schema = vol.Schema({
            vol.Required("email", default=current_email): str,
            vol.Required("password"): str,
        })

        if user_input is None:
            return self.async_show_form(step_id="init", data_schema=schema, errors=errors)

        email = user_input["email"].strip()
        password = user_input["password"]

        api = AkuvoxApiClient(
            session=async_get_clientsession(self.hass),
            hass=self.hass,
            entry=self.config_entry,
        )

        try:
            new_login = await api.async_login_password(email, password)
            if not new_login or "token" not in new_login:
                errors["base"] = "auth_failed"
                return self.async_show_form(step_id="init", data_schema=schema, errors=errors)

            new_data = {
                **self.config_entry.data,
                "email": email,
                "token": new_login.get("token"),
                "refresh_token": new_login.get("refresh_token"),
                "token_valid": new_login.get("token_valid"),
            }
            self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)

            await self.hass.config_entries.async_reload(self.config_entry.entry_id)

            return self.async_create_entry(title="", data={})

        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Reauthentication failed: %s", exc)
            errors["base"] = "auth_failed"
            return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
