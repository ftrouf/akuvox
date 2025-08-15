"""Akuvox API Client (password login only)."""
from __future__ import annotations

import asyncio
import socket
import json
import hashlib
import string

from homeassistant.core import HomeAssistant

import aiohttp
import async_timeout
import requests

from .data import AkuvoxData
from .door_poll import DoorLogPoller

from .const import (
    LOGGER,
    REST_SERVER_ADDR,
    REST_SERVER_PORT,
    REST_SERVER_API_VERSION,
    API_REST_SERVER_DATA,
    USERCONF_API_VERSION,
    API_USERCONF,
    OPENDOOR_API_VERSION,
    API_OPENDOOR,
    API_APP_HOST,
    API_GET_PERSONAL_TEMP_KEY_LIST,
    API_GET_PERSONAL_DOOR_LOG,
)

# =========================
# Exceptions
# =========================
class AkuvoxApiClientError(Exception):
    """General API error."""


class AkuvoxApiClientCommunicationError(AkuvoxApiClientError):
    """Communication error."""


class AkuvoxApiClientAuthenticationError(AkuvoxApiClientError):
    """Authentication error."""


# =========================
# Helpers (email obfuscation + password hash)
# =========================
def _caesar_plus3(s: str) -> str:
    lo, hi = string.ascii_lowercase, string.ascii_uppercase
    out = []
    for c in s:
        if c in lo:
            out.append(lo[(lo.index(c) + 3) % 26])
        elif c in hi:
            out.append(hi[(hi.index(c) + 3) % 26])
        else:
            out.append(c)
    return "".join(out)


def _double_md5(pw: str) -> str:
    h1 = hashlib.md5(pw.encode()).hexdigest().encode()
    return hashlib.md5(h1).hexdigest()


# =========================
# Client
# =========================
class AkuvoxApiClient:
    """Akuvox API Client (email/password only)."""

    _data: AkuvoxData = None  # type: ignore
    hass: HomeAssistant
    door_log_poller: DoorLogPoller

    def __init__(
        self,
        session: aiohttp.ClientSession,
        hass: HomeAssistant,
        entry,
    ) -> None:
        self._session = session
        self.hass = hass
        if entry:
            LOGGER.debug("▶️ Initializing AkuvoxData from API client init")
            self._data = AkuvoxData(entry=entry, hass=hass)  # type: ignore

    def init_api_with_data(
        self,
        hass: HomeAssistant,
        host=None,
        subdomain=None,
        token=None,
    ):
        """"Initialize values from saved data/options (password mode)."""
        if not self._data:
            LOGGER.debug("▶️ Initializing AkuvoxData from API client init_api_with_data")
            self._data = AkuvoxData(
                entry=None,  # type: ignore
                hass=hass,
                host=host,  # type: ignore
                subdomain=subdomain,  # type: ignore
                token=token,  # type: ignore
            )
        self.hass = self.hass if self.hass else hass

    # =========================
    # Public entrypoints (password flow)
    # =========================
    async def async_login_password(self, hass: HomeAssistant, email: str, password: str, subdomain: str) -> dict:
        """Login via email/password.

        Fait: GET https://<REST_SERVER_ADDR>:<PORT>/login?user=<email_cesar+3>&passwd=<md5(md5(password))>
        NB: on construit l'URL avec la query EN DUR (ne pas encoder '@').
        Retourne un dict: {'token','refresh_token','token_valid'} et remplit self._data.
        """
        if not email or not password:
            raise AkuvoxApiClientAuthenticationError("Email/password manquants")

        user_obf = _caesar_plus3(email.strip())
        passwd_hash = _double_md5(password)
        url = f"https://{REST_SERVER_ADDR}:{REST_SERVER_PORT}/login?user={user_obf}&passwd={passwd_hash}"
        headers = {
            "user-agent": "VBell/7.15.3 (iPhone; iOS 18.5; Scale/3.00)",
            "api-version": "7.11",
            "accept": "*/*",
        }

        def _do():
            return requests.get(url, headers=headers, timeout=15)

        response: requests.Response = await self.hass.async_add_executor_job(_do)

        if response.status_code != 200:
            raise AkuvoxApiClientAuthenticationError(
                f"HTTP {response.status_code} on /login: {response.text[:200]}"
            )

        try:
            body = response.json()
        except Exception as e:
            raise AkuvoxApiClientAuthenticationError(
                f"/login non-JSON: {e}; ct={response.headers.get('content-type')}"
            )

        # Attendu: {"datas":{"token":"...","refresh_token":"...","token_valid":"604800"},"err_code":"0","message":"success"}
        if str(body.get("err_code")) != "0" or "datas" not in body:
            raise AkuvoxApiClientAuthenticationError(f"Login refusé: {body}")

        datas = body["datas"] or {}
        token = datas.get("token")
        refresh = datas.get("refresh_token")

        """Request server list data."""
        self.init_api_with_data(
            hass=hass,
            subdomain=subdomain,
            token=token)
        if await self.async_init_api() is False:
            return False        
        # Si ton parseur existant traite la même structure, réutilise-le
        if hasattr(self._data, "parse_sms_login_response"):
            try:
                self._data.parse_sms_login_response(datas)  # type: ignore[attr-defined]
            except Exception:  # mieux vaut ne pas casser si les formats diffèrent
                LOGGER.debug("servers_list: format différent, parseur SMS ignoré")

        if not token:
            raise AkuvoxApiClientAuthenticationError("Pas de token renvoyé par /login")

        # Stocker dans le data model
        if self._data:
            self._data.token = token
            # S'il existe un champ refresh_token dans AkuvoxData, utilise-le. Sinon, garde compat via auth_token.
            if hasattr(self._data, "refresh_token"):
                self._data.refresh_token = refresh  # type: ignore[attr-defined]
            else:
                self._data.auth_token = refresh  # rétro-compat si le modèle n'a pas refresh_token

        return {
            "token": token,
            "refresh_token": refresh,
            "token_valid": datas.get("token_valid"),
        }

    async def async_get_servers_list(self) -> dict:
        """GET /servers_list avec le token courant."""
        if not self._data or not self._data.token:
            raise AkuvoxApiClientAuthenticationError("Pas de token pour /servers_list")

        # S'assurer de connaître le REST server host (API de découverte)
        if not self._data.host:
            ok = await self.async_fetch_rest_server()
            if not ok:
                raise AkuvoxApiClientError("Impossible de récupérer REST server host")

        url = f"https://{REST_SERVER_ADDR}:{REST_SERVER_PORT}/servers_list"
        headers = {
            "user-agent": "VBell/7.15.3 (iPhone; iOS 18.5; Scale/3.00)",
            "api-version": "6.8",
            "x-auth-token": self._data.token,
            "accept": "*/*",
            "accept-language": "fr-FR;q=1",
            "accept-encoding": "gzip, deflate, br",
        }

        def _do_get():
            return requests.get(url, headers=headers, timeout=15)

        response: requests.Response = await self.hass.async_add_executor_job(_do_get)

        if response.status_code != 200:
            raise AkuvoxApiClientError(
                f"HTTP {response.status_code} sur /servers_list: {response.text[:200]}"
            )

        txt = response.text.strip()
        try:
            json_data = json.loads(txt)
        except Exception:
            raise AkuvoxApiClientError(
                f"/servers_list non-JSON (CT={response.headers.get('content-type')}): {txt[:200]}"
            )
        
        return json_data

    async def async_init_api(self) -> bool:
        """Initialise la conf serveur et récupère le servers_list, puis lance le polling."""
        # Découverte REST server (host, etc.)
        if self._data.host is None or len(self._data.host) == 0:
            self._data.host = "...request in process"
            if await self.async_fetch_rest_server() is False:
                return False
        LOGGER.debug("INIT_API")
        # Récupère la liste des serveurs (nécessaire avant user_conf)
        try:
            await self.async_get_servers_list()
        except Exception as e:
            LOGGER.error("❌ API request for servers list failed: %s", e)
            return False

        # Begin polling personal door log
        await self.async_start_polling()
        return True

    async def async_start_polling(self):
        """Start polling the personal door log API."""
        self.door_log_poller = DoorLogPoller(
            hass=self.hass, poll_function=self.async_retrieve_personal_door_log
        )
        await self.door_log_poller.async_start()

    async def async_stop_polling(self):
        """Stop polling the personal door log API."""
        await self.door_log_poller.async_stop()

    # =========================
    # Data retrieval
    # =========================
    async def async_retrieve_user_data(self) -> bool:
        """Retrieve user devices and temp keys data."""
        # servers_list est déjà appelé côté init; on peut enchaîner
        await self.async_retrieve_device_data()
        await self.async_retrieve_temp_keys_data()
        return True

    async def async_retrieve_device_data(self) -> bool:
        """Request and parse the user's device data."""
        user_conf_data = await self.async_user_conf()
        if user_conf_data is not None:
            self._data.parse_userconf_data(user_conf_data)  # type: ignore
            return True
        return False

    async def async_user_conf(self):
        """Request the user's configuration data."""
        LOGGER.debug("📡 Retrieving list of user's devices...")
        url = f"https://{self._data.host}/{API_USERCONF}?token={self._data.token}"
        data = {}
        headers = {
            "Host": self._data.host,
            "X-AUTH-TOKEN": self._data.token,
            "Connection": "keep-alive",
            "api-version": USERCONF_API_VERSION,
            "Accept": "*/*",
            "User-Agent": "VBell/6.61.2 (iPhone; iOS 16.6; Scale/3.00)",
            "Accept-Language": "en-AU;q=1, he-AU;q=0.9, ru-RU;q=0.8",
            "x-cloud-lang": "en",
        }
        json_data = await self._async_api_wrapper(
            method="get", url=url, headers=headers, data=data
        )

        if json_data is not None:
            LOGGER.debug("✅ User's device list retrieved successfully")
            return json_data

        LOGGER.error("❌ Unable to retrieve user's device list.")
        return None

    def make_opendoor_request(self, name: str, host: str, token: str, data: str):
        """Send a request to open a door."""
        LOGGER.debug("📡 Sending request to open door '%s'...", name)
        LOGGER.debug("Request data = %s", str(data))
        url = f"https://{host}/{API_OPENDOOR}?token={token}"
        headers = {
            "Host": host,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-AUTH-TOKEN": token,
            "api-version": OPENDOOR_API_VERSION,
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "User-Agent": "VBell/6.61.2 (iPhone; iOS 16.6; Scale/3.00)",
            "Accept-Language": "en-AU;q=1, he-AU;q=0.9, ru-RU;q=0.8",
            "Content-Length": "24",
            "x-cloud-lang": "en",
        }
        response = self.post_request(url=url, headers=headers, data=data)
        json_data = self.process_response(response, url)
        if json_data is not None:
            LOGGER.debug("✅ Door open request sent successfully.")
            return json_data

        LOGGER.error("❌ Request to open door failed.")
        return None

    async def async_retrieve_temp_keys_data(self) -> bool:
        """Request and parse the user's temporary keys."""
        json_data = await self.async_get_temp_key_list()
        if json_data is not None:
            self._data.parse_temp_keys_data(json_data)
            return True
        return False

    async def async_get_temp_key_list(self):
        """Request the user's temporary keys list."""
        LOGGER.debug("📡 Retrieving list of user's temporary keys...")
        host = self.get_activities_host()
        subdomain = self._data.subdomain
        url = f"https://{host}/{API_GET_PERSONAL_TEMP_KEY_LIST}"
        data = {}
        headers = {
            "x-cloud-version": "6.4",
            "accept": "application/json, text/plain, */*",
            "sec-fetch-site": "same-origin",
            "accept-language": "en-AU,en;q=0.9",
            "sec-fetch-mode": "cors",
            "x-cloud-lang": "en",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) SmartPlus/6.2",
            "referer": f"https://{subdomain}.akuvox.com/smartplus/TmpKey.html?TOKEN={self._data.token}&USERTYPE=20&VERSION=6.6",
            "x-auth-token": self._data.token,
            "sec-fetch-dest": "empty",
        }

        json_data = await self._async_api_wrapper(
            method="get", url=url, headers=headers, data=data
        )

        if json_data is not None:
            LOGGER.debug("✅ User's temporary keys list retrieved successfully")
            return json_data

        LOGGER.error("❌ Unable to retrieve user's temporary key list.")
        return None

    async def async_start_polling_personal_door_log(self):
        """Backward-compat helper (kept): start polling loop."""
        self.hass.async_create_task(self.async_retrieve_personal_door_log())

    async def async_retrieve_personal_door_log(self) -> bool:
        """Request and parse the user's door log every 2 seconds."""
        while True:
            LOGGER.warning("📡 async_retrieve_personal_door_log loop démarrée")
            json_data = await self.async_get_personal_door_log()
            if json_data is not None:
                new_door_log = await self._data.async_parse_personal_door_log(json_data)
                LOGGER.warning("📦 new_door_log = %s", new_door_log)
                if new_door_log is not None:
                    LOGGER.debug(
                        "🚪 New door open event occurred. Firing akuvox_door_update event"
                    )
                    event_name = "akuvox_door_update"
                    self.hass.bus.async_fire(event_name, new_door_log)
            await asyncio.sleep(2)

    async def async_get_personal_door_log(self):
        """Request the user's personal door log data."""
        host = self.get_activities_host()
        url = f"https://{host}/{API_GET_PERSONAL_DOOR_LOG}"
        data = {}
        headers = {
            "x-cloud-version": "6.4",
            "accept": "application/json, text/plain, */*",
            "sec-fetch-site": "same-origin",
            "accept-language": "en-AU,en;q=0.9",
            "sec-fetch-mode": "cors",
            "x-cloud-lang": "en",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) SmartPlus/6.2",
            "referer": f"https://{self._data.subdomain}.akuvox.com/smartplus/Activities.html?TOKEN={self._data.token}",
            "x-auth-token": self._data.token,
            "sec-fetch-dest": "empty",
        }

        json_data: list = await self._async_api_wrapper(  # type: ignore[assignment]
            method="get", url=url, headers=headers, data=data
        )

        # Response empty, try changing app type "single" <--> "community"
        if json_data is not None and len(json_data) == 0:
            self.switch_activities_host()
            host = self.get_activities_host()
            url = f"https://{host}/{API_GET_PERSONAL_DOOR_LOG}"
            json_data = await self._async_api_wrapper(  # type: ignore[assignment]
                method="get", url=url, headers=headers, data=data
            )

        if json_data is not None and len(json_data) > 0:
            return json_data

        LOGGER.error("❌ Unable to retrieve user's personal door log")
        return None

    # =========================
    # Low-level wrappers
    # =========================
    async def _async_api_wrapper(
        self,
        method: str,
        url: str,
        data,
        headers: dict | None = None,
    ):
        """Synchronous requests wrapped in executor with timeouts, plus parsing."""
        try:
            async with async_timeout.timeout(10):
                func = self.post_request if method == "post" else self.get_request
                subdomain = self._data.subdomain
                url = url.replace("subdomain.", f"{subdomain}.")
                if not url.endswith(API_GET_PERSONAL_DOOR_LOG):
                    LOGGER.debug("⏳ Sending request to %s", url)
                response = await self.hass.async_add_executor_job(
                    func, url, headers, data, 10
                )
                return self.process_response(response, url)

        except asyncio.TimeoutError as exception:
            # Fix for accounts which use the "single" endpoint instead of "community"
            app_type_1 = "community"
            app_type_2 = "single"
            if f"app/{app_type_1}/" in url:
                LOGGER.warning(
                    "Request 'app/%s' API %s request timed out: %s - Retry using '%s'",
                    app_type_1,
                    method,
                    url,
                    app_type_2,
                )
                self._data.app_type = app_type_2
                url = url.replace("app/" + app_type_1 + "/", "app/" + app_type_2 + "/")
                return await self._async_api_wrapper(method, url, data, headers)
            if f"app/{app_type_2}/" in url:
                LOGGER.error(
                    "Timeout occured for 'app/%s' API %s request: %s",
                    app_type_2,
                    method,
                    url,
                )
                self._data.app_type = app_type_1
            raise AkuvoxApiClientCommunicationError(
                f"Timeout error fetching information: {exception}",
            ) from exception
        except (aiohttp.ClientError, socket.gaierror) as exception:
            raise AkuvoxApiClientCommunicationError(
                f"Error fetching information: {exception}",
            ) from exception
        except Exception as exception:  # pylint: disable=broad-except
            raise AkuvoxApiClientError(
                f"Something really wrong happened! {exception}. URL = {url}"
            ) from exception
        return None

    def process_response(self, response: requests.Response, url: str):
        """Process response and return dict/list depending on API format."""
        if response.status_code == 200:
            try:
                json_data = response.json()

                # Standard responses with 'result'
                if isinstance(json_data, dict) and json_data.get("result") == 0:
                    if "datas" in json_data:
                        return json_data["datas"]
                    return json_data

                # Temp key responses
                if isinstance(json_data, dict) and "code" in json_data:
                    if json_data["code"] == 0:
                        if "data" in json_data:
                            return json_data["data"]
                        return json_data
                    return []

                # Fallback: retourner le JSON brut (liste/dict) si pas de 'result'
                return json_data

            except Exception as error:
                LOGGER.error("❌ Error parsing JSON: %s\nRequest: %s", error, url)
        else:
            LOGGER.debug(
                "❌ Error: HTTP status code = %s for request to %s",
                response.status_code,
                url,
            )
        return None

    def post_request(self, url, headers, data="", timeout=10):
        """Synchronous POST request."""
        response: requests.Response = requests.post(
            url, headers=headers, data=data, timeout=timeout
        )
        return response

    def get_request(self, url, headers, data, timeout=10):
        """Synchronous GET request."""
        response: requests.Response = requests.get(
            url, headers=headers, data=data, timeout=timeout
        )
        return response

    # =========================
    # Helpers
    # =========================
    def get_title(self) -> str:
        """Title of Akuvox account."""
        return self._data.project_name

    def get_devices_json(self) -> dict:
        """Device data dictionary."""
        return self._data.get_device_data()

    def get_activities_host(self):
        """Get the host address string for activities API requests."""
        if self._data.app_type == "single":
            return API_APP_HOST + "single"
        return API_APP_HOST + "community"

    def switch_activities_host(self):
        """Switch the activities host from single <--> community."""
        if self._data.app_type == "single":
            LOGGER.debug("Switching API address from 'single' to 'community'")
            self._data.app_type = "community"
        else:
            self._data.app_type = "single"
            LOGGER.debug("Switching API address from 'community' to 'single'")

    def update_data(self, key, value):
        """Update the data model."""
        self._data.subdomain = value if key == "subdomain" else self._data.subdomain
        # Conserver 'auth_token' pour compat (peut contenir refresh_token suivant le modèle)
        if key == "auth_token":
            self._data.auth_token = value
        if key == "token":
            self._data.token = value
        self._data.wait_for_image_url = (
            value if key == "wait_for_image_url" else self._data.wait_for_image_url
        )

    # =========================
    # REST server discovery
    # =========================
    async def async_fetch_rest_server(self):
        """Retrieve the Akuvox REST server addresses and data."""
        LOGGER.debug("📡 Fetching REST server data...")
        json_data = await self._async_api_wrapper(
            method="get",
            url=f"https://{REST_SERVER_ADDR}:{REST_SERVER_PORT}/{API_REST_SERVER_DATA}",
            data=None,
            headers={"api-version": REST_SERVER_API_VERSION},
        )
        if json_data is not None:
            LOGGER.debug("✅ REST server data received successfully")
            if self._data.parse_rest_server_response(json_data):  # type: ignore
                return True
            LOGGER.error("❌ Unable to parse Akuvox server rest API data.")
        else:
            LOGGER.error("❌ Unable to fetch Akuvox server rest API data.")
        return False
