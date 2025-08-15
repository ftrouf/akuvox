"""Camera platform for akuvox."""

from collections.abc import Callable, Awaitable

from homeassistant.helpers import storage
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.const import ATTR_IDENTIFIERS, CONF_NAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.components.generic.camera import GenericCamera

from .const import DOMAIN, LOGGER, NAME, VERSION, DATA_STORAGE_KEY

def _force_udp(url: str) -> str:
    """
    Force le transport RTSP en UDP en ajoutant :
      - ?udp (ou &udp) pour go2rtc
      - #rtsp_transport=udp pour le chemin ffmpeg de go2rtc
    N’ajoute rien si 'udp' ou 'tcp' est déjà présent dans la query/fragment.
    """
    try:
        p = urlparse(url)
    except Exception:
        # si l’URL est invalide, on renvoie tel quel
        return url

    # seulement pour RTSP
    if p.scheme.lower() != "rtsp":
        return url

    q = p.query or ""
    f = p.fragment or ""

    # si déjà un indicateur udp/tcp, on ne touche pas
    if ("udp" in q) or ("tcp" in q) or ("rtsp_transport=udp" in f) or ("rtsp_transport=tcp" in f):
        return url

    # ajoute ?udp / &udp
    if q:
        q = q + "&udp"
    else:
        q = "udp"

    # ajoute aussi le fragment ffmpeg
    if f:
        f = f + "&rtsp_transport=udp"
    else:
        f = "rtsp_transport=udp"

    return urlunparse((p.scheme, p.netloc, p.path, p.params, q, f))

async def async_setup_entry(hass: HomeAssistant,
                            _entry,
                            async_add_devices: Callable[[list], Awaitable[None]]):
    """Set up the camera platform."""
    store = storage.Store(hass, 1, DATA_STORAGE_KEY)
    device_data = await store.async_load()

    if not device_data:
        LOGGER.error("No device data found")
        return

    cameras_data = device_data.get("camera_data")
    if not cameras_data:
        LOGGER.error("No camera data found in device data")
        return

    entities = []
    for camera_data in cameras_data:
        name = str(camera_data["name"]).strip()
        rtsp_url = str(camera_data["video_url"]).strip()
        # Force UDP pour fiabiliser go2rtc (et compat ffmpeg)
        rtsp_url_udp = _force_udp(rtsp_url)
        if rtsp_url_udp != rtsp_url:
            LOGGER.debug("RTSP URL (forced UDP) for '%s': %s (was: %s)", name, rtsp_url_udp, rtsp_url)
        else:
            LOGGER.debug("RTSP URL for '%s': %s", name, rtsp_url_udp)      
        entities.append(AkuvoxCameraEntity(
            hass=hass,
            name=name,
            rtsp_url=rtsp_url_udp
        ))

    if async_add_devices is None:
        LOGGER.error("async_add_devices is None")
        return

    async_add_devices(entities)
    return True

class AkuvoxCameraEntity(GenericCamera):
    """Akuvox camera class."""

    def __init__(
        self,
        hass: HomeAssistant,
        name: str,
        rtsp_url: str) -> None:
        """Initialize the Akuvox camera class."""
        LOGGER.debug("Adding Akuvox camera '%s'", name)

        super().__init__(
            hass=hass,
            device_info={
                ATTR_IDENTIFIERS: {(DOMAIN, name)},
                CONF_NAME: name,
                "stream_source": rtsp_url,
                "limit_refetch_to_url_change": True,
                "framerate": 2,
                "content_type": "",
                CONF_VERIFY_SSL: False,
                "rtsp_transport": "udp"
            },
            identifier=name,
            title=name,
        )

        self._name = name
        self._rtsp_url = rtsp_url
        self._attr_unique_id = name
        self._attr_name = name

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, name)},
            name=name,
            model=VERSION,
            manufacturer=NAME,
        )

