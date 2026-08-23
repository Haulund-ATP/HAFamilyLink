"""Select platform for Google Family Link integration."""
from __future__ import annotations

import logging

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, LOGGER_NAME
from .coordinator import FamilyLinkDataUpdateCoordinator

_LOGGER = logging.getLogger(LOGGER_NAME)

RESTRICTION_MAP = {
    "Anyone": 1,
    "Only contacts I add": 3,
    "Contacts I add & limited groups": 4
}

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Family Link select platform."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    entities = []

    # Check if data is available (just like in sensor.py)
    if not coordinator.data or "children_data" not in coordinator.data:
        _LOGGER.error("No children data in coordinator after first refresh")
        return

    # Iterate through the list of children exactly as sensor.py does
    for child_data in coordinator.data.get("children_data", []):
        child_id = child_data["child_id"]
        child_name = child_data["child_name"]
        
        _LOGGER.debug(f"Creating communication select entity for {child_name}")
        entities.append(FamilyLinkCommunicationSelect(coordinator, child_id, child_name))

    async_add_entities(entities, update_before_add=True)

class FamilyLinkCommunicationSelect(CoordinatorEntity, SelectEntity):
    """Representation of a Family Link Communication Restriction select entity."""

    _attr_options = list(RESTRICTION_MAP.keys())
    _attr_icon = "mdi:phone-lock"
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: FamilyLinkDataUpdateCoordinator,
        child_id: str,
        child_name: str,
    ) -> None:
        """Initialize the select entity."""
        super().__init__(coordinator)
        self.child_id = child_id
        
        self._attr_name = "Allowed Calls & Texts"
        self._attr_unique_id = f"{child_id}_communication_restriction"
        self._attr_current_option = None
        
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, child_id)},
            name=child_name,
            manufacturer="Google",
            model="Family Link Account",
        )

    @property
    def current_option(self) -> str | None:
        """Return the current selected option."""
        return self._attr_current_option

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass, fetch the initial state."""
        await super().async_added_to_hass()
        await self._async_update_state_from_api()

    async def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        # Every time the coordinator refreshes, we fetch our setting too
        await self._async_update_state_from_api()
        self.async_write_ha_state()

    async def _async_update_state_from_api(self) -> None:
        """Fetch the latest restriction state from the API."""
        try:
            level = await self.coordinator.client.get_contact_restriction(self.child_id)
            if level is not None:
                # Find the string name ("Anyone", etc.) that matches the returned integer
                for option_name, option_level in RESTRICTION_MAP.items():
                    if option_level == level:
                        self._attr_current_option = option_name
                        break
        except Exception as err:
            _LOGGER.error(f"Failed to fetch communication state for {self.child_id}: {err}")

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        level = RESTRICTION_MAP[option]
        
        success = await self.coordinator.client.set_contact_restriction(self.child_id, level)
        
        if success:
            _LOGGER.debug(f"Successfully set {self.child_id} communication to {option}")
            self._attr_current_option = option
            self.async_write_ha_state()
        else:
            _LOGGER.error(f"Failed to update communication settings for {self.child_id}")