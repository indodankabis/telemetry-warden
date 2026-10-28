"""
Base harvester interface.
"""

from abc import ABC, abstractmethod
from typing import List
from telemetry_warden.models import DeviceNode, TrafficSample


class BaseHarvester(ABC):
    @abstractmethod
    def discover_devices(self) -> List[DeviceNode]:
        """Discovers reachable devices on the local network."""
        pass

    @abstractmethod
    def sample_traffic(self, devices: List[DeviceNode]) -> List[TrafficSample]:
        """Collects point-in-time traffic metrics for the given devices."""
        pass
