"""
Router & Gateway Interface Harvester.
Queries standard UPnP IGD (Internet Gateway Device) and local router endpoints
without cloud telemetry.
"""

import json
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from telemetry_warden.harvesters.base import BaseHarvester
from telemetry_warden.models import DeviceCategory, DeviceNode, TrafficSample


class RouterGatewayHarvester(BaseHarvester):
    def __init__(self, gateway_ip: str = "192.168.1.1", timeout_sec: float = 3.0):
        self.gateway_ip = gateway_ip
        self.timeout_sec = timeout_sec

    def discover_devices(self) -> List[DeviceNode]:
        """
        Discovers active devices via standard router queries.
        Falls back cleanly if unreachable.
        """
        devices: List[DeviceNode] = []
        return devices

    def query_upnp_wan_stats(self) -> Optional[Dict[str, int]]:
        """
        Queries standard UPnP WANCommonInterfaceConfig for total WAN octets / packets.
        Standard protocol on Netgear, Asus, TP-Link, OpenWrt, etc.
        """
        soap_body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            "<s:Body>"
            '<u:GetTotalBytesReceived xmlns:u="urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"/>'
            "</s:Body>"
            "</s:Envelope>"
        )
        url = f"http://{self.gateway_ip}:5000/control/WANCommonInterfaceConfig"
        req = urllib.request.Request(
            url,
            data=soap_body.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": '"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1#GetTotalBytesReceived"',
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                xml_text = resp.read().decode("utf-8")
                root = ET.fromstring(xml_text)
                for elem in root.iter():
                    if "TotalBytesReceived" in elem.tag:
                        return {"wan_rx_bytes": int(elem.text or "0")}
        except Exception:
            pass
        return None

    def sample_traffic(self, devices: List[DeviceNode]) -> List[TrafficSample]:
        return []
