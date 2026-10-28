"""
ARP Table & Local Network Node Harvester.
Reads /proc/net/arp directly on Linux, with zero external dependencies.
"""

import os
import re
import socket
import time
from pathlib import Path
from typing import Dict, List, Optional

from telemetry_warden.harvesters.base import BaseHarvester
from telemetry_warden.models import DeviceCategory, DeviceNode, TrafficSample

# Common IoT OUI / Vendor Signatures (Honest lookup table, no cloud API required)
VENDOR_SIGNATURES: Dict[str, tuple[str, DeviceCategory]] = {
    # eufy / Anker cameras
    "2c:aa:8e": ("Anker/eufy", DeviceCategory.SECURITY_CAMERA),
    "14:59:c0": ("eufy", DeviceCategory.SECURITY_CAMERA),
    "00:1a:2b": ("Generic IP Cam", DeviceCategory.SECURITY_CAMERA),
    # Smart TVs & Streaming
    "d8:31:34": ("Roku", DeviceCategory.SMART_TV),
    "bc:79:ad": ("Roku", DeviceCategory.SMART_TV),
    "a8:23:fe": ("LG Electronics", DeviceCategory.SMART_TV),
    "64:1c:ae": ("Samsung Electronics", DeviceCategory.SMART_TV),
    "24:fc:e5": ("Hisense", DeviceCategory.SMART_TV),
    # Smart Audio / Assistants
    "5c:aa:fd": ("Sonos", DeviceCategory.VOICE_ASSISTANT),
    "94:9f:3e": ("Sonos", DeviceCategory.VOICE_ASSISTANT),
    "68:54:fd": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT),
    "fc:65:de": ("Amazon Echo", DeviceCategory.VOICE_ASSISTANT),
    # Smart Appliances & Garage
    "30:de:4b": ("Chamberlain MyQ", DeviceCategory.SMART_APPLIANCE),
    "40:24:b2": ("Chamberlain MyQ", DeviceCategory.SMART_APPLIANCE),
    "98:03:cf": ("Tesla EVSE", DeviceCategory.SMART_APPLIANCE),
    "f0:f5:bd": ("Midea / Air Conditioner", DeviceCategory.SMART_APPLIANCE),
}


class ArpTableHarvester(BaseHarvester):
    def __init__(self, arp_path: str = "/proc/net/arp"):
        self.arp_path = Path(arp_path)

    def _classify_device(self, mac: str, hostname: str) -> tuple[str, DeviceCategory]:
        norm_mac = mac.lower()
        prefix = ":".join(norm_mac.split(":")[:3]) if len(norm_mac.split(":")) >= 3 else ""

        if prefix in VENDOR_SIGNATURES:
            return VENDOR_SIGNATURES[prefix]

        # Hostname heuristic fallback
        h_lower = hostname.lower()
        if any(c in h_lower for c in ["cam", "floodlight", "doorbell", "nvr", "eufy", "reolink", "amcrest"]):
            return ("IP Camera", DeviceCategory.SECURITY_CAMERA)
        if any(t in h_lower for t in ["roku", "tv", "vizio", "bravia", "firetv", "appletv", "hisense"]):
            return ("Smart TV / Streaming", DeviceCategory.SMART_TV)
        if any(e in h_lower for e in ["echo", "alexa", "homepod", "nest-audio", "sonos"]):
            return ("Smart Speaker", DeviceCategory.VOICE_ASSISTANT)
        if any(a in h_lower for a in ["myq", "washer", "dryer", "fridge", "tesla", "wallconnector", "midea"]):
            return ("Smart Appliance / EVSE", DeviceCategory.SMART_APPLIANCE)
        if any(pc in h_lower for pc in ["desktop", "laptop", "xps", "thinkpad", "macbook", "pixel", "tab", "galaxy"]):
            return ("Workstation / Mobile", DeviceCategory.COMPUTE)

        return ("Unknown Device", DeviceCategory.UNKNOWN)

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def discover_devices(self) -> List[DeviceNode]:
        devices: List[DeviceNode] = []
        if not self.arp_path.exists():
            return devices

        try:
            lines = self.arp_path.read_text(encoding="utf-8").strip().splitlines()
            # Header format: IP address HW type Flags HW address Mask Device
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    flags = parts[2]
                    mac = parts[3].lower()
                    iface = parts[5]

                    # Flags 0x2 or 0x0 indicate completed vs incomplete ARP entries
                    if flags != "0x0" and mac != "00:00:00:00:00:00":
                        hostname = self._resolve_hostname(ip)
                        vendor, category = self._classify_device(mac, hostname)
                        devices.append(
                            DeviceNode(
                                ip=ip,
                                mac=mac,
                                hostname=hostname,
                                category=category,
                                vendor=vendor,
                                interface=iface,
                                is_active=True,
                            )
                        )
        except Exception:
            pass

        return devices

    def sample_traffic(self, devices: List[DeviceNode]) -> List[TrafficSample]:
        # Basic traffic sample timestamped
        now = time.time()
        samples: List[TrafficSample] = []
        for dev in devices:
            samples.append(
                TrafficSample(
                    ip=dev.ip,
                    timestamp=now,
                    rx_bytes=0,
                    tx_bytes=0,
                    rx_packets=0,
                    tx_packets=0,
                )
            )
        return samples
