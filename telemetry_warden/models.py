"""
Data models and typed structures for Telemetry Warden.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DeviceCategory(str, Enum):
    SECURITY_CAMERA = "security_camera"
    SMART_TV = "smart_tv"
    SMART_APPLIANCE = "smart_appliance"
    VOICE_ASSISTANT = "voice_assistant"
    COMPUTE = "compute"
    ROUTER_GATEWAY = "router_gateway"
    UNKNOWN = "unknown"


class ThreatLevel(str, Enum):
    CLEAN = "CLEAN"
    LOW_BEACON = "LOW_BEACON"
    MODERATE_LEAK = "MODERATE_LEAK"
    HIGH_EXFILTRATION = "HIGH_EXFILTRATION"


@dataclass
class DeviceNode:
    ip: str
    mac: str = "unknown"
    hostname: str = ""
    category: DeviceCategory = DeviceCategory.UNKNOWN
    vendor: str = ""
    interface: str = "eth0"
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


@dataclass
class TrafficSample:
    ip: str
    timestamp: float
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LeakAssessment:
    ip: str
    hostname: str
    category: DeviceCategory
    total_tx_bytes: int
    wan_tx_bytes: int
    local_tx_bytes: int
    outbound_leak_ratio: float  # wan_tx / total_tx (0.0 to 1.0)
    threat_level: ThreatLevel
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["threat_level"] = self.threat_level.value
        return d


@dataclass
class CameraVerification:
    camera_ip: str
    camera_name: str
    nvr_destination_ip: Optional[str]
    lan_stream_mbps: float
    wan_leak_mbps: float
    is_verified_local_private: bool
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BlockRule:
    target_ip: str
    hostname: str
    rule_type: str  # 'pihole', 'hosts', 'iptables', 'nftables'
    command_or_line: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    timestamp: str
    total_devices_scanned: int
    clean_devices_count: int
    suspicious_devices_count: int
    camera_verifications: List[CameraVerification] = field(default_factory=list)
    leak_assessments: List[LeakAssessment] = field(default_factory=list)
    suggested_block_rules: List[BlockRule] = field(default_factory=list)
    ledger_block_index: int = 0
    ledger_block_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total_devices_scanned": self.total_devices_scanned,
            "clean_devices_count": self.clean_devices_count,
            "suspicious_devices_count": self.suspicious_devices_count,
            "camera_verifications": [c.to_dict() for c in self.camera_verifications],
            "leak_assessments": [l.to_dict() for l in self.leak_assessments],
            "suggested_block_rules": [r.to_dict() for r in self.suggested_block_rules],
            "ledger_block_index": self.ledger_block_index,
            "ledger_block_hash": self.ledger_block_hash,
        }
