"""
Actionable Blocklist & Firewall Rule Generator.
Helps users actively STOP telemetry leaks on their local network.
"""

from typing import Dict, List
from telemetry_warden.models import BlockRule, DeviceCategory, LeakAssessment, ThreatLevel

# Known vendor telemetry endpoints (Honest, curated, verifiable domains)
VENDOR_TELEMETRY_DOMAINS: Dict[DeviceCategory, List[str]] = {
    DeviceCategory.SMART_TV: [
        "scribe.roku.com",
        "track.roku.com",
        "logs.roku.com",
        "samsungcloudsolution.com",
        "config.samsungcloudsolution.net",
        "log-config.samsungcloudsolution.net",
        "lgtvonline.lge.com",
        "rdx.lgtvcommon.com",
        "ad.lgsmartad.com",
    ],
    DeviceCategory.SECURITY_CAMERA: [
        "security-app.eufylife.com",
        "event-app.eufylife.com",
        "push.reolink.com",
        "telemetry.tuya.com",
    ],
    DeviceCategory.SMART_APPLIANCE: [
        "myq-gdo.myq-cloud.com",
        "telemetry.midea.com",
        "connect.smartthings.com",
    ],
    DeviceCategory.VOICE_ASSISTANT: [
        "device-metrics-us.amazon.com",
        "device-metrics-us-2.amazon.com",
        "msmetrics.ws.sonos.com",
    ],
}


class BlocklistGenerator:
    @staticmethod
    def generate_rules_for_leak(
        assessment: LeakAssessment,
        wan_interface: str = "eth0",
    ) -> List[BlockRule]:
        rules: List[BlockRule] = []

        if assessment.threat_level in [ThreatLevel.CLEAN, ThreatLevel.LOW_BEACON]:
            return rules

        ip = assessment.ip
        host = assessment.hostname or ip
        cat = assessment.category

        # 1. Linux iptables Rule (Drops outbound WAN traffic while preserving LAN access)
        iptables_cmd = (
            f"sudo iptables -I FORWARD -s {ip} -o {wan_interface} -j DROP"
        )
        rules.append(
            BlockRule(
                target_ip=ip,
                hostname=host,
                rule_type="iptables",
                command_or_line=iptables_cmd,
                description=(
                    f"Isolate {host} from internet. Drops WAN outbound traffic on {wan_interface} "
                    f"while keeping local LAN streaming, Home Assistant, and casting fully operational."
                ),
            )
        )

        # 2. nftables Rule
        nftables_cmd = (
            f"sudo nft add rule inet filter forward ip saddr {ip} oifname \"{wan_interface}\" drop"
        )
        rules.append(
            BlockRule(
                target_ip=ip,
                hostname=host,
                rule_type="nftables",
                command_or_line=nftables_cmd,
                description=f"Modern nftables equivalent rule to sandbox {host} from external WAN.",
            )
        )

        # 3. Pi-hole / DNS sinkhole entries if vendor domains are recognized
        domains = VENDOR_TELEMETRY_DOMAINS.get(cat, [])
        for dom in domains:
            rules.append(
                BlockRule(
                    target_ip=ip,
                    hostname=host,
                    rule_type="pihole",
                    command_or_line=dom,
                    description=f"Block telemetry tracker domain for {cat.value} ({dom}).",
                )
            )
            rules.append(
                BlockRule(
                    target_ip=ip,
                    hostname=host,
                    rule_type="hosts",
                    command_or_line=f"0.0.0.0 {dom}",
                    description=f"/etc/hosts sinkhole line for {dom}.",
                )
            )

        return rules
