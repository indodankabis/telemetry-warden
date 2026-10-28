"""
Traffic Accounting & Kirchhoff Switch-Fabric Conservation Engine.
"""

from typing import Dict, List, Optional
from telemetry_warden.models import (
    CameraVerification,
    DeviceCategory,
    DeviceNode,
    LeakAssessment,
    ThreatLevel,
    TrafficSample,
)


class TrafficAccountingEngine:
    """
    Evaluates LAN vs WAN traffic ratios and isolates East-West flows.
    """

    @staticmethod
    def assess_device_leak(
        device: DeviceNode,
        total_tx: int,
        wan_tx: int,
    ) -> LeakAssessment:
        local_tx = max(0, total_tx - wan_tx)
        leak_ratio = (wan_tx / total_tx) if total_tx > 0 else 0.0

        # Threat classification logic
        if leak_ratio < 0.15:
            threat = ThreatLevel.CLEAN
            reason = f"Normal local LAN communication ({round(local_tx / 1024, 1)} KB local)"
        elif leak_ratio < 0.50:
            threat = ThreatLevel.LOW_BEACON
            reason = f"Periodic cloud beacons/telemetry ({round(leak_ratio * 100, 1)}% outbound)"
        elif leak_ratio < 0.85:
            threat = ThreatLevel.MODERATE_LEAK
            reason = f"Elevated cloud telemetry ratio ({round(leak_ratio * 100, 1)}% outbound)"
        else:
            threat = ThreatLevel.HIGH_EXFILTRATION
            reason = f"Nearly 100% of device traffic is leaving local LAN to external cloud ({round(leak_ratio * 100, 1)}%)"

        return LeakAssessment(
            ip=device.ip,
            hostname=device.hostname or device.ip,
            category=device.category,
            total_tx_bytes=total_tx,
            wan_tx_bytes=wan_tx,
            local_tx_bytes=local_tx,
            outbound_leak_ratio=round(leak_ratio, 3),
            threat_level=threat,
            reason=reason,
        )

    @staticmethod
    def verify_camera_stream(
        camera_node: DeviceNode,
        cam_ingress_bps: float,
        wan_uplink_bps: float,
        nvr_node: Optional[DeviceNode] = None,
    ) -> CameraVerification:
        """
        Kirchhoff Conservation Verification:
        If camera ingress >> WAN uplink, the video stream is staying East-West (local).
        If WAN uplink rises to match camera ingress, video is streaming up to vendor servers.
        """
        cam_mbps = round((cam_ingress_bps * 8.0) / 1e6, 3)
        wan_mbps = round((wan_uplink_bps * 8.0) / 1e6, 3)

        # Inferred East-West local stream
        east_west_bps = max(0.0, cam_ingress_bps - wan_uplink_bps)
        lan_stream_mbps = round((east_west_bps * 8.0) / 1e6, 3)
        wan_leak_mbps = min(cam_mbps, wan_mbps)

        # If more than 70% of camera data is kept within LAN
        is_private = (lan_stream_mbps > (cam_mbps * 0.70)) or (wan_leak_mbps < 0.20)

        nvr_ip = nvr_node.ip if nvr_node else None
        if is_private:
            notes = (
                f"VERIFIED PRIVATE: Stream rate {cam_mbps} Mbps stays on local subnet. "
                f"WAN leakage is negligible ({wan_leak_mbps} Mbps)."
            )
        else:
            notes = (
                f"POTENTIAL CLOUD LEAK: Camera is transmitting {cam_mbps} Mbps and WAN uplink "
                f"is consuming {wan_mbps} Mbps. Video stream appears to be uploading to external servers."
            )

        return CameraVerification(
            camera_ip=camera_node.ip,
            camera_name=camera_node.hostname or camera_node.ip,
            nvr_destination_ip=nvr_ip,
            lan_stream_mbps=lan_stream_mbps,
            wan_leak_mbps=wan_leak_mbps,
            is_verified_local_private=is_private,
            notes=notes,
        )
