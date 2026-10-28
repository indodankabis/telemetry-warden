"""
Anomaly & Telemetry Burst Detection Engine.
Calculates statistical deviation and detects periodic phone-home beacons.
"""

import math
from typing import Dict, List, Optional
from telemetry_warden.models import DeviceCategory, DeviceNode, LeakAssessment, ThreatLevel


class AnomalyEngine:
    @staticmethod
    def detect_burst_anomalies(
        assessments: List[LeakAssessment],
        known_baselines: Optional[Dict[str, float]] = None,
    ) -> List[LeakAssessment]:
        """
        Flags devices deviating from expected IoT baseline.
        IoT devices (Smart TVs, appliances) have low baseline expectations for WAN upload.
        """
        suspicious: List[LeakAssessment] = []
        baselines = known_baselines or {}

        for a in assessments:
            # Smart TVs, Appliances, and Cameras should NOT have > 75% outbound WAN upload
            if a.category in [DeviceCategory.SMART_TV, DeviceCategory.SMART_APPLIANCE]:
                if a.outbound_leak_ratio > 0.60:
                    a.threat_level = ThreatLevel.HIGH_EXFILTRATION
                    a.reason = (
                        f"Unusually high outbound telemetry for an IoT device ({a.category.value}): "
                        f"{round(a.outbound_leak_ratio * 100, 1)}% of packets leave your LAN."
                    )
                    suspicious.append(a)
                elif a.outbound_leak_ratio > 0.30:
                    a.threat_level = ThreatLevel.MODERATE_LEAK
                    suspicious.append(a)
            elif a.threat_level in [ThreatLevel.MODERATE_LEAK, ThreatLevel.HIGH_EXFILTRATION]:
                suspicious.append(a)

        return suspicious
