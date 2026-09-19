import math
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.core.datetime_utils import diff_seconds, ensure_utc

# City coordinates catalog for Haversine velocity computation
GEO_COORDINATES: Dict[str, Tuple[float, float]] = {
    "New York, USA": (40.7128, -74.0060),
    "Tokyo, Japan": (35.6762, 139.6503),
    "London, UK": (51.5074, -0.1278),
    "Sydney, Australia": (-33.8688, 151.2093),
    "Berlin, Germany": (52.5200, 13.4050),
    "Paris, France": (48.8566, 2.3522),
    "Singapore": (1.3521, 103.8198),
    "San Francisco, USA": (37.7749, -122.4194),
}

SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "cmd.exe",
    "certutil.exe",
    "whoami.exe",
    "mimikatz.exe",
    "psexec.exe",
    "nc.exe",
    "ncat.exe",
    "vssadmin.exe"
}


def haversine_distance_km(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
    """Calculate Great-Circle distance between two coordinates in kilometers."""
    lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
    lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2.0) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    r = 6371.0  # Earth radius in kilometers
    return r * c


class DetectionRuleEngine:
    """Evaluates canonical security events against 10 deterministic rules."""

    @staticmethod
    def evaluate_all(
        event: Dict[str, Any],
        recent_events: List[Dict[str, Any]],
        ueba_baseline: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        triggered_rules = []

        # 1. RULE-AUTH-001: Brute Force Failed Logins (>= 5 failed in 5 min)
        rule_auth_001 = DetectionRuleEngine.check_brute_force(event, recent_events)
        if rule_auth_001:
            triggered_rules.append(rule_auth_001)

        # 2. RULE-AUTH-002: Successful Login after Brute Force Window
        rule_auth_002 = DetectionRuleEngine.check_success_after_brute_force(event, recent_events)
        if rule_auth_002:
            triggered_rules.append(rule_auth_002)

        # 3. RULE-GEO-001: Impossible Travel Velocity (> 1000 km/h)
        rule_geo_001 = DetectionRuleEngine.check_impossible_travel(event, recent_events)
        if rule_geo_001:
            triggered_rules.append(rule_geo_001)

        # 4. RULE-UEBA-001: Unknown Device
        rule_ueba_001 = DetectionRuleEngine.check_new_device(event, ueba_baseline)
        if rule_ueba_001:
            triggered_rules.append(rule_ueba_001)

        # 5. RULE-UEBA-002: Unknown Location
        rule_ueba_002 = DetectionRuleEngine.check_new_location(event, ueba_baseline)
        if rule_ueba_002:
            triggered_rules.append(rule_ueba_002)

        # 6. RULE-UEBA-003: Off-Hours Activity
        rule_ueba_003 = DetectionRuleEngine.check_off_hours(event, ueba_baseline)
        if rule_ueba_003:
            triggered_rules.append(rule_ueba_003)

        # 7. RULE-PROC-001: Suspicious Process Execution
        rule_proc_001 = DetectionRuleEngine.check_suspicious_process(event)
        if rule_proc_001:
            triggered_rules.append(rule_proc_001)

        # 8. RULE-NET-001: Large Data Transfer Volume
        rule_net_001 = DetectionRuleEngine.check_large_data_transfer(event, ueba_baseline)
        if rule_net_001:
            triggered_rules.append(rule_net_001)

        # 9. RULE-NET-002: Connection Frequency Spike
        rule_net_002 = DetectionRuleEngine.check_connection_frequency_spike(event, recent_events)
        if rule_net_002:
            triggered_rules.append(rule_net_002)

        # 10. RULE-CHAIN-001: Correlated Attack Chain
        rule_chain_001 = DetectionRuleEngine.check_correlated_attack_chain(event, recent_events)
        if rule_chain_001:
            triggered_rules.append(rule_chain_001)

        return triggered_rules

    @staticmethod
    def check_brute_force(event: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "AUTHENTICATION" or event.get("status") != "FAILURE":
            return None

        user = event.get("username")
        src_ip = event.get("source_ip")
        ts = event.get("timestamp")
        if not ts:
            return None

        # Count failures within preceding 5 minutes (300 seconds)
        failures = 0
        for ev in recent_events:
            if ev.get("event_type") == "AUTHENTICATION" and ev.get("status") == "FAILURE":
                ev_ts = ev.get("timestamp")
                diff = diff_seconds(ts, ev_ts)
                if diff is not None and 0 <= diff <= 300:
                    if (user and ev.get("username") == user) or (src_ip and ev.get("source_ip") == src_ip):
                        failures += 1

        if failures >= 5:
            return {
                "rule_id": "RULE-AUTH-001",
                "name": "Brute Force Authentication Sequence",
                "severity": "HIGH",
                "mitre_technique": "T1110.001",
                "mitre_name": "Password Guessing",
                "mitre_tactic": "Credential Access",
                "explanation": f"Observed {failures} consecutive failed authentication attempts within 5 minutes for user '{user}' from IP '{src_ip}'."
            }
        return None

    @staticmethod
    def check_success_after_brute_force(event: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "AUTHENTICATION" or event.get("status") != "SUCCESS":
            return None

        user = event.get("username")
        ts = event.get("timestamp")
        if not user or not ts:
            return None

        # Look for >= 3 failures in preceding 3 minutes (180s)
        recent_failures = [
            ev for ev in recent_events
            if ev.get("event_type") == "AUTHENTICATION"
            and ev.get("status") == "FAILURE"
            and ev.get("username") == user
            and (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 180)
        ]

        if len(recent_failures) >= 3:
            return {
                "rule_id": "RULE-AUTH-002",
                "name": "Successful Login Following Brute Force Window",
                "severity": "CRITICAL",
                "mitre_technique": "T1078",
                "mitre_name": "Valid Accounts",
                "mitre_tactic": "Initial Access",
                "explanation": f"Successful authentication for user '{user}' occurred immediately following {len(recent_failures)} failed attempts within 3 minutes."
            }
        return None

    @staticmethod
    def check_impossible_travel(event: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "AUTHENTICATION" or event.get("status") != "SUCCESS":
            return None

        user = event.get("username")
        loc1 = event.get("location")
        ts1 = event.get("timestamp")
        if not user or not loc1 or not ts1 or loc1 not in GEO_COORDINATES:
            return None

        coord1 = GEO_COORDINATES[loc1]

        # Check preceding logins for same user within last 24 hours
        for ev in recent_events:
            if ev.get("event_type") == "AUTHENTICATION" and ev.get("status") == "SUCCESS" and ev.get("username") == user:
                loc2 = ev.get("location")
                ts2 = ev.get("timestamp")
                if loc2 and ts2 and loc2 != loc1 and loc2 in GEO_COORDINATES:
                    diff = diff_seconds(ts1, ts2)
                    if diff is not None:
                        time_diff_hours = abs(diff) / 3600.0
                        if 0.001 <= time_diff_hours <= 24.0:
                            coord2 = GEO_COORDINATES[loc2]
                            dist_km = haversine_distance_km(coord1, coord2)
                            velocity_kmh = dist_km / time_diff_hours

                            if velocity_kmh > 1000.0:
                                return {
                                    "rule_id": "RULE-GEO-001",
                                    "name": "Impossible Travel Geospatial Velocity",
                                    "severity": "HIGH",
                                    "mitre_technique": "T1078",
                                    "mitre_name": "Valid Accounts",
                                    "mitre_tactic": "Initial Access",
                                    "explanation": f"Impossible travel detected for '{user}': logged in from '{loc2}' and '{loc1}' across {dist_km:.0f} km in {time_diff_hours*60:.1f} minutes ({velocity_kmh:.0f} km/h, exceeding 1000 km/h threshold)."
                                }
        return None

    @staticmethod
    def check_new_device(event: Dict[str, Any], ueba_baseline: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        device_id = event.get("device_id")
        if not device_id or not ueba_baseline:
            return None

        known_devices = set(ueba_baseline.get("known_devices", []))
        if known_devices and device_id not in known_devices:
            return {
                "rule_id": "RULE-UEBA-001",
                "name": "Authentication from Unrecognized Device",
                "severity": "MEDIUM",
                "mitre_technique": "T1078",
                "mitre_name": "Valid Accounts",
                "mitre_tactic": "Defense Evasion",
                "explanation": f"Device ID '{device_id}' has not been historically observed for identity '{event.get('username')}'."
            }
        return None

    @staticmethod
    def check_new_location(event: Dict[str, Any], ueba_baseline: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        location = event.get("location")
        if not location or not ueba_baseline:
            return None

        typical_locations = set(ueba_baseline.get("typical_locations", []))
        if typical_locations and location not in typical_locations:
            return {
                "rule_id": "RULE-UEBA-002",
                "name": "Access from Anomalous Location",
                "severity": "MEDIUM",
                "mitre_technique": "T1078",
                "mitre_name": "Valid Accounts",
                "mitre_tactic": "Initial Access",
                "explanation": f"Location '{location}' is outside the verified geographical profile for identity '{event.get('username')}'."
            }
        return None

    @staticmethod
    def check_off_hours(event: Dict[str, Any], ueba_baseline: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        ts = event.get("timestamp")
        if not ts or not ueba_baseline:
            return None

        hour = str(ts.hour)
        histogram = ueba_baseline.get("active_hours_histogram", {})
        if histogram and histogram.get(hour, 0) == 0:
            return {
                "rule_id": "RULE-UEBA-003",
                "name": "Off-Hours Activity Deviation",
                "severity": "LOW",
                "mitre_technique": "T1078",
                "mitre_name": "Valid Accounts",
                "mitre_tactic": "Defense Evasion",
                "explanation": f"Activity recorded at hour {hour}:00 UTC, which historically has 0% observed activity for identity '{event.get('username')}'."
            }
        return None

    @staticmethod
    def check_suspicious_process(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        proc_name = (event.get("process_name") or "").lower()
        if not proc_name:
            return None

        for susp in SUSPICIOUS_PROCESS_NAMES:
            if susp in proc_name:
                return {
                    "rule_id": "RULE-PROC-001",
                    "name": "Suspicious Process Execution",
                    "severity": "HIGH",
                    "mitre_technique": "T1059.001",
                    "mitre_name": "PowerShell",
                    "mitre_tactic": "Execution",
                    "explanation": f"Process execution of potentially malicious or dual-use binary '{proc_name}' under user context '{event.get('username')}'."
                }
        return None

    @staticmethod
    def check_large_data_transfer(event: Dict[str, Any], ueba_baseline: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        data_vol = event.get("data_volume") or 0
        if event.get("event_type") != "DATA_TRANSFER" or data_vol < 50 * 1024 * 1024:  # >= 50MB
            return None

        mean_vol = ueba_baseline.get("mean_transfer_volume", 1024 * 1024) if ueba_baseline else 1024 * 1024
        stddev_vol = ueba_baseline.get("stddev_transfer_volume", 5 * 1024 * 1024) if ueba_baseline else 5 * 1024 * 1024

        threshold = mean_vol + 3.0 * stddev_vol
        if data_vol > threshold:
            mb_transferred = data_vol / (1024 * 1024)
            return {
                "rule_id": "RULE-NET-001",
                "name": "High-Volume Data Egress Exceeding Baseline",
                "severity": "HIGH",
                "mitre_technique": "T1048",
                "mitre_name": "Exfiltration Over Alternative Protocol",
                "mitre_tactic": "Exfiltration",
                "explanation": f"Outbound data transfer of {mb_transferred:.1f} MB exceeds baseline 3-sigma upper threshold ({threshold / (1024*1024):.1f} MB)."
            }
        return None

    @staticmethod
    def check_connection_frequency_spike(event: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "NETWORK_CONNECTION":
            return None

        src_ip = event.get("source_ip")
        ts = event.get("timestamp")
        if not src_ip or not ts:
            return None

        # Count network connections in trailing 60 seconds
        recent_conns = sum(
            1 for ev in recent_events
            if ev.get("event_type") == "NETWORK_CONNECTION"
            and ev.get("source_ip") == src_ip
            and (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 60)
        )

        if recent_conns >= 15:
            return {
                "rule_id": "RULE-NET-002",
                "name": "Rapid Connection Establishment Spike",
                "severity": "MEDIUM",
                "mitre_technique": "T1046",
                "mitre_name": "Network Service Discovery",
                "mitre_tactic": "Discovery",
                "explanation": f"Observed {recent_conns} network connections established in 60 seconds from source IP '{src_ip}' (potential port scan or service enumeration)."
            }
        return None

    @staticmethod
    def check_correlated_attack_chain(event: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        user = event.get("username")
        ts = event.get("timestamp")
        if not user or not ts:
            return None

        # Look for multi-stage progression within last 15 minutes (900s)
        has_auth_failure = False
        has_auth_success = False
        has_process_exec = False
        has_data_transfer = False

        chain_events = [
            ev for ev in recent_events
            if ev.get("username") == user and (diff_seconds(ts, ev.get("timestamp")) is not None and 0 <= diff_seconds(ts, ev.get("timestamp")) <= 900)
        ] + [event]

        for ev in chain_events:
            etype = ev.get("event_type")
            status = ev.get("status")
            pname = (ev.get("process_name") or "").lower()
            dvol = ev.get("data_volume") or 0

            if etype == "AUTHENTICATION" and status == "FAILURE":
                has_auth_failure = True
            elif etype == "AUTHENTICATION" and status == "SUCCESS":
                has_auth_success = True
            elif etype == "PROCESS_EXECUTION" and any(s in pname for s in SUSPICIOUS_PROCESS_NAMES):
                has_process_exec = True
            elif etype == "DATA_TRANSFER" and dvol > 20 * 1024 * 1024:
                has_data_transfer = True

        stages_detected = sum([has_auth_failure, has_auth_success, has_process_exec, has_data_transfer])
        if stages_detected >= 3:
            return {
                "rule_id": "RULE-CHAIN-001",
                "name": "Correlated Multi-Stage Kill Chain",
                "severity": "CRITICAL",
                "mitre_technique": "T1078",
                "mitre_name": "Multi-Tactic Attack Campaign",
                "mitre_tactic": "Initial Access",
                "explanation": f"Detected multi-stage attack sequence for user '{user}': Authentication Anomaly -> Suspicious Execution -> Egress Transfer within 15 minutes."
            }
        return None
