from datetime import datetime, timedelta, timezone
from app.services.detection_rules import DetectionRuleEngine, haversine_distance_km


def test_haversine_formula():
    ny = (40.7128, -74.0060)
    tokyo = (35.6762, 139.6503)
    dist = haversine_distance_km(ny, tokyo)
    # NY to Tokyo is roughly 10,800 km
    assert 10500 < dist < 11200


def test_brute_force_rule_trigger():
    now = datetime.now(timezone.utc)
    recent = []
    # Create 5 failed logins within 2 minutes
    for i in range(5):
        recent.append({
            "timestamp": now - timedelta(seconds=120 - i * 20),
            "username": "victim_user",
            "source_ip": "198.51.100.10",
            "event_type": "AUTHENTICATION",
            "status": "FAILURE"
        })

    current_event = {
        "timestamp": now,
        "username": "victim_user",
        "source_ip": "198.51.100.10",
        "event_type": "AUTHENTICATION",
        "status": "FAILURE"
    }

    rule = DetectionRuleEngine.check_brute_force(current_event, recent)
    assert rule is not None
    assert rule["rule_id"] == "RULE-AUTH-001"
    assert rule["severity"] == "HIGH"
    assert rule["mitre_technique"] == "T1110.001"


def test_impossible_travel_rule_trigger():
    now = datetime.now(timezone.utc)
    # Login in New York
    t1 = now - timedelta(minutes=15)
    recent = [{
        "timestamp": t1,
        "username": "traveler",
        "event_type": "AUTHENTICATION",
        "status": "SUCCESS",
        "location": "New York, USA"
    }]

    # Login in Tokyo 15 minutes later
    current_event = {
        "timestamp": now,
        "username": "traveler",
        "event_type": "AUTHENTICATION",
        "status": "SUCCESS",
        "location": "Tokyo, Japan"
    }

    rule = DetectionRuleEngine.check_impossible_travel(current_event, recent)
    assert rule is not None
    assert rule["rule_id"] == "RULE-GEO-001"
    assert rule["severity"] == "HIGH"
    assert "exceeding 1000 km/h threshold" in rule["explanation"]


def test_suspicious_process_rule_trigger():
    event = {
        "username": "standard_user",
        "process_name": "C:\\Windows\\System32\\powershell.exe",
        "event_type": "PROCESS_EXECUTION"
    }
    rule = DetectionRuleEngine.check_suspicious_process(event)
    assert rule is not None
    assert rule["rule_id"] == "RULE-PROC-001"
    assert rule["severity"] == "HIGH"
    assert rule["mitre_technique"] == "T1059.001"


def test_large_data_transfer_rule_trigger():
    event = {
        "username": "dev_user",
        "event_type": "DATA_TRANSFER",
        "data_volume": 120 * 1024 * 1024  # 120MB
    }
    baseline = {
        "mean_transfer_volume": 2 * 1024 * 1024,
        "stddev_transfer_volume": 1 * 1024 * 1024
    }
    rule = DetectionRuleEngine.check_large_data_transfer(event, baseline)
    assert rule is not None
    assert rule["rule_id"] == "RULE-NET-001"
    assert rule["severity"] == "HIGH"
    assert rule["mitre_technique"] == "T1048"
