from datetime import datetime, timezone
from app.services.ml_anomaly_service import MLAnomalyService


def test_feature_vector_extraction():
    now = datetime.now(timezone.utc)
    event = {
        "timestamp": now,
        "username": "victim",
        "device_id": "NEW-LAPTOP-999",
        "location": "Berlin, Germany",
        "event_type": "AUTHENTICATION",
        "status": "FAILURE",
        "process_name": "mimikatz.exe",
        "data_volume": 60 * 1024 * 1024
    }
    recent = []
    baseline = {
        "active_hours_histogram": {"12": 10},
        "known_devices": ["DEV-WKS-001"],
        "typical_locations": ["New York, USA"],
        "common_processes": ["explorer.exe"]
    }

    vec = MLAnomalyService.extract_feature_vector(event, recent, baseline)
    assert len(vec) == 10
    # Failed logins index 0
    assert vec[0] == 1.0
    # New device index 4
    assert vec[4] == 1.0
    # New location index 5
    assert vec[5] == 1.0
    # Data transfer MB index 6
    assert vec[6] == 60.0
    # Process novelty index 7
    assert vec[7] == 1.0


def test_isolation_forest_anomaly_scoring():
    now = datetime.now(timezone.utc)
    # Extremely anomalous event
    anomalous_event = {
        "timestamp": now,
        "username": "compromised_user",
        "device_id": "UNKNOWN_DEVICE",
        "location": "Unknown Foreign Location",
        "event_type": "DATA_TRANSFER",
        "status": "SUCCESS",
        "process_name": "powershell.exe",
        "data_volume": 250 * 1024 * 1024
    }

    result = MLAnomalyService.evaluate_anomaly(anomalous_event, [])
    assert "anomaly_score" in result
    assert 0.0 <= result["anomaly_score"] <= 100.0
    assert result["label"] == "POTENTIAL ANOMALY"
    assert result["evidence_quality"] in ["LOW", "MEDIUM", "HIGH"]
    assert "contributing_features" in result
