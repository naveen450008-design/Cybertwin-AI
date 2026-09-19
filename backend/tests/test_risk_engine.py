import pytest
from app.services.risk_engine import RiskEngine


def test_canonical_risk_formula_baseline():
    """Validates the canonical 6-factor deterministic risk formula.
    Formula: Risk = min(100, 0.25*S_anomaly + 0.20*S_severity + 0.15*S_asset + 0.15*S_identity + 0.15*S_sequence + 0.10*S_stage)
    """
    # Anomaly: 0, Severity: LOW (25), Asset: WORKSTATION (40), Identity: standard (50), Events: 1 (10), Stage: INITIAL_ACCESS (30)
    # Expected: 0.25*0 + 0.20*25 + 0.15*40 + 0.15*50 + 0.15*10 + 0.10*30
    # = 0 + 5.0 + 6.0 + 7.5 + 1.5 + 3.0 = 23.0
    res = RiskEngine.calculate_risk(
        anomaly_score=0.0,
        severity="LOW",
        asset_type="WORKSTATION",
        username="john.doe",
        event_count=1,
        highest_stage="INITIAL_ACCESS"
    )
    assert res.risk_score == 23.0
    assert res.threat_severity_score == 25
    assert res.asset_criticality_score == 40
    assert res.identity_sensitivity_score == 50
    assert res.event_sequence_score == 10
    assert res.attack_stage_score == 30


def test_canonical_risk_formula_critical_attack():
    """Validates risk formula under high severity, critical asset, admin user, high anomaly, long chain."""
    # Anomaly: 80.0, Severity: CRITICAL (100), Asset: DATABASE (100), Identity: admin (100), Events: 10 (100), Stage: EXFILTRATION (100)
    # Expected: 0.25*80 + 0.20*100 + 0.15*100 + 0.15*100 + 0.15*100 + 0.10*100
    # = 20.0 + 20.0 + 15.0 + 15.0 + 15.0 + 10.0 = 95.0
    res = RiskEngine.calculate_risk(
        anomaly_score=80.0,
        severity="CRITICAL",
        asset_type="DATABASE",
        username="admin",
        event_count=10,
        highest_stage="EXFILTRATION",
        confidences=[0.95, 0.90]
    )
    assert res.risk_score == 95.0
    assert res.threat_severity_score == 100
    assert res.asset_criticality_score == 100
    assert res.identity_sensitivity_score == 100
    assert res.event_sequence_score == 100
    assert res.attack_stage_score == 100
    assert res.confidence_score == 0.925
    assert res.evidence_quality == "HIGH"


def test_risk_score_cap():
    """Validates that risk score never exceeds 100.0."""
    res = RiskEngine.calculate_risk(
        anomaly_score=100.0,
        severity="CRITICAL",
        asset_type="DATABASE",
        username="root",
        event_count=50,
        highest_stage="IMPACT"
    )
    assert res.risk_score == 100.0
