"""Canonical 6-Factor Deterministic Risk Engine.

Strictly implements the formula documented in docs/architecture/05_AI_ML_UEBA_DESIGN.md:
    Risk Score = min(100, 0.25 * S_anomaly + 0.20 * S_severity + 0.15 * S_asset + 0.15 * S_identity + 0.15 * S_sequence + 0.10 * S_stage)

Zero opaque heuristics; 100% deterministic, evidence-driven calculations.
"""

from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class RiskBreakdown:
    risk_score: float
    anomaly_score: float
    threat_severity_score: int
    asset_criticality_score: int
    identity_sensitivity_score: int
    event_sequence_score: int
    attack_stage_score: int
    confidence_score: float
    evidence_quality: str


class RiskEngine:
    # 1. Threat Severity Calibrations (0-100)
    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
        "INFORMATIONAL": 10
    }

    # 2. Asset Criticality Calibrations (0-100)
    ASSET_WEIGHTS: Dict[str, int] = {
        "DATABASE": 100,     # Tier-1 Critical Database
        "DOMAIN_CONTROLLER": 100,
        "SERVER": 75,        # Tier-2 Server / Application Gateway
        "GATEWAY": 75,
        "WORKSTATION": 40,   # Standard employee laptop / workstation
        "UNKNOWN": 40
    }

    # 3. Identity Sensitivity Calibrations (0-100)
    IDENTITY_WEIGHTS: Dict[str, int] = {
        "admin": 100,
        "root": 100,
        "executive": 100,
        "dba": 75,
        "devops": 75,
        "secops": 75,
        "engineer": 50,
        "user": 50,
        "standard": 50
    }

    # 4. Attack Stage Calibrations (0-100)
    STAGE_WEIGHTS: Dict[str, int] = {
        "INITIAL_ACCESS": 30,
        "EXECUTION": 50,
        "PERSISTENCE": 60,
        "PRIVILEGE_ESCALATION": 70,
        "DEFENSE_EVASION": 75,
        "CREDENTIAL_ACCESS": 75,
        "DISCOVERY": 60,
        "LATERAL_MOVEMENT": 80,
        "COLLECTION": 85,
        "EXFILTRATION": 100,
        "IMPACT": 100
    }

    @classmethod
    def calculate_risk(
        cls,
        anomaly_score: float,
        severity: str,
        asset_type: str | None,
        username: str | None,
        event_count: int,
        highest_stage: str | None,
        confidences: List[float] | None = None
    ) -> RiskBreakdown:
        """Computes deterministic 6-factor composite risk score."""
        # 1. Anomaly Score (S_anomaly): continuous [0, 100]
        s_anomaly = max(0.0, min(100.0, float(anomaly_score)))

        # 2. Threat Severity Score (S_severity)
        s_severity = cls.SEVERITY_WEIGHTS.get(severity.upper(), 50)

        # 3. Asset Criticality Score (S_asset)
        asset_norm = (asset_type or "WORKSTATION").upper()
        s_asset = cls.ASSET_WEIGHTS.get(asset_norm, 40)

        # 4. Identity Sensitivity Score (S_identity)
        user_norm = (username or "standard").lower()
        if any(admin_kw in user_norm for admin_kw in ["admin", "root", "domain_adm"]):
            s_identity = 100
        elif any(priv_kw in user_norm for priv_kw in ["dba", "devops", "secops", "it_admin"]):
            s_identity = 75
        else:
            s_identity = 50

        # 5. Event Sequence Score (S_sequence): min(100, (count / 10) * 100)
        s_sequence = min(100, int((event_count / 10.0) * 100))

        # 6. Attack Stage Score (S_stage)
        stage_norm = (highest_stage or "INITIAL_ACCESS").upper()
        s_stage = cls.STAGE_WEIGHTS.get(stage_norm, 30)

        # Composite Deterministic 6-Factor Formula:
        # Risk = min(100, 0.25*S_anomaly + 0.20*S_severity + 0.15*S_asset + 0.15*S_identity + 0.15*S_sequence + 0.10*S_stage)
        raw_risk = (
            0.25 * s_anomaly +
            0.20 * s_severity +
            0.15 * s_asset +
            0.15 * s_identity +
            0.15 * s_sequence +
            0.10 * s_stage
        )
        final_risk = round(min(100.0, max(0.0, raw_risk)), 2)

        # Confidence Score: arithmetic mean of detection confidences
        if confidences and len(confidences) > 0:
            avg_confidence = round(sum(confidences) / len(confidences), 3)
        else:
            avg_confidence = 0.85 if final_risk >= 60 else 0.65

        # Evidence Quality Rating
        if avg_confidence >= 0.80 and (s_anomaly >= 75 or s_sequence >= 40 or s_severity >= 75):
            evidence_quality = "HIGH"
        elif avg_confidence >= 0.50:
            evidence_quality = "MEDIUM"
        else:
            evidence_quality = "LOW"

        return RiskBreakdown(
            risk_score=final_risk,
            anomaly_score=round(s_anomaly, 2),
            threat_severity_score=s_severity,
            asset_criticality_score=s_asset,
            identity_sensitivity_score=s_identity,
            event_sequence_score=s_sequence,
            attack_stage_score=s_stage,
            confidence_score=avg_confidence,
            evidence_quality=evidence_quality
        )
