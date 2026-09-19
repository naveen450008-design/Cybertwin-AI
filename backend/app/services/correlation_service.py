"""15-Minute Sliding Window Alert Deduplication & Multi-Stage Event Correlation Service.

Clusters incoming security events and detection alerts sharing entities
(username, device_id, source_ip) into single cohesive security incidents.
Prevents alert fatigue and tracks multi-stage kill chains.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
import uuid
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.incident import Incident, IncidentEventMapping
from app.models.mitre import MitreTechnique, IncidentMitreMapping
from app.models.event import SecurityEvent
from app.models.asset import Asset
from app.services.risk_engine import RiskEngine
from app.services.mitre_service import MitreService


class CorrelationService:
    CORRELATION_WINDOW_MINUTES = 15
    SLA_MINUTES = 30

    @classmethod
    async def correlate_event(
        cls,
        db: AsyncSession,
        event: SecurityEvent
    ) -> Optional[Incident]:
        """Correlates a security event into an active incident or creates a new incident.
        
        Only correlates events that triggered a detection rule, had an anomaly score > 50,
        or have severity >= MEDIUM.
        """
        is_rule_trigger = bool(event.metadata_json.get("detection_rule_id"))
        anomaly_score = float(event.metadata_json.get("ml_anomaly_score", 0.0))
        is_anomalous = anomaly_score > 50.0
        is_high_sev = event.severity.upper() in ["HIGH", "CRITICAL"]

        if not (is_rule_trigger or is_anomalous or is_high_sev):
            return None

        event_ts = event.timestamp
        window_start = event_ts - timedelta(minutes=cls.CORRELATION_WINDOW_MINUTES)

        # 1. Search for active uncontained incident sharing username, device_id, or source_ip within window
        active_statuses = ["NEW", "INVESTIGATING", "CONTAINMENT_RECOMMENDED", "RESPONSE_PENDING"]
        stmt = (
            select(Incident)
            .join(IncidentEventMapping, Incident.incident_id == IncidentEventMapping.incident_id)
            .join(SecurityEvent, IncidentEventMapping.event_id == SecurityEvent.event_id)
            .where(
                Incident.status.in_(active_statuses),
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= event_ts + timedelta(minutes=5)
            )
            .options(
                selectinload(Incident.event_mappings).selectinload(IncidentEventMapping.incident),
                selectinload(Incident.mitre_mappings)
            )
            .order_by(desc(Incident.created_at))
        )

        matched_incident: Optional[Incident] = None
        correlation_reason = "Initial alert trigger"

        results = await db.execute(stmt)
        candidates = results.scalars().all()

        for inc in candidates:
            # Check entity matches
            for em in inc.event_mappings:
                linked_event_res = await db.execute(
                    select(SecurityEvent).where(SecurityEvent.event_id == em.event_id)
                )
                linked_ev = linked_event_res.scalar_one_or_none()
                if not linked_ev:
                    continue

                if event.username and linked_ev.username and event.username == linked_ev.username:
                    matched_incident = inc
                    correlation_reason = f"Shared identity: {event.username}"
                    break
                if event.device_id and linked_ev.device_id and event.device_id == linked_ev.device_id:
                    matched_incident = inc
                    correlation_reason = f"Shared host/device: {event.device_id}"
                    break
                if event.source_ip and linked_ev.source_ip and event.source_ip == linked_ev.source_ip:
                    matched_incident = inc
                    correlation_reason = f"Shared source IP: {event.source_ip}"
                    break

            if matched_incident:
                break

        # 2. Determine highest attack stage and asset type
        asset_type = "WORKSTATION"
        if event.device_name:
            asset_res = await db.execute(
                select(Asset).where(Asset.asset_name == event.device_name)
            )
            asset_obj = asset_res.scalar_one_or_none()
            if asset_obj:
                asset_type = asset_obj.asset_type

        # 3. Determine attack stage
        stage = "INITIAL_ACCESS"
        rule_id = event.metadata_json.get("detection_rule_id", "")
        if "PROC" in rule_id:
            stage = "EXECUTION"
        elif "NET" in rule_id or "EXFIL" in event.action.upper():
            stage = "EXFILTRATION"
        elif "CHAIN" in rule_id:
            stage = "LATERAL_MOVEMENT"

        # 4. If matching incident exists -> append and update
        if matched_incident:
            # Check if event already linked
            existing_mapping = await db.execute(
                select(IncidentEventMapping).where(
                    IncidentEventMapping.incident_id == matched_incident.incident_id,
                    IncidentEventMapping.event_id == event.event_id
                )
            )
            if existing_mapping.scalar_one_or_none() is None:
                seq_idx = len(matched_incident.event_mappings) + 1
                mapping = IncidentEventMapping(
                    incident_id=matched_incident.incident_id,
                    event_id=event.event_id,
                    correlation_reason=correlation_reason,
                    sequence_index=seq_idx
                )
                db.add(mapping)

                # Map MITRE techniques
                mitre_matches = MitreService.map_event_to_techniques(event)
                for mm in mitre_matches:
                    tech_exists = await db.execute(
                        select(MitreTechnique).where(MitreTechnique.technique_id == mm["technique_id"])
                    )
                    if not tech_exists.scalar_one_or_none():
                        rec = MitreService.CATALOG.get(mm["technique_id"])
                        if rec:
                            new_tech = MitreTechnique(
                                technique_id=rec.technique_id,
                                technique_name=rec.technique_name,
                                tactics=[rec.tactic],
                                description=rec.description
                            )
                            db.add(new_tech)
                            await db.flush()

                    mitre_map = IncidentMitreMapping(
                        incident_id=matched_incident.incident_id,
                        technique_id=mm["technique_id"],
                        tactic=mm["tactic"],
                        evidence_event_id=event.event_id,
                        confidence=mm["confidence"]
                    )
                    db.add(mitre_map)

                # Recompute Risk
                total_events = len(matched_incident.event_mappings) + 1
                max_anomaly = max(matched_incident.anomaly_score, anomaly_score)
                risk_breakdown = RiskEngine.calculate_risk(
                    anomaly_score=max_anomaly,
                    severity=event.severity,
                    asset_type=asset_type,
                    username=event.username,
                    event_count=total_events,
                    highest_stage=stage
                )

                matched_incident.risk_score = risk_breakdown.risk_score
                matched_incident.anomaly_score = risk_breakdown.anomaly_score
                matched_incident.threat_severity_score = risk_breakdown.threat_severity_score
                matched_incident.asset_criticality_score = risk_breakdown.asset_criticality_score
                matched_incident.identity_sensitivity_score = risk_breakdown.identity_sensitivity_score
                matched_incident.event_sequence_score = risk_breakdown.event_sequence_score
                matched_incident.attack_stage_score = risk_breakdown.attack_stage_score
                matched_incident.confidence_score = risk_breakdown.confidence_score
                matched_incident.evidence_quality = risk_breakdown.evidence_quality
                matched_incident.updated_at = datetime.now(timezone.utc)

                await db.commit()
                await db.refresh(matched_incident)
                return matched_incident

        # 5. Otherwise create new Incident
        title = f"Security Incident: {event.event_type} on {event.device_name or event.source_ip or 'Network'}"
        risk_breakdown = RiskEngine.calculate_risk(
            anomaly_score=anomaly_score,
            severity=event.severity,
            asset_type=asset_type,
            username=event.username,
            event_count=1,
            highest_stage=stage
        )

        sla_deadline = event_ts + timedelta(minutes=cls.SLA_MINUTES)

        new_incident = Incident(
            incident_id=uuid.uuid4(),
            incident_title=title,
            status="NEW",
            severity=event.severity,
            risk_score=risk_breakdown.risk_score,
            anomaly_score=risk_breakdown.anomaly_score,
            threat_severity_score=risk_breakdown.threat_severity_score,
            asset_criticality_score=risk_breakdown.asset_criticality_score,
            identity_sensitivity_score=risk_breakdown.identity_sensitivity_score,
            event_sequence_score=risk_breakdown.event_sequence_score,
            attack_stage_score=risk_breakdown.attack_stage_score,
            confidence_score=risk_breakdown.confidence_score,
            evidence_quality=risk_breakdown.evidence_quality,
            sla_breach_deadline=sla_deadline,
            created_at=event_ts,
            updated_at=event_ts
        )
        db.add(new_incident)
        await db.flush()

        # Add event mapping
        mapping = IncidentEventMapping(
            incident_id=new_incident.incident_id,
            event_id=event.event_id,
            correlation_reason="Initial correlated alert trigger",
            sequence_index=1,
            added_at=event_ts
        )
        db.add(mapping)

        # Map MITRE techniques
        mitre_matches = MitreService.map_event_to_techniques(event)
        for mm in mitre_matches:
            tech_exists = await db.execute(
                select(MitreTechnique).where(MitreTechnique.technique_id == mm["technique_id"])
            )
            if not tech_exists.scalar_one_or_none():
                rec = MitreService.CATALOG.get(mm["technique_id"])
                if rec:
                    new_tech = MitreTechnique(
                        technique_id=rec.technique_id,
                        technique_name=rec.technique_name,
                        tactics=[rec.tactic],
                        description=rec.description
                    )
                    db.add(new_tech)
                    await db.flush()

            mitre_map = IncidentMitreMapping(
                incident_id=new_incident.incident_id,
                technique_id=mm["technique_id"],
                tactic=mm["tactic"],
                evidence_event_id=event.event_id,
                confidence=mm["confidence"]
            )
            db.add(mitre_map)

        await db.commit()
        await db.refresh(new_incident)
        return new_incident
