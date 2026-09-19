import ipaddress
import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_, desc
from sqlalchemy.orm import selectinload

from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEventMapping
from app.models.mitre import MitreTechnique, IncidentMitreMapping
from app.models.user import User
from app.schemas.ip_intelligence import (
    IPIntelligenceSummary,
    IPIntelligenceDetail,
    IPRiskProfileBreakdown,
    IPBehaviourProfile,
    IPActivityTimelineItem,
    IPEntityRelationshipGraph,
    IPEntityNode,
    IPEntityEdge,
    IPAttackPathStep,
    IPClusterItem,
    ThreatRadarEntity,
    ThreatRadarResponse,
    SecurityHealthScoreResponse,
)


class IPIntelligenceService:
    """Defensive, passive IP Threat Intelligence service strictly utilizing internal database evidence."""

    # RFC 1918 and RFC 5737 Subnet definitions
    RFC1918_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    # RFC 5737 / RFC 3849 testnets representing external public internet simulation subnets
    SYNTHETIC_WAN_TESTNETS = [
        ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (used for external attacker scenarios)
        ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3 (used for impossible travel external scenarios)
        ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ]

    @classmethod
    def classify_ip_type(cls, ip_str: str) -> Tuple[str, bool, int, str]:
        """Classifies IP address using Python standard ipaddress without any network probing.
        Returns: (ip_type, is_internal, ip_version, cidr_classification)
        """
        if not ip_str or not isinstance(ip_str, str) or ip_str.strip() == "":
            return ("Unknown", False, 4, "RFC_UNKNOWN")

        # Strip ports or whitespace if present
        clean_ip = ip_str.split(":")[0].strip()

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            version = ip_obj.version

            if ip_obj.is_loopback:
                return ("Loopback", True, version, "RFC 1122 Loopback (127.0.0.0/8 or ::1)")

            # Check if it falls into synthetic external WAN test networks
            if any(ip_obj in net for net in cls.SYNTHETIC_WAN_TESTNETS):
                return ("Public", False, version, "External WAN Address (Synthetic ATT&CK Testbed)")

            # Check if strictly RFC 1918 private network
            if any(ip_obj in net for net in cls.RFC1918_NETWORKS) or (version == 6 and ip_obj.is_private):
                return ("Private", True, version, "RFC 1918 Private Enterprise Network")

            if ip_obj.is_link_local:
                return ("Link-Local", True, version, "RFC 3927 Link-Local Subnet")
            elif ip_obj.is_reserved:
                return ("Reserved", False, version, "IETF Reserved Address Space")
            elif ip_obj.is_multicast:
                return ("Multicast", False, version, "RFC 5771 Multicast Network")
            elif ip_obj.is_global:
                return ("Public", False, version, "Public Internet Routed Address")
            else:
                return ("Unknown", False, version, "Unclassified Address Range")
        except ValueError:
            return ("Unknown", False, 4, "Invalid or Obfuscated IP Format")

    @staticmethod
    def is_viewer_only(current_user: Optional[User]) -> bool:
        """Determines if the requesting operator is exclusively a Viewer (requiring PII masking)."""
        if not current_user:
            return True
        roles = [r.name for r in current_user.roles]
        return "Viewer" in roles and len(roles) == 1

    @staticmethod
    def mask_ip(ip_str: Optional[str], viewer_mode: bool) -> str:
        """Applies privacy masking if viewer_mode is enabled."""
        if not ip_str:
            return "UNKNOWN"
        if not viewer_mode:
            return ip_str
        if "." in ip_str:
            parts = ip_str.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.***.***"
        return ip_str

    @staticmethod
    def mask_username(username: Optional[str], viewer_mode: bool) -> Optional[str]:
        """Applies username masking for privacy if viewer_mode is enabled."""
        if not username:
            return None
        if not viewer_mode:
            return username
        return username[0] + "***" if len(username) > 1 else "***"

    @classmethod
    async def get_all_observed_ips_summary(
        cls,
        db: AsyncSession,
        current_user: Optional[User] = None
    ) -> List[IPIntelligenceSummary]:
        """Aggregates all unique observed IP addresses across events into summary intelligence profiles."""
        viewer_mode = cls.is_viewer_only(current_user)

        # Query distinct source and destination IPs with event counts and anomalies
        stmt = (
            select(
                SecurityEvent.source_ip,
                func.count(SecurityEvent.event_id).label("total_events"),
                func.max(SecurityEvent.timestamp).label("last_seen"),
                func.max(SecurityEvent.location).label("primary_location"),
            )
            .where(SecurityEvent.source_ip.isnot(None))
            .group_by(SecurityEvent.source_ip)
            .order_by(desc("total_events"))
        )
        result = await db.execute(stmt)
        rows = result.all()

        summaries: List[IPIntelligenceSummary] = []
        for src_ip, total_events, last_seen, primary_loc in rows:
            if not src_ip or src_ip.strip() == "":
                continue

            # Query anomaly count for this IP
            anomaly_stmt = (
                select(func.count(SecurityEvent.event_id))
                .where(
                    and_(
                        SecurityEvent.source_ip == src_ip,
                        or_(
                            SecurityEvent.severity.in_(["HIGH", "CRITICAL"]),
                            SecurityEvent.status.in_(["DENIED", "FAILURE", "ERROR"])
                        )
                    )
                )
            )
            anom_res = await db.execute(anomaly_stmt)
            total_anomalies = anom_res.scalar() or 0

            # Query incident count associated with this IP
            inc_stmt = (
                select(func.count(func.distinct(IncidentEventMapping.incident_id)))
                .select_from(IncidentEventMapping)
                .join(SecurityEvent, IncidentEventMapping.event_id == SecurityEvent.event_id)
                .where(SecurityEvent.source_ip == src_ip)
            )
            inc_res = await db.execute(inc_stmt)
            total_incidents = inc_res.scalar() or 0

            # Classify IP
            ip_type, is_internal, version, _ = cls.classify_ip_type(src_ip)

            # Compute Derived IP Risk Profile Score
            vol_factor = min(100.0, total_events * 8.0)
            anom_factor = min(100.0, (total_anomalies / max(1, total_events)) * 100.0 if total_events else 0.0)
            inc_factor = min(100.0, total_incidents * 35.0)
            base_risk = 0.30 * vol_factor + 0.35 * anom_factor + 0.35 * inc_factor
            
            # External non-RFC1918 addresses involved in attacks receive elevated focus
            if not is_internal and (total_anomalies > 0 or total_incidents > 0):
                base_risk = min(100.0, base_risk * 1.25)

            final_risk = round(min(100.0, max(5.0, base_risk)), 1)

            if final_risk >= 75:
                threat_level = "CRITICAL"
            elif final_risk >= 50:
                threat_level = "HIGH"
            elif final_risk >= 25:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            display_ip = cls.mask_ip(src_ip, viewer_mode)

            summaries.append(
                IPIntelligenceSummary(
                    ip_address=display_ip,
                    ip_type=ip_type,
                    is_internal=is_internal,
                    version=version,
                    total_events=total_events,
                    total_anomalies=total_anomalies,
                    total_incidents=total_incidents,
                    ip_risk_score=final_risk,
                    threat_level=threat_level,
                    primary_location=primary_loc or ("Internal Corporate Network" if is_internal else "Data unavailable"),
                    last_seen=last_seen
                )
            )

        return summaries

    @classmethod
    async def get_ip_deep_intelligence(
        cls,
        db: AsyncSession,
        raw_ip: str,
        current_user: Optional[User] = None
    ) -> Optional[IPIntelligenceDetail]:
        """Builds a comprehensive, passive intelligence profile for a specific IP address using strictly internal evidence."""
        viewer_mode = cls.is_viewer_only(current_user)

        # Retrieve all events matching this IP (as source or destination)
        stmt = (
            select(SecurityEvent)
            .where(or_(SecurityEvent.source_ip == raw_ip, SecurityEvent.destination_ip == raw_ip))
            .order_by(SecurityEvent.timestamp.asc())
        )
        result = await db.execute(stmt)
        events = result.scalars().all()

        if not events:
            # If no events found directly, check if it's a valid IP format anyway
            ip_type, is_internal, version, cidr = cls.classify_ip_type(raw_ip)
            return IPIntelligenceDetail(
                ip_address=cls.mask_ip(raw_ip, viewer_mode),
                ip_type=ip_type,
                is_internal=is_internal,
                version=version,
                cidr_classification=cidr,
                geo={"status": "Data unavailable", "city": "Unknown", "country": "Unknown", "coordinates": "Approximate coords unavailable"},
                network={"asn": "Data unavailable", "isp": "Unknown", "hostname": "Data unavailable"},
                reputation={
                    "status": "Reputation data unavailable",
                    "configured_source": None,
                    "disclaimer": "Zero active network probes performed. Displaying passive evidence only.",
                    "confidence": 0.0
                },
                risk_profile=IPRiskProfileBreakdown(
                    ip_risk_score=10.0,
                    threat_level="LOW",
                    event_volume_score=0.0,
                    anomaly_factor_score=0.0,
                    incident_factor_score=0.0,
                    severity_factor_score=0.0,
                    mitre_factor_score=0.0,
                    formula_documentation="No historical events detected in local database for this IP.",
                    evidence_source="INTERNAL_SECURITY_EVIDENCE"
                ),
                behaviour=IPBehaviourProfile(),
                timeline=[],
                entity_graph=IPEntityRelationshipGraph(nodes=[], edges=[]),
                attack_path=[],
                related_clusters=[]
            )

        # Classify IP Address
        ip_type, is_internal, version, cidr = cls.classify_ip_type(raw_ip)

        # Gather Event IDs for incident lookups
        event_ids = [e.event_id for e in events]
        inc_mapping_stmt = (
            select(IncidentEventMapping, Incident)
            .join(Incident, IncidentEventMapping.incident_id == Incident.incident_id)
            .where(IncidentEventMapping.event_id.in_(event_ids))
            .options(
                selectinload(Incident.mitre_mappings).selectinload(IncidentMitreMapping.technique)
            )
        )
        inc_res = await db.execute(inc_mapping_stmt)
        inc_mappings = inc_res.all()

        # Map event_id -> list of incident IDs and mitre techniques
        event_to_incidents: Dict[str, List[str]] = {}
        all_incident_objs: Dict[str, Incident] = {}
        associated_mitre: Set[str] = set()

        for mapping, incident_obj in inc_mappings:
            eid_str = str(mapping.event_id)
            inc_id_str = str(incident_obj.incident_id)
            event_to_incidents.setdefault(eid_str, []).append(inc_id_str)
            all_incident_objs[inc_id_str] = incident_obj
            for m in incident_obj.mitre_mappings:
                tname = m.technique.technique_name if m.technique else m.technique_id
                associated_mitre.add(f"{m.technique_id} - {tname}")

        # Compute Behavioural Profile
        total_events = len(events)
        users = sorted(list({e.username for e in events if e.username}))
        devices = sorted(list({e.device_name or e.device_id for e in events if (e.device_name or e.device_id)}))
        servers = sorted(list({e.server_id for e in events if e.server_id}))
        first_seen = events[0].timestamp if events else None
        last_seen = events[-1].timestamp if events else None

        # Calculate Anomaly Stats
        anomaly_count = 0
        severity_weights = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFORMATIONAL": 10}
        max_severity_score = 10
        anomaly_scores: List[float] = []

        for e in events:
            sev_score = severity_weights.get(e.severity.upper(), 10)
            if sev_score > max_severity_score:
                max_severity_score = sev_score

            meta = e.metadata_json or {}
            score = meta.get("ml_anomaly_score")
            if score is not None and float(score) > 50.0:
                anomaly_count += 1
                anomaly_scores.append(float(score))
            elif e.severity in ["HIGH", "CRITICAL"] or e.status in ["FAILURE", "DENIED"]:
                anomaly_count += 1

        avg_anom_score = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else (
            (anomaly_count / max(1, total_events)) * 100.0
        )

        # Derived IP Risk Profile Formula Breakdown
        s_vol = min(100.0, total_events * 10.0)
        s_anom = min(100.0, avg_anom_score)
        s_inc = min(100.0, len(all_incident_objs) * 35.0)
        s_sev = float(max_severity_score)
        s_mitre = min(100.0, len(associated_mitre) * 25.0)

        # Transparent derived IP Risk Profile formula:
        # Score = min(100, 0.25*S_vol + 0.25*S_anom + 0.20*S_inc + 0.15*S_sev + 0.15*S_mitre)
        raw_ip_risk = (
            0.25 * s_vol +
            0.25 * s_anom +
            0.20 * s_inc +
            0.15 * s_sev +
            0.15 * s_mitre
        )
        if not is_internal and (anomaly_count > 0 or len(all_incident_objs) > 0):
            raw_ip_risk = min(100.0, raw_ip_risk * 1.20)

        final_ip_risk = round(min(100.0, max(5.0, raw_ip_risk)), 1)
        if final_ip_risk >= 75:
            threat_level = "CRITICAL"
        elif final_ip_risk >= 50:
            threat_level = "HIGH"
        elif final_ip_risk >= 25:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        risk_profile = IPRiskProfileBreakdown(
            ip_risk_score=final_ip_risk,
            threat_level=threat_level,
            event_volume_score=round(s_vol, 1),
            anomaly_factor_score=round(s_anom, 1),
            incident_factor_score=round(s_inc, 1),
            severity_factor_score=round(s_sev, 1),
            mitre_factor_score=round(s_mitre, 1),
            formula_documentation=(
                "IP Risk Profile = min(100, 0.25*S_vol + 0.25*S_anomaly + 0.20*S_incident + "
                "0.15*S_severity + 0.15*S_mitre). Derived solely from active telemetry evidence."
            ),
            evidence_source="INTERNAL_SECURITY_EVIDENCE"
        )

        # Passive Geo extraction from events
        locations = [e.location for e in events if e.location]
        primary_location = locations[-1] if locations else ("Internal Corporate Site" if is_internal else "Data unavailable")
        geo_data = {
            "primary_location": primary_location,
            "recorded_locations": list(set(locations)) if locations else ["Data unavailable"],
            "approximate_coordinates": "Approximate: City-level aggregation only (no physical coordinates)",
            "telemetry_source": "Stored event location field"
        }

        # Network Information from telemetry
        network_data = {
            "cidr_category": cidr,
            "ip_version": version,
            "address_type": "Internal / RFC1918 Subnet" if is_internal else "External / Public WAN Address",
            "reverse_dns": "Data unavailable (passive mode - zero external DNS queries triggered)",
            "asn_routing": "Data unavailable (unconfigured local research testbed)"
        }

        # Explicit Reputation Disclosure (Non-fabricated)
        reputation_data = {
            "status": "Reputation data unavailable",
            "reason": "No external threat intelligence provider configured in local research testbed",
            "disclaimer": "Defensive passive analysis only; zero active port scanning or probing performed.",
            "source_classification": "EXTERNAL_IP_INTELLIGENCE_DISCLAIMER",
            "internal_evidence_status": "ACTIVE_EVENTS_RECORDED"
        }

        # Build Chronological Timeline
        timeline_items: List[IPActivityTimelineItem] = []
        for e in events:
            eid_str = str(e.event_id)
            meta = e.metadata_json or {}
            anom_val = meta.get("ml_anomaly_score")
            rule_id = meta.get("detection_rule_id")

            timeline_items.append(
                IPActivityTimelineItem(
                    event_id=e.event_id,
                    timestamp=e.timestamp,
                    event_type=e.event_type,
                    action=e.action,
                    severity=e.severity,
                    status=e.status,
                    username=cls.mask_username(e.username, viewer_mode),
                    destination_ip=cls.mask_ip(e.destination_ip, viewer_mode),
                    device_name=e.device_name or e.device_id,
                    server_id=e.server_id,
                    process_name=e.process_name,
                    is_anomaly=bool(anom_val and float(anom_val) > 50.0) or bool(rule_id),
                    anomaly_score=float(anom_val) if anom_val else None,
                    detection_rule_id=rule_id,
                    incident_ids=event_to_incidents.get(eid_str, [])
                )
            )

        # Build Entity Relationship Graph
        # [IP] -> [Users], [Devices], [Servers] -> [Incidents] -> [MITRE Techniques]
        display_ip = cls.mask_ip(raw_ip, viewer_mode)
        nodes: List[IPEntityNode] = []
        edges: List[IPEntityEdge] = []
        seen_node_ids: Set[str] = set()

        ip_node_id = f"ip-{raw_ip}"
        nodes.append(IPEntityNode(
            id=ip_node_id,
            type="ip",
            label=f"IP: {display_ip}",
            severity=threat_level,
            metadata={"ip": display_ip, "type": ip_type, "is_internal": is_internal}
        ))
        seen_node_ids.add(ip_node_id)

        for u in users:
            disp_u = cls.mask_username(u, viewer_mode) or "unknown"
            u_id = f"user-{u}"
            if u_id not in seen_node_ids:
                nodes.append(IPEntityNode(
                    id=u_id,
                    type="user",
                    label=f"User: {disp_u}",
                    metadata={"username": disp_u}
                ))
                seen_node_ids.add(u_id)
            edges.append(IPEntityEdge(
                id=f"edge-{ip_node_id}-{u_id}",
                source=ip_node_id,
                target=u_id,
                label="Observed Authentication"
            ))

        for d in devices:
            d_id = f"dev-{d}"
            if d_id not in seen_node_ids:
                nodes.append(IPEntityNode(
                    id=d_id,
                    type="device",
                    label=f"Host: {d}",
                    metadata={"device": d}
                ))
                seen_node_ids.add(d_id)
            edges.append(IPEntityEdge(
                id=f"edge-{ip_node_id}-{d_id}",
                source=ip_node_id,
                target=d_id,
                label="Network Link"
            ))

        for s in servers:
            s_id = f"srv-{s}"
            if s_id not in seen_node_ids:
                nodes.append(IPEntityNode(
                    id=s_id,
                    type="server",
                    label=f"Target: {s}",
                    metadata={"server": s}
                ))
                seen_node_ids.add(s_id)
            edges.append(IPEntityEdge(
                id=f"edge-{ip_node_id}-{s_id}",
                source=ip_node_id,
                target=s_id,
                label="Target Server"
            ))

        for inc_id, inc_obj in all_incident_objs.items():
            inc_node_id = f"inc-{inc_id}"
            if inc_node_id not in seen_node_ids:
                nodes.append(IPEntityNode(
                    id=inc_node_id,
                    type="incident",
                    label=f"Incident: {inc_obj.incident_title[:28]}...",
                    severity=inc_obj.severity,
                    metadata={"incident_id": str(inc_obj.incident_id), "risk_score": inc_obj.risk_score}
                ))
                seen_node_ids.add(inc_node_id)
            edges.append(IPEntityEdge(
                id=f"edge-{ip_node_id}-{inc_node_id}",
                source=ip_node_id,
                target=inc_node_id,
                label="Correlated Evidence"
            ))

            for m in inc_obj.mitre_mappings:
                m_node_id = f"mitre-{m.technique_id}"
                if m_node_id not in seen_node_ids:
                    tname = m.technique.technique_name if m.technique else m.technique_id
                    nodes.append(IPEntityNode(
                        id=m_node_id,
                        type="mitre",
                        label=f"ATT&CK: {m.technique_id}",
                        metadata={"technique_id": m.technique_id, "technique_name": tname, "tactic": m.tactic}
                    ))
                    seen_node_ids.add(m_node_id)
                edges.append(IPEntityEdge(
                    id=f"edge-{inc_node_id}-{m_node_id}",
                    source=inc_node_id,
                    target=m_node_id,
                    label=m.tactic
                ))

        # Build Attack Path Sequence
        attack_path: List[IPAttackPathStep] = []
        step_idx = 1
        attack_path.append(IPAttackPathStep(
            step_number=step_idx,
            stage_name="SOURCE IP ENTRY",
            entity_type="IP",
            entity_name=display_ip,
            description=f"Inbound traffic observed from {ip_type} address ({cidr}).",
            timestamp=first_seen,
            severity="INFORMATIONAL"
        ))

        first_auth_event = next((e for e in events if e.event_type == "AUTHENTICATION"), None)
        if first_auth_event:
            step_idx += 1
            attack_path.append(IPAttackPathStep(
                step_number=step_idx,
                stage_name="AUTHENTICATION ATTEMPT",
                entity_type="EVENT",
                entity_name=first_auth_event.action,
                description=f"Action '{first_auth_event.action}' targeted user '{cls.mask_username(first_auth_event.username, viewer_mode)}'. Status: {first_auth_event.status}.",
                timestamp=first_auth_event.timestamp,
                severity=first_auth_event.severity
            ))

        if users:
            step_idx += 1
            attack_path.append(IPAttackPathStep(
                step_number=step_idx,
                stage_name="TARGET USER IDENTITY",
                entity_type="USER",
                entity_name=cls.mask_username(users[0], viewer_mode) or "unknown",
                description=f"Observed user identity linked to ingress events from {display_ip}.",
                timestamp=first_seen,
                severity="MEDIUM"
            ))

        if devices:
            step_idx += 1
            attack_path.append(IPAttackPathStep(
                step_number=step_idx,
                stage_name="ENDPOINT / HOST TARGET",
                entity_type="DEVICE",
                entity_name=devices[0],
                description=f"Originating or relay workstation asset '{devices[0]}'.",
                timestamp=first_seen,
                severity="MEDIUM"
            ))

        if servers:
            step_idx += 1
            attack_path.append(IPAttackPathStep(
                step_number=step_idx,
                stage_name="DESTINATION SERVICE / SERVER",
                entity_type="SERVER",
                entity_name=servers[0],
                description=f"Lateral or direct connection target server '{servers[0]}'.",
                timestamp=last_seen,
                severity="HIGH"
            ))

        if all_incident_objs:
            first_inc = list(all_incident_objs.values())[0]
            step_idx += 1
            attack_path.append(IPAttackPathStep(
                step_number=step_idx,
                stage_name="CORRELATED SECURITY INCIDENT",
                entity_type="INCIDENT",
                entity_name=first_inc.incident_title,
                description=f"Clustered into incident '{first_inc.incident_title}' with composite Risk Score {first_inc.risk_score}.",
                timestamp=first_inc.created_at,
                severity=first_inc.severity
            ))

        if associated_mitre:
            tech_sample = list(associated_mitre)[0]
            step_idx += 1
            attack_path.append(IPAttackPathStep(
                step_number=step_idx,
                stage_name="MITRE ATT&CK EVIDENCE MAPPING",
                entity_type="MITRE",
                entity_name=tech_sample,
                description=f"Evidence grounded to enterprise ATT&CK technique '{tech_sample}'.",
                timestamp=last_seen,
                severity="CRITICAL" if final_ip_risk >= 70 else "HIGH"
            ))

        # Build IP Clusters (Observed Related Activity)
        # Find other IPs that co-occurred in the same incidents
        related_clusters: List[IPClusterItem] = []
        if all_incident_objs:
            inc_ids = [inc.incident_id for inc in all_incident_objs.values()]
            co_stmt = (
                select(SecurityEvent.source_ip, func.count(SecurityEvent.event_id), func.max(SecurityEvent.timestamp))
                .join(IncidentEventMapping, SecurityEvent.event_id == IncidentEventMapping.event_id)
                .where(
                    and_(
                        IncidentEventMapping.incident_id.in_(inc_ids),
                        SecurityEvent.source_ip != raw_ip,
                        SecurityEvent.source_ip.isnot(None)
                    )
                )
                .group_by(SecurityEvent.source_ip)
                .limit(5)
            )
            co_res = await db.execute(co_stmt)
            co_rows = co_res.all()

            for co_ip, count_events, co_last in co_rows:
                co_type, _, _, _ = cls.classify_ip_type(co_ip)
                related_clusters.append(
                    IPClusterItem(
                        related_ip=cls.mask_ip(co_ip, viewer_mode),
                        ip_type=co_type,
                        relationship_type="Observed relationship (Co-occurred in correlated security incident)",
                        shared_incidents_count=len(inc_ids),
                        shared_targets_count=len(servers) + len(devices),
                        last_co_occurrence=co_last
                    )
                )

        behaviour = IPBehaviourProfile(
            first_seen=first_seen,
            last_seen=last_seen,
            total_events=total_events,
            total_anomalies=anomaly_count,
            total_incidents=len(all_incident_objs),
            associated_users=[cls.mask_username(u, viewer_mode) or "unknown" for u in users],
            associated_devices=devices,
            associated_servers=servers,
            associated_mitre_techniques=sorted(list(associated_mitre))
        )

        return IPIntelligenceDetail(
            ip_address=display_ip,
            ip_type=ip_type,
            is_internal=is_internal,
            version=version,
            cidr_classification=cidr,
            geo=geo_data,
            network=network_data,
            reputation=reputation_data,
            risk_profile=risk_profile,
            behaviour=behaviour,
            timeline=timeline_items,
            entity_graph=IPEntityRelationshipGraph(nodes=nodes, edges=edges),
            attack_path=attack_path,
            related_clusters=related_clusters
        )

    @classmethod
    async def get_threat_radar_entities(
        cls,
        db: AsyncSession,
        current_user: Optional[User] = None
    ) -> ThreatRadarResponse:
        """Generates polar coordinates for currently observed security entities on the Threat Radar."""
        viewer_mode = cls.is_viewer_only(current_user)
        entities: List[ThreatRadarEntity] = []

        # 1. Suspicious / Observed IPs (Quadrant 1: 15 to 75 degrees)
        ip_summaries = await cls.get_all_observed_ips_summary(db, current_user)
        for i, ip_sum in enumerate(ip_summaries[:8]):
            angle = 15.0 + (i * 8.0) % 65.0
            # Higher threat score = smaller distance (closer to center of radar)
            distance = round(max(15.0, min(85.0, 100.0 - (ip_sum.ip_risk_score * 0.75))), 1)
            entities.append(
                ThreatRadarEntity(
                    id=f"radar-ip-{i}",
                    entity_type="IP",
                    label=ip_sum.ip_address,
                    threat_score=ip_sum.ip_risk_score,
                    severity=ip_sum.threat_level,
                    distance=distance,
                    angle=angle,
                    metadata={
                        "ip_type": ip_sum.ip_type,
                        "events": ip_sum.total_events,
                        "anomalies": ip_sum.total_anomalies,
                        "incidents": ip_sum.total_incidents
                    }
                )
            )

        # 2. Correlated Incidents (Quadrant 2: 105 to 165 degrees)
        inc_stmt = select(Incident).order_by(desc(Incident.risk_score)).limit(6)
        inc_res = await db.execute(inc_stmt)
        incidents = inc_res.scalars().all()

        for i, inc in enumerate(incidents):
            angle = 105.0 + (i * 10.0) % 65.0
            distance = round(max(12.0, min(85.0, 100.0 - (inc.risk_score * 0.75))), 1)
            entities.append(
                ThreatRadarEntity(
                    id=f"radar-inc-{inc.incident_id}",
                    entity_type="INCIDENT",
                    label=inc.incident_title[:24] + "...",
                    threat_score=inc.risk_score,
                    severity=inc.severity,
                    distance=distance,
                    angle=angle,
                    metadata={"incident_id": str(inc.incident_id), "status": inc.status}
                )
            )

        # 3. Anomalous Users (Quadrant 3: 195 to 255 degrees)
        user_stmt = (
            select(SecurityEvent.username, func.count(SecurityEvent.event_id).label("cnt"))
            .where(
                and_(
                    SecurityEvent.username.isnot(None),
                    SecurityEvent.severity.in_(["HIGH", "CRITICAL"])
                )
            )
            .group_by(SecurityEvent.username)
            .order_by(desc("cnt"))
            .limit(5)
        )
        user_res = await db.execute(user_stmt)
        user_rows = user_res.all()

        for i, (uname, cnt) in enumerate(user_rows):
            angle = 195.0 + (i * 12.0) % 65.0
            user_threat = min(95.0, 40.0 + (cnt * 10.0))
            distance = round(max(15.0, min(85.0, 100.0 - (user_threat * 0.75))), 1)
            entities.append(
                ThreatRadarEntity(
                    id=f"radar-user-{i}",
                    entity_type="USER",
                    label=f"User: {cls.mask_username(uname, viewer_mode)}",
                    threat_score=user_threat,
                    severity="HIGH" if user_threat >= 70 else "MEDIUM",
                    distance=distance,
                    angle=angle,
                    metadata={"high_sev_events": cnt}
                )
            )

        # 4. Impacted Devices / Gateways (Quadrant 4: 285 to 345 degrees)
        dev_stmt = (
            select(SecurityEvent.device_name, func.count(SecurityEvent.event_id).label("cnt"))
            .where(SecurityEvent.device_name.isnot(None))
            .group_by(SecurityEvent.device_name)
            .order_by(desc("cnt"))
            .limit(5)
        )
        dev_res = await db.execute(dev_stmt)
        dev_rows = dev_res.all()

        for i, (dname, cnt) in enumerate(dev_rows):
            angle = 285.0 + (i * 12.0) % 65.0
            dev_threat = min(90.0, 30.0 + (cnt * 5.0))
            distance = round(max(18.0, min(85.0, 100.0 - (dev_threat * 0.75))), 1)
            entities.append(
                ThreatRadarEntity(
                    id=f"radar-dev-{i}",
                    entity_type="DEVICE",
                    label=f"Host: {dname}",
                    threat_score=dev_threat,
                    severity="HIGH" if dev_threat >= 70 else "MEDIUM",
                    distance=distance,
                    angle=angle,
                    metadata={"event_count": cnt}
                )
            )

        return ThreatRadarResponse(
            classification="VISUAL_ANALYTICS_INTERNAL_OBSERVED_ENTITIES",
            description="Polar radar mapping of internal observed security entities across four quadrants.",
            entities=entities,
            total_tracked=len(entities)
        )

    @classmethod
    async def get_tenant_security_health_score(
        cls,
        db: AsyncSession,
        current_user: Optional[User] = None
    ) -> SecurityHealthScoreResponse:
        """Computes transparent tenant-wide Security Health Score from real database incident and anomaly evidence."""
        # Query incidents
        inc_stmt = select(Incident)
        inc_res = await db.execute(inc_stmt)
        incidents = inc_res.scalars().all()

        active_incidents = [i for i in incidents if i.status not in ["RESOLVED", "CLOSED", "FALSE_POSITIVE"]]
        critical_incidents = [i for i in active_incidents if i.severity == "CRITICAL" or i.risk_score >= 75.0]

        # Anomaly count
        anom_stmt = select(func.count(SecurityEvent.event_id)).where(SecurityEvent.severity.in_(["HIGH", "CRITICAL"]))
        anom_res = await db.execute(anom_stmt)
        total_anomalies = anom_res.scalar() or 0

        # Query high-risk IPs
        all_ips = await cls.get_all_observed_ips_summary(db, current_user)
        high_risk_ips = [ip for ip in all_ips if ip.ip_risk_score >= 50.0]

        # Canonical Tenant Formula:
        # Health = 100 - (0.25*I_risk + 0.20*E_posture + 0.20*N_exposure + 0.20*S_unresolved + 0.15*(100 - V_containment))
        avg_active_risk = (sum(i.risk_score for i in active_incidents) / len(active_incidents)) if active_incidents else 10.0
        i_risk = min(100.0, avg_active_risk)
        e_posture = min(100.0, len(critical_incidents) * 25.0)
        n_exposure = min(100.0, len(high_risk_ips) * 20.0)
        s_unresolved = min(100.0, (total_anomalies / 20.0) * 100.0)
        
        contained_count = sum(1 for i in incidents if i.status in ["CONTAINED", "RESOLVED"])
        v_containment = (contained_count / max(1, len(incidents))) * 100.0 if incidents else 100.0

        deduction = (
            0.25 * i_risk +
            0.20 * e_posture +
            0.20 * n_exposure +
            0.20 * s_unresolved +
            0.15 * max(0.0, 100.0 - v_containment)
        )
        health_score = round(max(15.0, min(99.0, 100.0 - deduction)), 1)

        if health_score >= 80.0:
            status_str = "OPTIMAL"
        elif health_score >= 60.0:
            status_str = "MODERATE"
        elif health_score >= 40.0:
            status_str = "ELEVATED_RISK"
        else:
            status_str = "CRITICAL"

        return SecurityHealthScoreResponse(
            security_health_score=health_score,
            health_status=status_str,
            formula_documentation=(
                "Health Score = 100 - (0.25*I_risk + 0.20*E_posture + 0.20*N_exposure + "
                "0.20*S_unresolved + 0.15*(100 - V_containment)). Non-industry research evaluation metric."
            ),
            factors={
                "incident_risk_factor": round(i_risk, 1),
                "critical_exposure_factor": round(e_posture, 1),
                "external_network_exposure": round(n_exposure, 1),
                "unresolved_anomalies_factor": round(s_unresolved, 1),
                "containment_rate_factor": round(v_containment, 1),
            },
            active_incidents_count=len(active_incidents),
            critical_incidents_count=len(critical_incidents),
            total_anomalies_count=total_anomalies,
            high_risk_ips_count=len(high_risk_ips)
        )
