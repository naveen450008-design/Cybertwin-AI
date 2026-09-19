"""In-Memory Digital Twin Topology Graph & Safe Response Simulation Engine.

STRICT SAFETY INVARIANTS:
- All state mutations are 100% in-memory within the simulated directed graph G = (V, E).
- Zero OS-level calls (no os.system, no subprocess, no process kill).
- Zero network modifications (no firewall changes, no DNS changes, no routing changes).
- All outputs are labeled with mandatory marker: SIMULATED ACTION.
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from copy import deepcopy
import logging

logger = logging.getLogger("cyber_soc.digital_twin")


@dataclass
class TwinNode:
    id: str
    type: str  # USER, SESSION, WORKSTATION, SERVER, GATEWAY, DATABASE
    name: str
    tier: int = 3  # 1 (Critical DB), 2 (App/Gateway), 3 (Workstation)
    is_isolated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TwinEdge:
    id: str
    source: str
    target: str
    relation: str  # OWNS, ACTIVE_ON, CONNECTS_TO, ROUTES_TRAFFIC_TO, QUERIES
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class DigitalTwinService:
    """In-memory Digital Twin maintaining enterprise topological graph G = (V, E)."""

    _instance: Optional["DigitalTwinService"] = None

    def __init__(self):
        self.nodes: Dict[str, TwinNode] = {}
        self.edges: Dict[str, TwinEdge] = {}
        self.snapshots: Dict[str, Dict[str, Any]] = {}  # action_id -> pre-mutation graph state
        self._initialize_default_topology()

    @classmethod
    def get_instance(cls) -> "DigitalTwinService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _initialize_default_topology(self):
        """Initializes canonical enterprise topology graph G = (V, E)."""
        self.nodes.clear()
        self.edges.clear()

        # 1. User Nodes
        users = [
            ("usr-alex-chen", "alex.chen", 3, {"role": "Finance Specialist"}),
            ("usr-sarah-connor", "sarah.connor", 2, {"role": "DevOps Engineer"}),
            ("usr-david-kim", "david.kim", 1, {"role": "Security Admin"}),
            ("usr-elena-rodriguez", "elena.rodriguez", 3, {"role": "HR Generalist"}),
        ]
        for uid, name, tier, meta in users:
            self.nodes[uid] = TwinNode(id=uid, type="USER", name=name, tier=tier, metadata=meta)

        # 2. Session Nodes
        sessions = [
            ("sess-4019", "SESS-ALEX-01", "usr-alex-chen"),
            ("sess-5022", "SESS-SARAH-01", "usr-sarah-connor"),
            ("sess-6031", "SESS-DAVID-01", "usr-david-kim"),
        ]
        for sid, name, uid in sessions:
            self.nodes[sid] = TwinNode(id=sid, type="SESSION", name=name, tier=3)
            self.edges[f"edge-{uid}-{sid}"] = TwinEdge(
                id=f"edge-{uid}-{sid}", source=uid, target=sid, relation="OWNS"
            )

        # 3. Workstations
        workstations = [
            ("dev-wks-012", "WS-FINANCE-CHEN", "192.168.1.104", "sess-4019"),
            ("dev-wks-018", "WS-DEVOPS-SARAH", "192.168.1.118", "sess-5022"),
            ("dev-wks-001", "WS-SEC-DAVID", "192.168.1.5", "sess-6031"),
            ("dev-wks-025", "WS-HR-ELENA", "192.168.1.125", None),
        ]
        for wid, name, ip, sid in workstations:
            self.nodes[wid] = TwinNode(
                id=wid, type="WORKSTATION", name=name, tier=3, metadata={"ip_address": ip}
            )
            if sid:
                self.edges[f"edge-{sid}-{wid}"] = TwinEdge(
                    id=f"edge-{sid}-{wid}", source=sid, target=wid, relation="ACTIVE_ON"
                )

        # 4. Gateways & Application Servers
        self.nodes["srv-gw-001"] = TwinNode(
            id="srv-gw-001", type="GATEWAY", name="GW-EDGE-01", tier=2, metadata={"ip_address": "10.0.0.1"}
        )
        self.nodes["srv-app-002"] = TwinNode(
            id="srv-app-002", type="SERVER", name="SRV-APP-FIN", tier=2, metadata={"ip_address": "10.0.1.20"}
        )

        # 5. Critical Database (Tier-1)
        self.nodes["srv-db-001"] = TwinNode(
            id="srv-db-001", type="DATABASE", name="SRV-DB-PROD", tier=1, metadata={"ip_address": "10.0.2.100", "criticality": 100}
        )

        # Connect topology edges
        # Workstations connect to Gateway
        for wid in ["dev-wks-012", "dev-wks-018", "dev-wks-001", "dev-wks-025"]:
            self.edges[f"edge-{wid}-gw"] = TwinEdge(
                id=f"edge-{wid}-gw", source=wid, target="srv-gw-001", relation="CONNECTS_TO"
            )

        # Gateway routes to App Server
        self.edges["edge-gw-app"] = TwinEdge(
            id="edge-gw-app", source="srv-gw-001", target="srv-app-002", relation="ROUTES_TRAFFIC_TO"
        )

        # App Server queries Database
        self.edges["edge-app-db"] = TwinEdge(
            id="edge-app-db", source="srv-app-002", target="srv-db-001", relation="QUERIES"
        )

    def get_topology_snapshot(self) -> Dict[str, Any]:
        """Returns the serialized topology for visualization."""
        nodes_data = [
            {
                "id": n.id,
                "type": n.type,
                "name": n.name,
                "tier": n.tier,
                "is_isolated": n.is_isolated,
                "metadata": n.metadata
            }
            for n in self.nodes.values()
        ]
        edges_data = [
            {
                "id": e.id,
                "source": e.source,
                "target": e.target,
                "relation": e.relation,
                "is_active": e.is_active
            }
            for e in self.edges.values()
        ]
        return {
            "nodes": nodes_data,
            "edges": edges_data,
            "marker": "SIMULATED ACTION",
            "safety_invariant": "Zero OS / Network Mutability"
        }

    def execute_simulation(
        self,
        action_id: str,
        action_type: str,
        target_entity_id: str
    ) -> Dict[str, Any]:
        """Safely mutates the in-memory Digital Twin graph."""
        # 1. Save pre-mutation snapshot for rollback
        self.snapshots[str(action_id)] = {
            "nodes": deepcopy(self.nodes),
            "edges": deepcopy(self.edges)
        }

        affected_edges = []
        action_desc = ""

        # Normalize target ID
        target_norm = target_entity_id.lower().strip()

        if action_type == "SIMULATE_ISOLATE_DEVICE":
            # Locate device node by ID or name
            matched_node = None
            for n in self.nodes.values():
                if n.id.lower() == target_norm or n.name.lower() == target_norm:
                    matched_node = n
                    break

            if matched_node:
                matched_node.is_isolated = True
                # Deactivate all connected edges
                for eid, e in self.edges.items():
                    if e.source == matched_node.id or e.target == matched_node.id:
                        e.is_active = False
                        affected_edges.append(eid)
                action_desc = f"Severed {len(affected_edges)} network edges for isolated device '{matched_node.name}' in Digital Twin."
            else:
                action_desc = f"Simulated isolation recorded for entity '{target_entity_id}'."

        elif action_type == "SIMULATE_BLOCK_IP":
            # Deactivate edges associated with IP address
            for eid, e in self.edges.items():
                src_node = self.nodes.get(e.source)
                tgt_node = self.nodes.get(e.target)
                src_ip = src_node.metadata.get("ip_address", "") if src_node else ""
                tgt_ip = tgt_node.metadata.get("ip_address", "") if tgt_node else ""
                if target_norm in src_ip or target_norm in tgt_ip:
                    e.is_active = False
                    affected_edges.append(eid)
            action_desc = f"Blocked simulated traffic on {len(affected_edges)} twin edges for IP '{target_entity_id}'."

        elif action_type == "SIMULATE_TERMINATE_SESSION":
            for eid, e in self.edges.items():
                if e.target.lower() == target_norm or e.source.lower() == target_norm or target_norm in e.id.lower():
                    e.is_active = False
                    affected_edges.append(eid)
            action_desc = f"Terminated simulated session edge for target '{target_entity_id}'."

        elif action_type in ["SIMULATE_RESTRICT_ACCESS", "FLAG_USER_FOR_MONITORING"]:
            action_desc = f"Applied policy {action_type} to identity '{target_entity_id}' in Digital Twin."

        logger.info(f"[SIMULATED ACTION] Executed {action_type} on {target_entity_id}: {action_desc}")

        return {
            "action_id": str(action_id),
            "action_type": action_type,
            "target": target_entity_id,
            "status": "EXECUTED_SIMULATION",
            "description": action_desc,
            "affected_edges_count": len(affected_edges),
            "marker": "SIMULATED ACTION"
        }

    def rollback_simulation(self, action_id: str) -> bool:
        """Restores in-memory graph state from pre-mutation snapshot."""
        snap = self.snapshots.get(str(action_id))
        if not snap:
            # If no explicit snapshot, reset topology
            self._initialize_default_topology()
            return True

        self.nodes = deepcopy(snap["nodes"])
        self.edges = deepcopy(snap["edges"])
        del self.snapshots[str(action_id)]
        logger.info(f"[SIMULATED ACTION] Rolled back action {action_id} to pre-mutation state.")
        return True
