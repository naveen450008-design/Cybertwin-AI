import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  ShieldAlert, 
  CheckCircle, 
  RotateCcw, 
  Server, 
  Laptop, 
  Network, 
  User as UserIcon, 
  Activity, 
  Play, 
  Layers, 
  Lock, 
  RefreshCw,
  Info
} from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';

interface TopologyNode {
  id: string;
  type: string;
  ip: string;
  criticality: string;
  is_isolated: boolean;
  active_sessions: number;
}

interface TopologyEdge {
  source: string;
  target: string;
  relationship: string;
  is_active: boolean;
}

interface BlastRadiusResult {
  action_type: string;
  target_entity_id: string;
  disruption_score: number;
  severed_sessions_count: number;
  collateral_users_count: number;
  tier1_disrupted: boolean;
  estimated_risk_reduction_pct: number;
  recommended_mode: string;
  impact_tier: string;
  summary: string;
  marker: string;
}

interface SimulationAction {
  action_id: string;
  incident_id?: string;
  action_type: string;
  target_entity_type: string;
  target_entity_id: string;
  response_mode: string;
  approval_status: string;
  approved_by?: string;
  approved_at?: string;
  blast_radius_impact: any;
  is_reverted: boolean;
  executed_at?: string;
  created_at: string;
  marker: string;
}

export const SimulationConsolePage: React.FC = () => {
  const { hasRole, user } = useAuth();
  const canApproveHighImpact = hasRole('Security Analyst') || hasRole('Security Admin');
  const canStageActions = hasRole('Incident Responder') || hasRole('Security Analyst') || hasRole('Security Admin');

  // Topology state
  const [nodes, setNodes] = useState<TopologyNode[]>([]);
  const [edges, setEdges] = useState<TopologyEdge[]>([]);
  const [topologyLoading, setTopologyLoading] = useState(false);
  const [selectedNodeType, setSelectedNodeType] = useState<string>('ALL');

  // Blast Radius Calculator state
  const [targetEntityId, setTargetEntityId] = useState<string>('192.168.1.100');
  const [targetEntityType, setTargetEntityType] = useState<string>('DEVICE');
  const [actionType, setActionType] = useState<string>('SIMULATE_ISOLATE_DEVICE');
  const [responseMode, setResponseMode] = useState<string>('RECOMMEND');
  const [blastLoading, setBlastLoading] = useState(false);
  const [blastResult, setBlastResult] = useState<BlastRadiusResult | null>(null);
  const [stageLoading, setStageLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Staged Actions state
  const [actions, setActions] = useState<SimulationAction[]>([]);
  const [actionsLoading, setActionsLoading] = useState(false);
  const [executingActionId, setExecutingActionId] = useState<string | null>(null);

  useEffect(() => {
    fetchTopology();
    fetchActions();
  }, []);

  const fetchTopology = async () => {
    setTopologyLoading(true);
    try {
      const res = await api.get('/simulation/topology');
      setNodes(res.data.nodes || []);
      setEdges(res.data.edges || []);
    } catch (err: any) {
      console.error('Failed to load topology:', err);
    } finally {
      setTopologyLoading(false);
    }
  };

  const fetchActions = async () => {
    setActionsLoading(true);
    try {
      const res = await api.get('/simulation/actions');
      setActions(res.data || []);
    } catch (err: any) {
      console.error('Failed to load simulation actions:', err);
    } finally {
      setActionsLoading(false);
    }
  };

  const handleCalculateBlastRadius = async () => {
    setBlastLoading(true);
    setStatusMessage(null);
    try {
      const res = await api.post('/simulation/blast-radius', {
        action_type: actionType,
        target_entity_id: targetEntityId,
      });
      setBlastResult(res.data);
    } catch (err: any) {
      setStatusMessage(`Blast radius calculation failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setBlastLoading(false);
    }
  };

  const handleStageAction = async () => {
    setStageLoading(true);
    setStatusMessage(null);
    try {
      await api.post('/simulation/actions/request', {
        action_type: actionType,
        target_entity_type: targetEntityType,
        target_entity_id: targetEntityId,
        response_mode: responseMode,
      });
      setStatusMessage('Simulated action staged successfully. Awaiting analyst approval.');
      fetchActions();
    } catch (err: any) {
      setStatusMessage(`Failed to stage action: ${err.response?.data?.detail || err.message}`);
    } finally {
      setStageLoading(false);
    }
  };

  const handleApproveAction = async (actionId: string, action_type: string) => {
    setExecutingActionId(actionId);
    setStatusMessage(null);
    try {
      await api.post(`/simulation/actions/${actionId}/approve`);
      setStatusMessage(`Executed simulated action ${action_type} in Digital Twin.`);
      fetchActions();
      fetchTopology(); // Refresh node isolation states
    } catch (err: any) {
      setStatusMessage(`Approval failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setExecutingActionId(null);
    }
  };

  const handleRollbackAction = async (actionId: string) => {
    setExecutingActionId(actionId);
    setStatusMessage(null);
    try {
      await api.post(`/simulation/actions/${actionId}/rollback`);
      setStatusMessage(`Rolled back simulated action in Digital Twin.`);
      fetchActions();
      fetchTopology();
    } catch (err: any) {
      setStatusMessage(`Rollback failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setExecutingActionId(null);
    }
  };

  const filteredNodes = nodes.filter(n => {
    if (selectedNodeType === 'ALL') return true;
    return n.type.toUpperCase() === selectedNodeType.toUpperCase();
  });

  const getNodeIcon = (type: string) => {
    switch (type.toUpperCase()) {
      case 'SERVER': return <Server className="w-4 h-4 text-purple-400" />;
      case 'WORKSTATION': return <Laptop className="w-4 h-4 text-blue-400" />;
      case 'GATEWAY': return <Network className="w-4 h-4 text-amber-400" />;
      case 'USER': return <UserIcon className="w-4 h-4 text-cyan-400" />;
      default: return <Layers className="w-4 h-4 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner with Safety Invariant Guarantee */}
      <div className="bg-gradient-to-r from-emerald-950/40 via-gray-900 to-blue-950/40 border border-emerald-500/30 rounded-xl p-5 shadow-lg backdrop-blur-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-mono font-bold px-2 py-0.5 rounded">
                SIMULATED ACTION ONLY
              </span>
              <span className="bg-gray-800 text-gray-400 text-[10px] font-mono px-2 py-0.5 rounded">
                ZERO OS / NETWORK MUTABILITY
              </span>
            </div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Cpu className="w-6 h-6 text-emerald-400" />
              Digital Twin Topology & Blast-Radius Simulator
            </h1>
            <p className="text-xs text-gray-400 mt-1 max-w-3xl">
              Defensive graph simulation engine: models operational dependencies, estimates disruption scores, 
              and validates containment actions strictly in-memory before human approval. No real firewall or OS changes.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => { fetchTopology(); fetchActions(); }}
              className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs px-3 py-2 rounded-lg border border-gray-700 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${(topologyLoading || actionsLoading) ? 'animate-spin' : ''}`} />
              Refresh Graph
            </button>
          </div>
        </div>

        {statusMessage && (
          <div className="mt-4 p-2.5 bg-blue-900/30 border border-blue-500/40 rounded text-xs text-blue-200 flex items-center gap-2">
            <Info className="w-4 h-4 text-blue-400 shrink-0" />
            <span>{statusMessage}</span>
          </div>
        )}
      </div>

      {/* Main Grid: Topology on Left, Blast Radius & Staging on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Digital Twin Topology (7 cols) */}
        <div className="lg:col-span-7 bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-gray-800 pb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              <h2 className="text-sm font-semibold text-gray-200">In-Memory Topology Graph G=(V,E)</h2>
              <span className="text-[10px] bg-gray-800 text-gray-400 font-mono px-2 py-0.5 rounded">
                {nodes.length} Nodes | {edges.length} Dependencies
              </span>
            </div>
            
            {/* Filter buttons */}
            <div className="flex items-center gap-1">
              {['ALL', 'WORKSTATION', 'SERVER', 'GATEWAY'].map(type => (
                <button
                  key={type}
                  onClick={() => setSelectedNodeType(type)}
                  className={`text-[10px] font-mono px-2 py-1 rounded transition ${
                    selectedNodeType === type
                      ? 'bg-blue-600/30 text-blue-300 border border-blue-500/40'
                      : 'text-gray-400 hover:bg-gray-800'
                  }`}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>

          {/* Node Grid Visualization */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[420px] overflow-y-auto pr-1">
            {filteredNodes.map(node => (
              <div 
                key={node.id}
                onClick={() => {
                  setTargetEntityId(node.id);
                  if (node.type === 'SERVER' || node.type === 'WORKSTATION') {
                    setTargetEntityType('DEVICE');
                    setActionType('SIMULATE_ISOLATE_DEVICE');
                  } else if (node.type === 'USER') {
                    setTargetEntityType('USER');
                    setActionType('SIMULATE_RESTRICT_ACCESS');
                  } else {
                    setTargetEntityType('IP');
                    setActionType('SIMULATE_BLOCK_IP');
                  }
                }}
                className={`p-3 rounded-lg border cursor-pointer transition flex flex-col justify-between ${
                  node.is_isolated
                    ? 'bg-rose-950/30 border-rose-800/60 hover:border-rose-600'
                    : targetEntityId === node.id
                      ? 'bg-blue-950/40 border-blue-500'
                      : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {getNodeIcon(node.type)}
                    <span className="font-mono text-xs font-semibold text-gray-200">{node.id}</span>
                  </div>
                  {node.is_isolated ? (
                    <span className="bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[9px] font-mono px-1.5 py-0.5 rounded font-bold">
                      SIMULATED ISOLATED
                    </span>
                  ) : (
                    <span className="bg-emerald-500/10 text-emerald-400 text-[9px] font-mono px-1.5 py-0.5 rounded">
                      ACTIVE
                    </span>
                  )}
                </div>

                <div className="mt-2 grid grid-cols-2 gap-2 text-[10px] font-mono text-gray-400">
                  <div>IP: <span className="text-gray-300">{node.ip}</span></div>
                  <div>Tier: <span className={node.criticality === 'Tier-1' ? 'text-amber-400 font-bold' : 'text-gray-300'}>{node.criticality}</span></div>
                  <div>Sessions: <span className="text-gray-300">{node.active_sessions}</span></div>
                  <div>Type: <span className="text-gray-300">{node.type}</span></div>
                </div>
              </div>
            ))}
          </div>

          <div className="text-[11px] text-gray-500 bg-gray-900/50 p-2.5 rounded border border-gray-800 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-gray-400" />
              Click any node to populate Target Entity in the Blast Radius Analyzer.
            </span>
            <span className="font-mono text-emerald-400 text-[10px]">In-Memory State: Ready</span>
          </div>
        </div>

        {/* Right Column: Blast Radius Impact Calculator (5 cols) */}
        <div className="lg:col-span-5 bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-gray-800 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
              <h2 className="text-sm font-semibold text-gray-200">Blast Radius Analyzer</h2>
            </div>
            <span className="text-[9px] bg-blue-950 text-blue-300 border border-blue-800 font-mono px-1.5 py-0.5 rounded">
              FORMULA §3
            </span>
          </div>

          {/* Calculator Inputs */}
          <div className="space-y-3">
            <div>
              <label className="text-[11px] font-mono text-gray-400 block mb-1">Target Entity ID</label>
              <input
                type="text"
                value={targetEntityId}
                onChange={e => setTargetEntityId(e.target.value)}
                placeholder="e.g. 192.168.1.100, srv-db-01, dev-admin"
                className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[11px] font-mono text-gray-400 block mb-1">Target Entity Type</label>
                <select
                  value={targetEntityType}
                  onChange={e => setTargetEntityType(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="DEVICE">DEVICE</option>
                  <option value="IP">IP ADDRESS</option>
                  <option value="USER">USER</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-mono text-gray-400 block mb-1">Response Mode</label>
                <select
                  value={responseMode}
                  onChange={e => setResponseMode(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="OBSERVE">OBSERVE</option>
                  <option value="RECOMMEND">RECOMMEND</option>
                  <option value="CONTROLLED_AUTONOMOUS">CONTROLLED_AUTONOMOUS</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-[11px] font-mono text-gray-400 block mb-1">Simulated Defensive Action</label>
              <select
                value={actionType}
                onChange={e => setActionType(e.target.value)}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
              >
                <option value="SIMULATE_ISOLATE_DEVICE">SIMULATE_ISOLATE_DEVICE</option>
                <option value="SIMULATE_BLOCK_IP">SIMULATE_BLOCK_IP</option>
                <option value="SIMULATE_TERMINATE_SESSION">SIMULATE_TERMINATE_SESSION</option>
                <option value="SIMULATE_RESTRICT_ACCESS">SIMULATE_RESTRICT_ACCESS</option>
                <option value="FLAG_USER_FOR_MONITORING">FLAG_USER_FOR_MONITORING</option>
              </select>
            </div>

            <button
              onClick={handleCalculateBlastRadius}
              disabled={blastLoading || !targetEntityId}
              className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs py-2.5 rounded-lg transition disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              {blastLoading ? 'Simulating Blast Radius...' : 'Calculate Blast Radius'}
            </button>
          </div>

          {/* Blast Radius Results Card */}
          {blastResult && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-lg p-4 space-y-3 mt-4">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-gray-400 uppercase">Operational Disruption</span>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                  blastResult.impact_tier === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                  blastResult.impact_tier === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                  blastResult.impact_tier === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                  'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}>
                  {blastResult.impact_tier} IMPACT
                </span>
              </div>

              {/* Disruption Score Gauge */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-gray-400">Disruption Score:</span>
                  <span className="font-bold text-white">{blastResult.disruption_score.toFixed(1)} / 100</span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                  <div 
                    className={`h-2 rounded-full ${
                      blastResult.disruption_score > 50 ? 'bg-rose-500' :
                      blastResult.disruption_score > 25 ? 'bg-amber-500' :
                      'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.min(100, blastResult.disruption_score)}%` }}
                  />
                </div>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono pt-1">
                <div className="bg-gray-800/60 p-2 rounded">
                  <span className="text-gray-400">Severed Sessions:</span>
                  <div className="text-xs font-bold text-white mt-0.5">{blastResult.severed_sessions_count}</div>
                </div>
                <div className="bg-gray-800/60 p-2 rounded">
                  <span className="text-gray-400">Collateral Users:</span>
                  <div className="text-xs font-bold text-white mt-0.5">{blastResult.collateral_users_count}</div>
                </div>
                <div className="bg-gray-800/60 p-2 rounded">
                  <span className="text-gray-400">Tier-1 Disrupted:</span>
                  <div className={`text-xs font-bold mt-0.5 ${blastResult.tier1_disrupted ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {blastResult.tier1_disrupted ? 'YES (CRITICAL)' : 'NO'}
                  </div>
                </div>
                <div className="bg-gray-800/60 p-2 rounded">
                  <span className="text-gray-400">Est. Risk Reduction:</span>
                  <div className="text-xs font-bold text-emerald-400 mt-0.5">-{blastResult.estimated_risk_reduction_pct.toFixed(0)}%</div>
                </div>
              </div>

              {/* Summary Narrative */}
              <div className="text-[11px] text-gray-300 bg-gray-800/40 p-2.5 rounded border border-gray-700/60">
                {blastResult.summary}
              </div>

              {/* Stage Action Button */}
              <button
                onClick={handleStageAction}
                disabled={stageLoading || !canStageActions}
                className="w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs py-2 rounded-lg transition disabled:opacity-50"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                {stageLoading ? 'Staging...' : 'Stage Simulated Action for Approval'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Response Action Queue & Human Approval Gate */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex items-center justify-between border-b border-gray-800 pb-3">
          <div className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-purple-400" />
            <h2 className="text-sm font-semibold text-gray-200">Human Approval Gate & Response Actions Queue</h2>
            <span className="text-[10px] bg-gray-800 text-gray-400 font-mono px-2 py-0.5 rounded">
              Strict RBAC Gate
            </span>
          </div>
          <span className="text-[11px] font-mono text-gray-400">
            Current User: <span className="text-blue-400">{user?.username}</span> ({user?.roles[0]?.name})
          </span>
        </div>

        {actions.length === 0 ? (
          <div className="text-center py-8 text-xs text-gray-500">
            No simulated actions staged yet. Use the Blast Radius Analyzer above to stage actions.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-900/80 text-[10px] uppercase font-mono text-gray-400 border-b border-gray-800">
                <tr>
                  <th className="py-2.5 px-3">Action Type</th>
                  <th className="py-2.5 px-3">Target Entity</th>
                  <th className="py-2.5 px-3">Mode</th>
                  <th className="py-2.5 px-3">Disruption Impact</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Approved By</th>
                  <th className="py-2.5 px-3 text-right">Human-in-the-Loop Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 font-mono">
                {actions.map(act => {
                  const isHighImpact = act.action_type === 'SIMULATE_ISOLATE_DEVICE' || act.action_type === 'SIMULATE_BLOCK_IP';
                  const canExecuteThis = !isHighImpact || canApproveHighImpact;
                  const isPending = act.approval_status === 'PENDING_APPROVAL';
                  const isExecuted = act.approval_status === 'EXECUTED_SIMULATION';
                  const isRolledBack = act.approval_status === 'ROLLED_BACK';

                  return (
                    <tr key={act.action_id} className="hover:bg-gray-900/50 transition">
                      <td className="py-3 px-3 font-semibold text-white">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] bg-emerald-950 text-emerald-400 px-1 py-0.5 rounded border border-emerald-800">
                            SIMULATED
                          </span>
                          <span>{act.action_type}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="text-blue-400">{act.target_entity_id}</span>
                        <span className="text-[10px] text-gray-500 ml-1">({act.target_entity_type})</span>
                      </td>
                      <td className="py-3 px-3 text-gray-400">{act.response_mode}</td>
                      <td className="py-3 px-3">
                        <span className="text-amber-400">
                          {act.blast_radius_impact?.disruption_score?.toFixed(1) ?? 'N/A'}
                        </span>
                        <span className="text-[10px] text-gray-500 ml-1">
                          ({act.blast_radius_impact?.impact_tier || 'TIER'})
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        {isPending && (
                          <span className="bg-amber-950/80 text-amber-400 border border-amber-800/80 text-[10px] px-2 py-0.5 rounded">
                            PENDING APPROVAL
                          </span>
                        )}
                        {isExecuted && (
                          <span className="bg-emerald-950/80 text-emerald-400 border border-emerald-800/80 text-[10px] px-2 py-0.5 rounded">
                            EXECUTED SIMULATION
                          </span>
                        )}
                        {isRolledBack && (
                          <span className="bg-gray-800 text-gray-400 text-[10px] px-2 py-0.5 rounded">
                            ROLLED BACK
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-gray-400 text-[11px]">
                        {act.approved_by || '—'}
                      </td>
                      <td className="py-3 px-3 text-right">
                        {isPending && (
                          <button
                            onClick={() => handleApproveAction(act.action_id, act.action_type)}
                            disabled={!canExecuteThis || executingActionId === act.action_id}
                            title={!canExecuteThis ? 'Requires Security Analyst or Security Admin role' : 'Approve and execute safely in Digital Twin'}
                            className="bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] px-2.5 py-1 rounded transition disabled:opacity-40"
                          >
                            {executingActionId === act.action_id ? 'Executing...' : 'Approve & Execute'}
                          </button>
                        )}
                        {isExecuted && (
                          <button
                            onClick={() => handleRollbackAction(act.action_id)}
                            disabled={executingActionId === act.action_id}
                            className="bg-gray-800 hover:bg-gray-700 text-amber-300 border border-gray-700 text-[11px] px-2.5 py-1 rounded transition flex items-center gap-1 ml-auto"
                          >
                            <RotateCcw className="w-3 h-3" />
                            {executingActionId === act.action_id ? 'Reverting...' : 'Instant Rollback'}
                          </button>
                        )}
                        {isRolledBack && (
                          <span className="text-[10px] text-gray-500">Completed</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default SimulationConsolePage;
