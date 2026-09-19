import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { 
  ArrowLeft, 
  Flame, 
  Activity, 
  Play, 
  Pause, 
  RotateCcw, 
  Bot, 
  Network, 
  Layers, 
  Zap,
  Globe
} from 'lucide-react';
import { IPIntelligenceDrawer } from '../components/IPIntelligenceDrawer';
import { MitreFingerprint } from '../components/MitreFingerprint';
import { UebaBehaviourVisualizer } from '../components/UebaBehaviourVisualizer';

interface TimelineEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  action: string;
  severity: string;
  username?: string;
  source_ip?: string;
  device_name?: string;
  correlation_reason: string;
  sequence_index: number;
}

interface IncidentDetail {
  incident_id: string;
  incident_title: string;
  status: string;
  severity: string;
  risk_score: number;
  anomaly_score: number;
  threat_severity_score: number;
  asset_criticality_score: number;
  identity_sensitivity_score: number;
  event_sequence_score: number;
  attack_stage_score: number;
  confidence_score: number;
  evidence_quality: string;
  assigned_analyst?: string;
  sla_breach_deadline?: string;
  created_at: string;
  mitre_techniques: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    confidence: number;
  }>;
}

interface GraphNode {
  id: string;
  type: string;
  label: string;
  metadata: Record<string, any>;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export const IncidentDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { token } = useAuth();
  const navigate = useNavigate();

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);

  // Scrubber Replay State
  const [isPlaying, setIsPlaying] = useState(false);
  const [replaySpeed, setReplaySpeed] = useState<1 | 2 | 5>(1);
  const [currentStep, setCurrentStep] = useState(0);

  // Copilot State
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [copilotResult, setCopilotResult] = useState<any>(null);

  // IP Recon Drawer State
  const [selectedIP, setSelectedIP] = useState<string | null>(null);

  const headers = { Authorization: `Bearer ${token}` };

  const fetchDetails = async () => {
    if (!id) return;
    setLoading(true);
    try {
      const [incRes, timeRes, graphRes] = await Promise.all([
        axios.get(`/api/v1/incidents/${id}`, { headers }),
        axios.get(`/api/v1/incidents/${id}/timeline`, { headers }),
        axios.get(`/api/v1/incidents/${id}/graph`, { headers })
      ]);
      setIncident(incRes.data);
      const events = timeRes.data.events || [];
      setTimeline(events);
      setCurrentStep(events.length);
      setGraphNodes(graphRes.data.nodes || []);
      setGraphEdges(graphRes.data.edges || []);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetails();
  }, [id, token]);

  // Timeline Replay Timer
  useEffect(() => {
    let interval: any = null;
    if (isPlaying && timeline.length > 0) {
      interval = setInterval(() => {
        setCurrentStep((prev) => {
          if (prev >= timeline.length) {
            setIsPlaying(false);
            return timeline.length;
          }
          return prev + 1;
        });
      }, 1000 / replaySpeed);
    }
    return () => clearInterval(interval);
  }, [isPlaying, replaySpeed, timeline.length]);

  const handleStatusChange = async (newStatus: string) => {
    if (!id) return;
    try {
      const res = await axios.patch(
        `/api/v1/incidents/${id}/status`,
        { status: newStatus },
        { headers }
      );
      setIncident(res.data);
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  const handleAskCopilot = async () => {
    if (!id) return;
    setCopilotOpen(true);
    setCopilotLoading(true);
    try {
      const res = await axios.post(
        '/api/v1/copilot/query',
        { incident_id: id },
        { headers }
      );
      setCopilotResult(res.data);
    } catch (err) {
      console.error('Failed to query Copilot:', err);
    } finally {
      setCopilotLoading(false);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-gray-500 font-mono">Loading incident telemetry...</div>;
  }

  if (!incident) {
    return (
      <div className="p-8 text-center text-gray-500 font-mono">
        Incident not found. <button onClick={() => navigate('/incidents')} className="text-indigo-400 underline ml-2">Back to Queue</button>
      </div>
    );
  }

  const visibleTimeline = timeline.slice(0, currentStep);

  return (
    <div className="space-y-6">
      {/* Top Navigation & Status Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/incidents')}
            className="p-2 rounded-lg bg-gray-900 border border-gray-800 text-gray-400 hover:text-white transition"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white tracking-tight">{incident.incident_title}</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950/80 border border-red-800 text-red-300">
                {incident.severity}
              </span>
            </div>
            <p className="text-xs font-mono text-gray-500 mt-0.5">
              Incident ID: {incident.incident_id} &bull; Created {new Date(incident.created_at).toUTCString()}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {/* Status Dropdown */}
          <select
            value={incident.status}
            onChange={(e) => handleStatusChange(e.target.value)}
            className="px-3 py-1.5 bg-gray-900 border border-gray-700 text-xs font-mono text-gray-200 rounded-lg focus:outline-none focus:border-indigo-500"
          >
            {['NEW', 'INVESTIGATING', 'CONTAINMENT_RECOMMENDED', 'CONTAINED', 'RESOLVED', 'CLOSED'].map((st) => (
              <option key={st} value={st}>{st}</option>
            ))}
          </select>

          {/* AI Copilot Trigger */}
          <button
            onClick={handleAskCopilot}
            className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono rounded-lg transition flex items-center gap-1.5 shadow"
          >
            <Bot className="w-3.5 h-3.5" />
            <span>AI Copilot</span>
          </button>

          {/* Simulation Link */}
          <button
            onClick={() => navigate('/simulation')}
            className="px-3 py-1.5 bg-purple-900/60 hover:bg-purple-800/80 border border-purple-700 text-purple-200 text-xs font-mono rounded-lg transition flex items-center gap-1.5"
          >
            <Zap className="w-3.5 h-3.5 text-purple-400" />
            <span>Simulate Response</span>
          </button>
        </div>
      </div>

      {/* 6-Factor Canonical Risk Breakdown Panel */}
      <div className="bg-[#111827] border border-gray-800 rounded-lg p-5">
        <div className="flex items-center justify-between border-b border-gray-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold text-white">
              Deterministic 6-Factor Composite Risk Model
            </h2>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-gray-400">
              Formula: <code className="text-indigo-300">min(100, 0.25*S_anom + 0.20*S_sev + 0.15*S_asset + 0.15*S_id + 0.15*S_seq + 0.10*S_stage)</code>
            </span>
            <span className="px-3 py-1 rounded bg-red-950/80 border border-red-800 text-red-300 font-bold font-mono text-sm">
              Risk: {incident.risk_score.toFixed(1)}/100
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="bg-gray-900/80 p-2.5 rounded border border-gray-800 text-xs font-mono">
            <span className="text-gray-500 block text-[10px]">ANOMALY (25%)</span>
            <strong className="text-amber-400 text-sm">{incident.anomaly_score.toFixed(1)}</strong>
            <span className="text-[10px] text-gray-500 block">Isolation Forest</span>
          </div>
          <div className="bg-gray-900/80 p-2.5 rounded border border-gray-800 text-xs font-mono">
            <span className="text-gray-500 block text-[10px]">SEVERITY (20%)</span>
            <strong className="text-red-400 text-sm">{incident.threat_severity_score}</strong>
            <span className="text-[10px] text-gray-500 block">Threat Rating</span>
          </div>
          <div className="bg-gray-900/80 p-2.5 rounded border border-gray-800 text-xs font-mono">
            <span className="text-gray-500 block text-[10px]">ASSET (15%)</span>
            <strong className="text-blue-400 text-sm">{incident.asset_criticality_score}</strong>
            <span className="text-[10px] text-gray-500 block">Criticality Tier</span>
          </div>
          <div className="bg-gray-900/80 p-2.5 rounded border border-gray-800 text-xs font-mono">
            <span className="text-gray-500 block text-[10px]">IDENTITY (15%)</span>
            <strong className="text-purple-400 text-sm">{incident.identity_sensitivity_score}</strong>
            <span className="text-[10px] text-gray-500 block">Privilege Tier</span>
          </div>
          <div className="bg-gray-900/80 p-2.5 rounded border border-gray-800 text-xs font-mono">
            <span className="text-gray-500 block text-[10px]">SEQUENCE (15%)</span>
            <strong className="text-emerald-400 text-sm">{incident.event_sequence_score}</strong>
            <span className="text-[10px] text-gray-500 block">Event Chain</span>
          </div>
          <div className="bg-gray-900/80 p-2.5 rounded border border-gray-800 text-xs font-mono">
            <span className="text-gray-500 block text-[10px]">STAGE (10%)</span>
            <strong className="text-indigo-400 text-sm">{incident.attack_stage_score}</strong>
            <span className="text-[10px] text-gray-500 block">Kill-Chain Depth</span>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Chips */}
      {incident.mitre_techniques.length > 0 && (
        <div className="bg-[#111827] border border-gray-800 rounded-lg p-4">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-red-400" />
            Correlated MITRE ATT&CK Techniques (Offline Catalog Evidence)
          </h3>
          <div className="flex flex-wrap gap-2">
            {incident.mitre_techniques.map((mt) => (
              <div
                key={mt.technique_id}
                className="px-2.5 py-1 rounded bg-red-950/60 border border-red-900/80 text-xs font-mono flex items-center gap-2"
              >
                <strong className="text-red-300">{mt.technique_id}</strong>
                <span className="text-gray-300">{mt.technique_name}</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-black/40 rounded text-red-400 border border-red-900">
                  {mt.tactic}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attack Graph Visualization Canvas */}
      <div className="bg-[#111827] border border-gray-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-4 border-b border-gray-800 pb-3">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-indigo-400" />
            <h2 className="text-sm font-semibold text-white">Attack Progression Graph</h2>
          </div>
          <span className="text-xs font-mono text-gray-500">
            {graphNodes.length} Nodes &bull; {graphEdges.length} Traversal Edges
          </span>
        </div>

        <div className="bg-[#0B0F17] border border-gray-800/80 rounded-lg p-6 min-h-[220px] flex items-center justify-around flex-wrap gap-6 relative">
          {graphNodes.length === 0 ? (
            <div className="text-xs font-mono text-gray-500">No attack graph nodes populated.</div>
          ) : (
            graphNodes.map((node) => (
              <div
                key={node.id}
                onClick={() => {
                  if (node.type === 'attacker_ip') {
                    const ip = node.metadata?.source_ip || node.label.replace('IP: ', '');
                    setSelectedIP(ip);
                  }
                }}
                className={`p-3 rounded-lg border text-center font-mono text-xs min-w-[140px] shadow-lg transition transform hover:scale-105 ${
                  node.type === 'attacker_ip'
                    ? 'bg-red-950/70 border-red-800 text-red-200 cursor-pointer hover:ring-2 hover:ring-red-500'
                    : node.type === 'user'
                    ? 'bg-purple-950/70 border-purple-800 text-purple-200'
                    : node.type === 'device'
                    ? 'bg-blue-950/70 border-blue-800 text-blue-200'
                    : 'bg-emerald-950/70 border-emerald-800 text-emerald-200'
                }`}
              >
                <div className="text-[10px] uppercase font-bold tracking-wider opacity-75">
                  {node.type === 'attacker_ip' ? 'ATTACKER IP (CLICK FOR RECON)' : node.type}
                </div>
                <div className="font-semibold text-sm mt-0.5">{node.label}</div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Interactive Timeline with 1x/2x/5x Replay Scrubber */}
      <div className="bg-[#111827] border border-gray-800 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-white">Attack Sequence Timeline & Replay Scrubber</h2>
          </div>

          {/* Replay Controls */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsPlaying(!isPlaying)}
              className="p-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white transition flex items-center gap-1 text-xs font-mono"
            >
              {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              <span>{isPlaying ? 'Pause' : 'Replay'}</span>
            </button>
            <button
              onClick={() => { setIsPlaying(false); setCurrentStep(0); }}
              className="p-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 transition text-xs font-mono"
              title="Reset to start"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>

            {/* Speed Multiplier */}
            <div className="flex items-center gap-1 border border-gray-800 rounded bg-gray-900 p-0.5 text-[11px] font-mono">
              {[1, 2, 5].map((spd) => (
                <button
                  key={spd}
                  onClick={() => setReplaySpeed(spd as 1 | 2 | 5)}
                  className={`px-1.5 py-0.5 rounded ${
                    replaySpeed === spd ? 'bg-indigo-600 text-white font-bold' : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {spd}x
                </button>
              ))}
            </div>

            <span className="text-xs font-mono text-gray-400 ml-2">
              Step {currentStep} of {timeline.length}
            </span>
          </div>
        </div>

        {/* Step Slider */}
        <input
          type="range"
          min="0"
          max={timeline.length}
          value={currentStep}
          onChange={(e) => {
            setIsPlaying(false);
            setCurrentStep(parseInt(e.target.value));
          }}
          className="w-full h-1.5 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-indigo-500 mb-4"
        />

        {/* Event List */}
        <div className="space-y-2">
          {visibleTimeline.length === 0 ? (
            <div className="text-xs font-mono text-gray-500 py-3 text-center">
              Replay reset. Click Play to scrub through events chronologically.
            </div>
          ) : (
            visibleTimeline.map((ev, idx) => (
              <div
                key={ev.event_id}
                className="bg-gray-900/80 border border-gray-800/80 rounded p-3 text-xs font-mono flex items-center justify-between gap-3 hover:border-gray-700 transition"
              >
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 rounded-full bg-indigo-950 border border-indigo-800 text-indigo-300 flex items-center justify-center font-bold text-[10px]">
                    {ev.sequence_index || idx + 1}
                  </span>
                  <div>
                    <div className="font-semibold text-gray-200">
                      {ev.event_type} &bull; {ev.action}
                    </div>
                    <div className="text-[11px] text-gray-400 mt-0.5">
                      {ev.correlation_reason}
                    </div>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-gray-400">{new Date(ev.timestamp).toLocaleTimeString()}</div>
                  <div className="text-[10px] text-gray-500 flex items-center justify-end gap-1">
                    {ev.source_ip ? (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIP(ev.source_ip!);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1"
                        title="Inspect IP Intelligence"
                      >
                        <Globe className="w-2.5 h-2.5" /> {ev.source_ip}
                      </button>
                    ) : (
                      ev.username || 'System'
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* MITRE ATT&CK Visual Fingerprint */}
      <MitreFingerprint techniques={incident.mitre_techniques} />

      {/* UEBA Behavioural Profile Visualizer */}
      <UebaBehaviourVisualizer 
        username={timeline[0]?.username || 'user_02'} 
        anomalyScore={incident.anomaly_score} 
        observedIp={timeline[0]?.source_ip || '198.51.100.42'} 
      />

      {/* AI Investigation Copilot Slide-Out Drawer */}
      {copilotOpen && (
        <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-[#0E131F] border-l border-gray-800 shadow-2xl p-6 z-50 overflow-y-auto space-y-4">
          <div className="flex items-center justify-between border-b border-gray-800 pb-3">
            <div className="flex items-center gap-2">
              <Bot className="w-5 h-5 text-indigo-400" />
              <h3 className="text-base font-bold text-white">AI Investigation Copilot</h3>
            </div>
            <button
              onClick={() => setCopilotOpen(false)}
              className="text-gray-400 hover:text-white font-mono text-sm"
            >
              &times; Close
            </button>
          </div>

          <div className="text-xs font-mono text-amber-400 bg-amber-950/40 border border-amber-900 p-2.5 rounded">
            EVIDENCE GROUNDED: Synthesis is derived exclusively from verified database records.
          </div>

          {copilotLoading ? (
            <div className="p-8 text-center text-gray-400 font-mono text-xs animate-pulse">
              Extracting database facts & correlating MITRE evidence...
            </div>
          ) : copilotResult ? (
            <div className="space-y-4 text-xs font-mono">
              <div>
                <h4 className="text-gray-400 uppercase text-[10px] font-bold">Executive Synthesis</h4>
                <p className="text-gray-200 mt-1 leading-relaxed bg-gray-900 p-3 rounded border border-gray-800">
                  {copilotResult.executive_summary}
                </p>
              </div>

              <div>
                <h4 className="text-emerald-400 uppercase text-[10px] font-bold">Verified Evidence (FACT / EVIDENCE)</h4>
                <div className="space-y-1.5 mt-1.5">
                  {copilotResult.verified_facts?.map((fact: any, i: number) => (
                    <div key={i} className="bg-gray-900/90 p-2 rounded border border-emerald-900/40 text-[11px]">
                      <span className="text-emerald-300 font-semibold">{fact.action}</span> &bull; {fact.entity}
                      <span className="text-gray-500 block text-[10px]">Rule: {fact.rule_triggered}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-amber-400 uppercase text-[10px] font-bold">Model Guidance (ESTIMATED PREDICTION)</h4>
                <div className="space-y-1.5 mt-1.5">
                  {copilotResult.estimated_predictions?.map((pred: any, i: number) => (
                    <div key={i} className="bg-gray-900/90 p-2 rounded border border-amber-900/40 text-[11px]">
                      <strong className="text-amber-300">{pred.metric}:</strong> {pred.value}
                      <span className="text-gray-400 block text-[10px] mt-0.5">{pred.basis}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-3 bg-purple-950/40 border border-purple-800 rounded">
                <span className="text-purple-300 font-bold block text-[11px]">Recommended Response Action</span>
                <span className="text-white text-xs block font-bold mt-1">{copilotResult.recommended_simulated_action}</span>
                <button
                  onClick={() => navigate('/simulation')}
                  className="mt-2 w-full py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs transition"
                >
                  Configure Safe Simulation
                </button>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* Slide-out IP Threat Intelligence Recon Drawer */}
      <IPIntelligenceDrawer
        ipAddress={selectedIP}
        onClose={() => setSelectedIP(null)}
      />
    </div>
  );
};
