import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { 
  X, 
  Globe, 
  ShieldAlert, 
  Activity, 
  Network, 
  MapPin, 
  Clock, 
  User, 
  Laptop, 
  Server, 
  ExternalLink, 
  AlertTriangle, 
  Info, 
  Copy, 
  ChevronRight, 
  Target
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface IPIntelligenceDrawerProps {
  ipAddress: string | null;
  onClose: () => void;
}

export const IPIntelligenceDrawer: React.FC<IPIntelligenceDrawerProps> = ({
  ipAddress,
  onClose,
}) => {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'GRAPH' | 'ATTACK_PATH' | 'TIMELINE' | 'CLUSTERS'>('OVERVIEW');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!ipAddress || !token) return;
    const fetchIPDetail = async () => {
      setLoading(true);
      try {
        const cleanIp = ipAddress.split(':')[0].trim();
        const res = await axios.get(`/api/v1/ip-intelligence/details/${encodeURIComponent(cleanIp)}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setData(res.data);
      } catch (err) {
        console.error('Failed to load IP detail:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchIPDetail();
  }, [ipAddress, token]);

  if (!ipAddress) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(ipAddress);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getThreatColor = (lvl: string) => {
    switch (lvl) {
      case 'CRITICAL': return 'text-red-400 bg-red-950/70 border-red-800';
      case 'HIGH': return 'text-amber-400 bg-amber-950/70 border-amber-800';
      case 'MEDIUM': return 'text-yellow-400 bg-yellow-950/70 border-yellow-800';
      default: return 'text-blue-400 bg-blue-950/70 border-blue-800';
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end animate-in fade-in duration-200">
      <div 
        className="w-full max-w-2xl bg-[#0F172A] border-l border-gray-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-300 overflow-hidden"
      >
        {/* Drawer Header */}
        <div className="p-5 border-b border-gray-800 bg-[#111827] shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-pulse" />
              <span className="text-xs font-mono uppercase tracking-wider text-blue-400 font-bold flex items-center gap-1.5">
                <Globe className="w-4 h-4" /> PASSIVE IP THREAT INTELLIGENCE
              </span>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded-lg text-gray-400 hover:text-gray-100 hover:bg-gray-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xl font-mono font-bold text-gray-100">{ipAddress}</span>
              <button
                onClick={handleCopy}
                className="p-1 text-gray-400 hover:text-gray-200 text-xs font-mono"
                title="Copy IP"
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
              {copied && <span className="text-[10px] text-emerald-400 font-mono">Copied!</span>}
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className={`px-2.5 py-0.5 rounded border font-semibold ${
                data?.is_internal 
                  ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800' 
                  : 'bg-purple-950/70 text-purple-300 border-purple-800'
              }`}>
                {data?.is_internal ? 'INTERNAL / RFC1918' : 'EXTERNAL / PUBLIC WAN'}
              </span>

              {data?.risk_profile?.threat_level && (
                <span className={`px-2 py-0.5 rounded border font-bold ${getThreatColor(data.risk_profile.threat_level)}`}>
                  {data.risk_profile.threat_level} THREAT
                </span>
              )}
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex gap-2 mt-4 text-xs font-mono border-b border-gray-800 -mb-5 pb-2 overflow-x-auto">
            {[
              { id: 'OVERVIEW', label: 'Overview & Risk' },
              { id: 'GRAPH', label: 'Entity Graph' },
              { id: 'ATTACK_PATH', label: 'Attack Path' },
              { id: 'TIMELINE', label: 'Activity Timeline' },
              { id: 'CLUSTERS', label: 'Related Clusters' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-3 py-1.5 rounded-t-lg transition-colors shrink-0 ${
                  activeTab === tab.id
                    ? 'bg-gray-800 text-blue-400 border-t border-x border-gray-700 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading ? (
            <div className="h-64 flex flex-col items-center justify-center text-gray-400 font-mono text-xs">
              <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3" />
              <span>Querying passive intelligence models...</span>
            </div>
          ) : !data ? (
            <div className="text-gray-400 text-xs font-mono">No telemetry records found for this IP.</div>
          ) : (
            <>
              {/* TAB 1: OVERVIEW */}
              {activeTab === 'OVERVIEW' && (
                <div className="space-y-4">
                  {/* Risk Profile Score Card */}
                  <div className="bg-[#111827] p-4 rounded-xl border border-gray-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4" /> IP RISK PROFILE
                      </span>
                      <span className="text-[10px] font-mono bg-gray-800 px-2 py-0.5 rounded text-gray-400">
                        INTERNAL SECURITY EVIDENCE
                      </span>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="w-20 h-20 rounded-full border-4 border-amber-500/30 flex flex-col items-center justify-center bg-[#0B0F17]">
                        <span className="text-2xl font-bold font-mono text-amber-400">
                          {data.risk_profile.ip_risk_score.toFixed(0)}
                        </span>
                        <span className="text-[9px] font-mono text-gray-500">/ 100</span>
                      </div>

                      <div className="flex-1 space-y-1.5 text-xs font-mono">
                        <div className="text-gray-200 font-bold">
                          Threat Classification: {data.risk_profile.threat_level}
                        </div>
                        <p className="text-[11px] text-gray-400 leading-relaxed">
                          {data.risk_profile.formula_documentation}
                        </p>
                      </div>
                    </div>

                    {/* Factor Breakdown Bars */}
                    <div className="grid grid-cols-2 gap-2 pt-2 border-t border-gray-800 text-[11px] font-mono">
                      <div>
                        <div className="flex justify-between text-gray-400 mb-0.5">
                          <span>Event Volume:</span>
                          <span className="text-gray-200">{data.risk_profile.event_volume_score}</span>
                        </div>
                        <div className="w-full bg-gray-800 h-1 rounded">
                          <div className="bg-blue-400 h-1 rounded" style={{ width: `${data.risk_profile.event_volume_score}%` }} />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-gray-400 mb-0.5">
                          <span>Anomaly Factor:</span>
                          <span className="text-amber-400">{data.risk_profile.anomaly_factor_score}</span>
                        </div>
                        <div className="w-full bg-gray-800 h-1 rounded">
                          <div className="bg-amber-400 h-1 rounded" style={{ width: `${data.risk_profile.anomaly_factor_score}%` }} />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-gray-400 mb-0.5">
                          <span>Incident Clustered:</span>
                          <span className="text-purple-400">{data.risk_profile.incident_factor_score}</span>
                        </div>
                        <div className="w-full bg-gray-800 h-1 rounded">
                          <div className="bg-purple-400 h-1 rounded" style={{ width: `${data.risk_profile.incident_factor_score}%` }} />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-gray-400 mb-0.5">
                          <span>Severity Factor:</span>
                          <span className="text-red-400">{data.risk_profile.severity_factor_score}</span>
                        </div>
                        <div className="w-full bg-gray-800 h-1 rounded">
                          <div className="bg-red-400 h-1 rounded" style={{ width: `${data.risk_profile.severity_factor_score}%` }} />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Passive Geo & Network Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="bg-[#111827] p-3.5 rounded-xl border border-gray-800 space-y-2">
                      <div className="text-gray-400 font-semibold flex items-center gap-1.5">
                        <MapPin className="w-3.5 h-3.5 text-blue-400" /> GEOLOCATION (PASSIVE)
                      </div>
                      <div className="text-gray-200 font-bold">{data.geo.primary_location}</div>
                      <div className="text-[10px] text-gray-500">{data.geo.approximate_coordinates}</div>
                    </div>

                    <div className="bg-[#111827] p-3.5 rounded-xl border border-gray-800 space-y-2">
                      <div className="text-gray-400 font-semibold flex items-center gap-1.5">
                        <Network className="w-3.5 h-3.5 text-cyan-400" /> NETWORK CLASSIFICATION
                      </div>
                      <div className="text-gray-200 font-bold">{data.cidr_classification}</div>
                      <div className="text-[10px] text-gray-500">{data.network.address_type}</div>
                    </div>
                  </div>

                  {/* Reputation Disclosure */}
                  <div className="bg-[#111827] p-4 rounded-xl border border-gray-800 space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between text-gray-400 font-semibold">
                      <span className="flex items-center gap-1.5">
                        <Activity className="w-3.5 h-3.5 text-amber-400" /> EXTERNAL REPUTATION STATUS
                      </span>
                      <span className="text-[10px] bg-gray-800 px-2 py-0.5 rounded text-gray-500">
                        {data.reputation.source_classification}
                      </span>
                    </div>
                    <div className="text-amber-400 font-bold">{data.reputation.status}</div>
                    <p className="text-[11px] text-gray-400">{data.reputation.reason}</p>
                    <div className="text-[10px] text-gray-500 pt-1 border-t border-gray-800">
                      {data.reputation.disclaimer}
                    </div>
                  </div>

                  {/* Behaviour Summary Grid */}
                  <div className="bg-[#111827] p-4 rounded-xl border border-gray-800 space-y-3 text-xs font-mono">
                    <div className="text-gray-300 font-semibold flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-indigo-400" /> BEHAVIOURAL PROFILE METRICS
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                      <div className="bg-[#0B0F17] p-2 rounded-lg border border-gray-800">
                        <div className="text-[10px] text-gray-500">EVENTS</div>
                        <div className="text-sm font-bold text-blue-400">{data.behaviour.total_events}</div>
                      </div>
                      <div className="bg-[#0B0F17] p-2 rounded-lg border border-gray-800">
                        <div className="text-[10px] text-gray-500">ANOMALIES</div>
                        <div className="text-sm font-bold text-amber-400">{data.behaviour.total_anomalies}</div>
                      </div>
                      <div className="bg-[#0B0F17] p-2 rounded-lg border border-gray-800">
                        <div className="text-[10px] text-gray-500">INCIDENTS</div>
                        <div className="text-sm font-bold text-purple-400">{data.behaviour.total_incidents}</div>
                      </div>
                      <div className="bg-[#0B0F17] p-2 rounded-lg border border-gray-800">
                        <div className="text-[10px] text-gray-500">ATT&CK TECHS</div>
                        <div className="text-sm font-bold text-red-400">{data.behaviour.associated_mitre_techniques.length}</div>
                      </div>
                    </div>

                    <div className="space-y-1 text-[11px] pt-1">
                      <div className="text-gray-400">
                        <span className="text-gray-500">Associated Users:</span>{' '}
                        {data.behaviour.associated_users.join(', ') || 'None recorded'}
                      </div>
                      <div className="text-gray-400">
                        <span className="text-gray-500">Associated Devices:</span>{' '}
                        {data.behaviour.associated_devices.join(', ') || 'None recorded'}
                      </div>
                      <div className="text-gray-400">
                        <span className="text-gray-500">Target Servers:</span>{' '}
                        {data.behaviour.associated_servers.join(', ') || 'None recorded'}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: ENTITY RELATIONSHIP GRAPH */}
              {activeTab === 'GRAPH' && (
                <div className="space-y-3">
                  <div className="text-xs font-mono text-gray-400 flex items-center justify-between">
                    <span>IP &rarr; ENTITY RELATIONSHIPS ({data.entity_graph.nodes.length} NODES):</span>
                    <span className="text-[10px] text-gray-500">Grounded to stored events</span>
                  </div>

                  <div className="bg-[#0B0F17] p-4 rounded-xl border border-gray-800 space-y-3">
                    <div className="flex flex-wrap gap-2">
                      {data.entity_graph.nodes.map((node: any) => (
                        <div
                          key={node.id}
                          className={`p-2.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${
                            node.type === 'ip' ? 'bg-blue-950/60 border-blue-800 text-blue-300' :
                            node.type === 'user' ? 'bg-indigo-950/60 border-indigo-800 text-indigo-300' :
                            node.type === 'device' ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300' :
                            node.type === 'server' ? 'bg-cyan-950/60 border-cyan-800 text-cyan-300' :
                            node.type === 'incident' ? 'bg-purple-950/60 border-purple-800 text-purple-300 cursor-pointer hover:border-purple-400' :
                            'bg-red-950/60 border-red-800 text-red-300'
                          }`}
                          onClick={() => {
                            if (node.type === 'incident' && node.metadata?.incident_id) {
                              onClose();
                              navigate(`/incidents/${node.metadata.incident_id}`);
                            }
                          }}
                        >
                          {node.type === 'ip' && <Globe className="w-3.5 h-3.5" />}
                          {node.type === 'user' && <User className="w-3.5 h-3.5" />}
                          {node.type === 'device' && <Laptop className="w-3.5 h-3.5" />}
                          {node.type === 'server' && <Server className="w-3.5 h-3.5" />}
                          {node.type === 'incident' && <ShieldAlert className="w-3.5 h-3.5" />}
                          {node.type === 'mitre' && <Target className="w-3.5 h-3.5" />}
                          <span className="font-semibold">{node.label}</span>
                          {node.type === 'incident' && <ExternalLink className="w-3 h-3 ml-1" />}
                        </div>
                      ))}
                    </div>

                    <div className="pt-3 border-t border-gray-800 text-[11px] font-mono text-gray-400 space-y-1">
                      <div className="font-semibold text-gray-300">Observed Edges:</div>
                      {data.entity_graph.edges.map((edge: any) => (
                        <div key={edge.id} className="text-gray-500">
                          &bull; {edge.source} &rarr; {edge.target} <span className="text-blue-400">({edge.label})</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: ATTACK PATH */}
              {activeTab === 'ATTACK_PATH' && (
                <div className="space-y-3">
                  <div className="text-xs font-mono text-gray-400">
                    CHRONOLOGICAL ATTACK PATH RECONSTRUCTION:
                  </div>

                  <div className="space-y-2">
                    {data.attack_path.map((step: any) => (
                      <div
                        key={step.step_number}
                        className="bg-[#111827] p-3.5 rounded-xl border border-gray-800 flex items-start gap-3 font-mono text-xs"
                      >
                        <div className="w-6 h-6 rounded-full bg-gray-800 border border-gray-700 flex items-center justify-center font-bold text-gray-300 shrink-0 text-[11px]">
                          {step.step_number}
                        </div>

                        <div className="flex-1 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] text-blue-400 font-bold">{step.stage_name}</span>
                            <span className={`text-[9px] px-1.5 py-0.2 rounded ${
                              step.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                              step.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              'bg-gray-800 text-gray-400'
                            }`}>
                              {step.severity}
                            </span>
                          </div>

                          <div className="text-gray-200 font-semibold">{step.entity_name}</div>
                          <p className="text-[11px] text-gray-400 leading-relaxed">{step.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 4: TIMELINE */}
              {activeTab === 'TIMELINE' && (
                <div className="space-y-3">
                  <div className="text-xs font-mono text-gray-400">
                    ACTUAL TELEMETRY EVENT STREAM ({data.timeline.length} EVENTS):
                  </div>

                  <div className="space-y-2">
                    {data.timeline.map((ev: any) => (
                      <div
                        key={ev.event_id}
                        className="bg-[#111827] p-3 rounded-xl border border-gray-800 font-mono text-xs space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] text-gray-500">
                            {new Date(ev.timestamp).toISOString()}
                          </span>
                          <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                            ev.status === 'SUCCESS' ? 'text-emerald-400 bg-emerald-950/40 border border-emerald-800' :
                            'text-red-400 bg-red-950/40 border border-red-800'
                          }`}>
                            {ev.status}
                          </span>
                        </div>

                        <div className="flex items-center justify-between">
                          <span className="text-gray-200 font-bold">{ev.action}</span>
                          <span className="text-gray-400 text-[11px]">{ev.event_type}</span>
                        </div>

                        <div className="text-[11px] text-gray-400 flex flex-wrap gap-x-3">
                          {ev.username && <span>User: <strong className="text-gray-300">{ev.username}</strong></span>}
                          {ev.device_name && <span>Host: <strong className="text-gray-300">{ev.device_name}</strong></span>}
                          {ev.process_name && <span>Proc: <strong className="text-gray-300">{ev.process_name}</strong></span>}
                        </div>

                        {ev.is_anomaly && (
                          <div className="text-[10px] text-amber-400 font-semibold flex items-center gap-1 pt-1">
                            <AlertTriangle className="w-3 h-3" />
                            POTENTIAL ANOMALY (Score: {ev.anomaly_score?.toFixed(1) || 'Rule flagged'})
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 5: CLUSTERS */}
              {activeTab === 'CLUSTERS' && (
                <div className="space-y-3">
                  <div className="text-xs font-mono text-gray-400">
                    OBSERVED CO-OCCURRING IP CLUSTERS:
                  </div>

                  {data.related_clusters.length > 0 ? (
                    <div className="space-y-2">
                      {data.related_clusters.map((c: any, i: number) => (
                        <div
                          key={i}
                          className="bg-[#111827] p-3.5 rounded-xl border border-gray-800 font-mono text-xs space-y-2"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-blue-400">{c.related_ip}</span>
                            <span className="text-[10px] bg-gray-800 px-2 py-0.5 rounded text-gray-400">
                              {c.ip_type}
                            </span>
                          </div>
                          <p className="text-[11px] text-gray-400">{c.relationship_type}</p>
                          <div className="flex gap-4 text-[10px] text-gray-500">
                            <span>Shared Incidents: <strong>{c.shared_incidents_count}</strong></span>
                            <span>Shared Target Hosts: <strong>{c.shared_targets_count}</strong></span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-gray-500 text-xs font-mono p-4 bg-[#0B0F17] rounded-xl border border-gray-800">
                      No co-occurring clusters observed for this IP in correlated incidents yet.
                    </div>
                  )}

                  <div className="p-3 bg-gray-900/60 rounded-lg border border-gray-800 text-[10px] font-mono text-gray-500">
                    <Info className="w-3.5 h-3.5 inline mr-1 text-blue-400" />
                    Labels represent neutral observed relationships (e.g. shared incident or target host). Zero attribution claims made without evidence.
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Drawer Footer Actions */}
        <div className="p-4 border-t border-gray-800 bg-[#111827] flex items-center justify-between shrink-0 font-mono text-xs">
          <button
            onClick={() => {
              onClose();
              navigate('/incidents');
            }}
            className="flex items-center gap-1.5 text-gray-400 hover:text-gray-200 transition-colors"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span>View Correlated Incidents</span>
          </button>

          <button
            onClick={() => {
              onClose();
              navigate('/simulation');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 border border-blue-500/50 rounded-lg transition-colors"
          >
            <span>Simulate Containment</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
