import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { 
  ShieldAlert, 
  Clock, 
  ChevronRight, 
  Filter, 
  Flame
} from 'lucide-react';

interface MitreTechniqueSummary {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
}

interface IncidentItem {
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
  updated_at: string;
  event_count: number;
  mitre_techniques: MitreTechniqueSummary[];
}

export const IncidentsPage: React.FC = () => {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const headers = { Authorization: `Bearer ${token}` };

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      let url = '/api/v1/incidents?limit=50';
      if (statusFilter !== 'ALL') url += `&status=${statusFilter}`;
      if (severityFilter !== 'ALL') url += `&severity=${severityFilter}`;
      
      const res = await axios.get(url, { headers });
      setIncidents(res.data.incidents || []);
      setTotalCount(res.data.total || 0);
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const timer = setInterval(fetchIncidents, 8000);
    return () => clearInterval(timer);
  }, [token, statusFilter, severityFilter]);

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-300 border-red-800';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800';
      default:
        return 'bg-blue-950/80 text-blue-300 border-blue-800';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'NEW':
        return 'bg-blue-950 text-blue-400 border-blue-800';
      case 'INVESTIGATING':
        return 'bg-purple-950 text-purple-300 border-purple-800';
      case 'CONTAINMENT_RECOMMENDED':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'CONTAINED':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'RESOLVED':
        return 'bg-gray-800 text-gray-300 border-gray-700';
      default:
        return 'bg-gray-900 text-gray-400 border-gray-800';
    }
  };

  const getSlaRemaining = (deadlineStr?: string) => {
    if (!deadlineStr) return { text: 'No SLA', color: 'text-gray-500' };
    const deadline = new Date(deadlineStr).getTime();
    const now = Date.now();
    const diffMs = deadline - now;
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins <= 0) {
      return { text: 'SLA BREACHED', color: 'text-red-400 font-bold animate-pulse' };
    } else if (diffMins <= 10) {
      return { text: `${diffMins}m remaining`, color: 'text-amber-400 font-semibold' };
    } else {
      return { text: `${diffMins}m remaining`, color: 'text-emerald-400' };
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-7 h-7 text-indigo-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Incident Management & Workbench
            </h1>
          </div>
          <p className="text-sm text-gray-400 mt-1">
            Correlated multi-stage security incidents with 6-factor risk scoring, SLA countdowns, and MITRE ATT&CK mapping.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-xs font-mono px-3 py-1.5 rounded bg-gray-900 border border-gray-800 text-gray-300">
            Total Incidents: <strong className="text-white">{totalCount}</strong>
          </div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#111827] p-3 rounded-lg border border-gray-800 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-gray-500 flex items-center gap-1 mr-1">
            <Filter className="w-3.5 h-3.5" /> Status:
          </span>
          {['ALL', 'NEW', 'INVESTIGATING', 'CONTAINMENT_RECOMMENDED', 'CONTAINED', 'RESOLVED'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded transition ${
                statusFilter === st
                  ? 'bg-indigo-600 text-white font-semibold'
                  : 'bg-gray-900 text-gray-400 hover:text-white border border-gray-800'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-gray-500">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2 py-0.5 rounded transition ${
                severityFilter === sev
                  ? 'bg-gray-700 text-white font-semibold'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Incident Queue Table */}
      <div className="bg-[#111827] border border-gray-800 rounded-lg overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-900/90 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Incident Title</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-center">Composite Risk</th>
                <th className="p-3.5 text-center">Evidence Quality</th>
                <th className="p-3.5">SLA Countdown</th>
                <th className="p-3.5">MITRE ATT&CK</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-gray-500">
                    {loading ? 'Loading incidents...' : 'No incidents match active filters. Use the Ingestion & Demo panel to inject scenarios.'}
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => {
                  const sla = getSlaRemaining(inc.sla_breach_deadline);
                  return (
                    <tr
                      key={inc.incident_id}
                      onClick={() => navigate(`/incidents/${inc.incident_id}`)}
                      className="hover:bg-gray-800/50 cursor-pointer transition"
                    >
                      <td className="p-3.5">
                        <span className={`px-2.5 py-1 rounded text-[10px] font-bold border ${getSeverityBadge(inc.severity)}`}>
                          {inc.severity}
                        </span>
                      </td>
                      <td className="p-3.5">
                        <div className="font-semibold text-gray-200 hover:text-indigo-400 transition text-sm">
                          {inc.incident_title}
                        </div>
                        <div className="text-[11px] text-gray-500 mt-0.5 flex items-center gap-2">
                          <span>{inc.event_count} correlated events</span>
                          <span>&bull;</span>
                          <span>Created {new Date(inc.created_at).toLocaleTimeString()}</span>
                          {inc.assigned_analyst && (
                            <>
                              <span>&bull;</span>
                              <span className="text-indigo-400">@{inc.assigned_analyst}</span>
                            </>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-medium border ${getStatusBadge(inc.status)}`}>
                          {inc.status}
                        </span>
                      </td>
                      <td className="p-3.5 text-center">
                        <div className="inline-flex items-center gap-1 font-bold text-sm">
                          <Flame className={`w-3.5 h-3.5 ${inc.risk_score >= 70 ? 'text-red-400' : inc.risk_score >= 40 ? 'text-amber-400' : 'text-blue-400'}`} />
                          <span className={inc.risk_score >= 70 ? 'text-red-400' : inc.risk_score >= 40 ? 'text-amber-400' : 'text-blue-400'}>
                            {inc.risk_score.toFixed(1)}
                          </span>
                        </div>
                        <div className="text-[10px] text-gray-500">/ 100 max</div>
                      </td>
                      <td className="p-3.5 text-center">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${
                          inc.evidence_quality === 'HIGH' 
                            ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800' 
                            : inc.evidence_quality === 'MEDIUM' 
                            ? 'bg-blue-950/60 text-blue-300 border-blue-800' 
                            : 'bg-gray-900 text-gray-400 border-gray-800'
                        }`}>
                          {inc.evidence_quality}
                        </span>
                      </td>
                      <td className="p-3.5">
                        <div className={`flex items-center gap-1.5 text-xs font-mono ${sla.color}`}>
                          <Clock className="w-3.5 h-3.5" />
                          <span>{sla.text}</span>
                        </div>
                      </td>
                      <td className="p-3.5">
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {inc.mitre_techniques.slice(0, 3).map((mt) => (
                            <span
                              key={mt.technique_id}
                              className="px-1.5 py-0.5 rounded text-[9px] bg-red-950/70 border border-red-900 text-red-300"
                              title={`${mt.technique_name} (${mt.tactic})`}
                            >
                              {mt.technique_id}
                            </span>
                          ))}
                          {inc.mitre_techniques.length > 3 && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] bg-gray-800 text-gray-400">
                              +{inc.mitre_techniques.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5 text-right">
                        <button className="inline-flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300 transition">
                          Investigate <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
