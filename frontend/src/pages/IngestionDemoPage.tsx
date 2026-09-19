import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { 
  Upload, 
  Play, 
  RotateCcw, 
  CheckCircle2, 
  Activity, 
  FileText, 
  Layers, 
  Eye, 
  EyeOff,
  Radio
} from 'lucide-react';

interface IngestionBatch {
  batch_id: string;
  source_format: string;
  total_records: number;
  valid_records: number;
  invalid_records: number;
  duplicate_records: number;
  stored_records: number;
  processing_time_ms: number;
  created_at: string;
}

interface SecurityEventItem {
  event_id: string;
  timestamp: string;
  username: string | null;
  source_ip: string | null;
  device_name: string | null;
  event_type: string;
  action: string;
  status: string;
  severity: string;
  metadata_json: Record<string, any>;
}

export const IngestionDemoPage: React.FC = () => {
  const { token, user } = useAuth();
  const role = user?.roles[0]?.name || 'Viewer';
  const [batches, setBatches] = useState<IngestionBatch[]>([]);
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<{ text: string; type: 'success' | 'error' | 'info' } | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadType, setUploadType] = useState<'csv' | 'json'>('csv');

  const headers = { Authorization: `Bearer ${token}` };

  const fetchTelemetry = async () => {
    try {
      const [batchRes, eventRes] = await Promise.all([
        axios.get('/api/v1/events/batches?limit=5', { headers }),
        axios.get('/api/v1/events?limit=25', { headers })
      ]);
      setBatches(batchRes.data.batches || []);
      setEvents(eventRes.data.events || []);
    } catch (err: any) {
      console.error('Failed to fetch ingestion telemetry:', err);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 6000);
    return () => clearInterval(interval);
  }, [token]);

  const handleScenarioTrigger = async (endpoint: string, scenarioName: string) => {
    setLoading(true);
    setActionMessage(null);
    try {
      const res = await axios.post(`/api/v1/demo/${endpoint}`, {}, { headers });
      setActionMessage({
        text: `[SYNTHETIC DATA] ${scenarioName} injected: ${res.data.events_generated || res.data.message || 'Complete'}`,
        type: 'success'
      });
      await fetchTelemetry();
    } catch (err: any) {
      setActionMessage({
        text: err.response?.data?.detail || `Failed to execute ${scenarioName}`,
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;

    setLoading(true);
    setActionMessage(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const endpoint = uploadType === 'csv' ? '/api/v1/events/upload-csv' : '/api/v1/events/upload-json';
      const res = await axios.post(endpoint, formData, {
        headers: {
          ...headers,
          'Content-Type': 'multipart/form-data'
        }
      });
      setActionMessage({
        text: `Batch ${res.data.batch_id} processed: ${res.data.valid_records} valid, ${res.data.duplicate_records} duplicates, ${res.data.stored_records} stored.`,
        type: 'success'
      });
      setSelectedFile(null);
      await fetchTelemetry();
    } catch (err: any) {
      setActionMessage({
        text: err.response?.data?.detail || 'File upload failed.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-900/60 text-red-300 border-red-700';
      case 'HIGH':
        return 'bg-amber-900/60 text-amber-300 border-amber-700';
      case 'MEDIUM':
        return 'bg-yellow-900/60 text-yellow-300 border-yellow-700';
      case 'LOW':
        return 'bg-blue-900/60 text-blue-300 border-blue-700';
      default:
        return 'bg-gray-800 text-gray-300 border-gray-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <Radio className="w-7 h-7 text-indigo-400 animate-pulse" />
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Telemetry Ingestion & Synthetic Scenarios
            </h1>
          </div>
          <p className="text-sm text-gray-400 mt-1">
            Dual-format CSV/JSON ingestion pipeline with deterministic attack scenario generators.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono bg-emerald-950/60 border border-emerald-800 text-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5" /> Pipeline Active
          </span>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono bg-indigo-950/60 border border-indigo-800 text-indigo-300">
            Seed = 42
          </span>
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div className={`p-4 rounded-lg border text-sm font-mono flex items-center justify-between ${
          actionMessage.type === 'success' 
            ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200' 
            : actionMessage.type === 'error'
            ? 'bg-red-950/40 border-red-800 text-red-200'
            : 'bg-blue-950/40 border-blue-800 text-blue-200'
        }`}>
          <span>{actionMessage.text}</span>
          <button 
            onClick={() => setActionMessage(null)}
            className="text-xs text-gray-400 hover:text-white ml-4 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Control Grid: Synthetic Scenarios & Ingestion Upload */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Synthetic Attack Scenario Generators (2 Cols) */}
        <div className="lg:col-span-2 bg-[#111827] border border-gray-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Play className="w-4 h-4 text-indigo-400" />
              Synthetic Attack Scenarios (seed=42)
            </h2>
            <span className="text-xs font-mono text-amber-400 bg-amber-950/50 border border-amber-800 px-2 py-0.5 rounded">
              SYNTHETIC DATA
            </span>
          </div>
          <p className="text-xs text-gray-400 mb-4">
            Inject deterministic security scenarios to evaluate detection rules, UEBA baseline deviations, and Isolation Forest ML models.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              onClick={() => handleScenarioTrigger('generate-normal', 'Normal Activity Baseline')}
              disabled={loading}
              className="p-3 bg-gray-900/90 hover:bg-gray-800 border border-gray-700/80 rounded text-left transition duration-150 disabled:opacity-50"
            >
              <div className="text-sm font-medium text-emerald-400 flex items-center justify-between">
                <span>Baseline Activity</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 bg-emerald-950 text-emerald-300 rounded border border-emerald-800">Normal</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Inject 15 normal user sessions matching 30-day active-hour baselines.
              </p>
            </button>

            <button
              onClick={() => handleScenarioTrigger('generate-suspicious', 'Suspicious Brute-Force & Impossible Travel')}
              disabled={loading}
              className="p-3 bg-gray-900/90 hover:bg-gray-800 border border-gray-700/80 rounded text-left transition duration-150 disabled:opacity-50"
            >
              <div className="text-sm font-medium text-amber-400 flex items-center justify-between">
                <span>Brute-Force & Travel</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 bg-amber-950 text-amber-300 rounded border border-amber-800">Rule/UEBA</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Fires RULE-AUTH-001/002 and Haversine velocity RULE-GEO-001 (&gt;1000 km/h).
              </p>
            </button>

            <button
              onClick={() => handleScenarioTrigger('generate-coordinated-attack', 'Full Coordinated Kill-Chain Attack')}
              disabled={loading}
              className="p-3 bg-gray-900/90 hover:bg-gray-800 border border-red-900/50 rounded text-left transition duration-150 disabled:opacity-50"
            >
              <div className="text-sm font-medium text-red-400 flex items-center justify-between">
                <span>Coordinated Kill-Chain</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 bg-red-950 text-red-300 rounded border border-red-800">Multi-Stage</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Initial access $\to$ Discovery $\to$ Lateral move $\to$ Exfiltration (5 MITRE tactics).
              </p>
            </button>

            <button
              onClick={() => handleScenarioTrigger('run-full-simulation', 'Full Comprehensive Multi-Scenario Suite')}
              disabled={loading}
              className="p-3 bg-gray-900/90 hover:bg-gray-800 border border-indigo-900/50 rounded text-left transition duration-150 disabled:opacity-50"
            >
              <div className="text-sm font-medium text-indigo-400 flex items-center justify-between">
                <span>Full Simulation Suite</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 bg-indigo-950 text-indigo-300 rounded border border-indigo-800">Comprehensive</span>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Executes all 6 attack scenarios in succession for complete SOC workload testing.
              </p>
            </button>
          </div>

          <div className="mt-4 pt-4 border-t border-gray-800 flex justify-end">
            <button
              onClick={() => handleScenarioTrigger('reset', 'Synthetic Telemetry Reset')}
              disabled={loading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono bg-gray-800 hover:bg-gray-700 text-gray-300 transition"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Reset Synthetic Telemetry
            </button>
          </div>
        </div>

        {/* Multi-Format File Ingestion (1 Col) */}
        <div className="bg-[#111827] border border-gray-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-2">
              <Upload className="w-4 h-4 text-emerald-400" />
              Batch File Ingestion
            </h2>
            <p className="text-xs text-gray-400 mb-4">
              Upload raw event files. Events are normalized to canonical schema and deduplicated via SHA-256 event hash.
            </p>

            <form onSubmit={handleFileUpload} className="space-y-3">
              <div className="flex gap-2 mb-2">
                <button
                  type="button"
                  onClick={() => setUploadType('csv')}
                  className={`flex-1 py-1 text-xs rounded font-mono border ${
                    uploadType === 'csv' 
                      ? 'bg-emerald-950/60 border-emerald-700 text-emerald-300' 
                      : 'bg-gray-900 border-gray-800 text-gray-400'
                  }`}
                >
                  CSV Format
                </button>
                <button
                  type="button"
                  onClick={() => setUploadType('json')}
                  className={`flex-1 py-1 text-xs rounded font-mono border ${
                    uploadType === 'json' 
                      ? 'bg-emerald-950/60 border-emerald-700 text-emerald-300' 
                      : 'bg-gray-900 border-gray-800 text-gray-400'
                  }`}
                >
                  JSON Format
                </button>
              </div>

              <div className="border-2 border-dashed border-gray-800 hover:border-gray-700 rounded-lg p-4 text-center cursor-pointer transition">
                <input
                  type="file"
                  id="event-file-input"
                  accept={uploadType === 'csv' ? '.csv' : '.json'}
                  onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                  className="hidden"
                />
                <label htmlFor="event-file-input" className="cursor-pointer">
                  <FileText className="w-8 h-8 text-gray-500 mx-auto mb-1" />
                  <span className="text-xs text-gray-300 block font-medium">
                    {selectedFile ? selectedFile.name : `Select ${uploadType.toUpperCase()} File`}
                  </span>
                  <span className="text-[10px] text-gray-500 block mt-0.5">
                    {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : 'Max 10MB batch'}
                  </span>
                </label>
              </div>

              <button
                type="submit"
                disabled={!selectedFile || loading}
                className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:hover:bg-emerald-600 text-white font-medium text-xs rounded transition flex items-center justify-center gap-1.5"
              >
                <Upload className="w-3.5 h-3.5" />
                {loading ? 'Processing...' : 'Ingest Batch'}
              </button>
            </form>
          </div>

          <div className="mt-4 pt-3 border-t border-gray-800 text-[11px] text-gray-500 font-mono">
            RBAC: Ingestion requires Security Analyst or Security Admin.
          </div>
        </div>
      </div>

      {/* Batch Ingestion Telemetry Bar */}
      <div className="bg-[#111827] border border-gray-800 rounded-lg p-4">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
          <Layers className="w-3.5 h-3.5 text-indigo-400" /> Recent Ingestion Batches
        </h3>
        {batches.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono py-2">No batch processing history available yet.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {batches.map((b) => (
              <div key={b.batch_id} className="bg-gray-900/70 border border-gray-800 rounded p-3 text-xs font-mono">
                <div className="flex items-center justify-between text-gray-400 mb-1.5">
                  <span className="text-[10px] text-indigo-400 font-semibold">{b.source_format.toUpperCase()}</span>
                  <span className="text-[10px] text-gray-500">{b.processing_time_ms.toFixed(1)} ms</span>
                </div>
                <div className="grid grid-cols-2 gap-1 text-[11px]">
                  <span className="text-gray-400">Total: <strong className="text-white">{b.total_records}</strong></span>
                  <span className="text-gray-400">Valid: <strong className="text-emerald-400">{b.valid_records}</strong></span>
                  <span className="text-gray-400">Duplicates: <strong className="text-amber-400">{b.duplicate_records}</strong></span>
                  <span className="text-gray-400">Stored: <strong className="text-blue-400">{b.stored_records}</strong></span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Live Event Stream Table */}
      <div className="bg-[#111827] border border-gray-800 rounded-lg overflow-hidden">
        <div className="p-4 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">Live Ingested Security Event Stream</h3>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs font-mono text-gray-400">
              {role === 'Viewer' ? (
                <>
                  <EyeOff className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-amber-400">PII Masked (Viewer Role)</span>
                </>
              ) : (
                <>
                  <Eye className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Full Visibility ({role})</span>
                </>
              )}
            </div>
            <span className="text-xs font-mono text-gray-500">{events.length} events loaded</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-900/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="p-3">Timestamp (UTC)</th>
                <th className="p-3">Event Type</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Identity / User</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Device / Host</th>
                <th className="p-3">Action</th>
                <th className="p-3">Detection Flags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-6 text-center text-gray-500">
                    No security events available. Trigger a synthetic scenario above to populate telemetry.
                  </td>
                </tr>
              ) : (
                events.map((ev) => {
                  const ruleId = ev.metadata_json?.detection_rule_id;
                  const anomalyScore = ev.metadata_json?.ml_anomaly_score;
                  return (
                    <tr key={ev.event_id} className="hover:bg-gray-800/40 transition">
                      <td className="p-3 text-gray-400 whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="p-3 font-semibold text-gray-200">{ev.event_type}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(ev.severity)}`}>
                          {ev.severity}
                        </span>
                      </td>
                      <td className="p-3 text-gray-300">{ev.username || '—'}</td>
                      <td className="p-3 text-gray-400">{ev.source_ip || '—'}</td>
                      <td className="p-3 text-gray-400">{ev.device_name || '—'}</td>
                      <td className="p-3 text-gray-400">{ev.action}</td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {ruleId && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-950/80 text-red-300 border border-red-800">
                              {ruleId}
                            </span>
                          )}
                          {anomalyScore !== undefined && anomalyScore > 50 && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] bg-amber-950/80 text-amber-300 border border-amber-800" title="Isolation Forest Normalized Score">
                              POTENTIAL ANOMALY ({anomalyScore.toFixed(0)})
                            </span>
                          )}
                          {!ruleId && (!anomalyScore || anomalyScore <= 50) && (
                            <span className="text-gray-500 text-[10px]">Normal</span>
                          )}
                        </div>
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
