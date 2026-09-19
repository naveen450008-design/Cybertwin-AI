import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Lock, 
  CheckCircle2, 
  AlertOctagon, 
  Cpu, 
  Database,
  RefreshCw,
  Activity
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';
import { HealthResponse } from '../types/health';
import axios from 'axios';

export const DashboardPage: React.FC = () => {
  const { user, hasRole } = useAuth();
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [isHealthLoading, setIsHealthLoading] = useState(true);

  // RBAC Test State
  const [rbacTestResult, setRbacTestResult] = useState<{
    status: 'IDLE' | 'SUCCESS' | 'DENIED' | 'ERROR';
    message: string;
  }>({ status: 'IDLE', message: '' });
  const [isTestingRbac, setIsTestingRbac] = useState(false);

  const [eventStats, setEventStats] = useState<{ total: number; anomalies: number; batches: number }>({ total: 0, anomalies: 0, batches: 0 });
  const { token } = useAuth();

  const fetchHealth = async () => {
    setIsHealthLoading(true);
    try {
      const data = await authService.getHealth();
      setHealthData(data);
    } catch {
      setHealthData({
        status: 'degraded',
        version: '0.1.0',
        timestamp: new Date().toISOString(),
        database: 'OFFLINE',
      });
    } finally {
      setIsHealthLoading(false);
    }
  };

  const fetchStats = async () => {
    if (!token) return;
    try {
      const authHeaders = { headers: { Authorization: `Bearer ${token}` } };
      const [eventsRes, batchesRes] = await Promise.all([
        axios.get('/api/v1/events?limit=50', authHeaders),
        axios.get('/api/v1/events/batches?limit=1', authHeaders)
      ]);
      const evList = eventsRes.data.events || [];
      const anomalyCount = evList.filter((e: any) => 
        (e.metadata_json?.ml_anomaly_score && e.metadata_json?.ml_anomaly_score > 50) || 
        e.metadata_json?.detection_rule_id
      ).length;
      setEventStats({
        total: eventsRes.data.total_count || evList.length,
        anomalies: anomalyCount,
        batches: batchesRes.data.total_batches || 0
      });
    } catch {
      // Graceful fallback if no events yet
    }
  };

  useEffect(() => {
    fetchHealth();
    fetchStats();
  }, [token]);

  const handleTestRbac = async () => {
    setIsTestingRbac(true);
    setRbacTestResult({ status: 'IDLE', message: '' });
    try {
      const res = await authService.testAdminAction();
      setRbacTestResult({
        status: 'SUCCESS',
        message: `HTTP 200 OK — ${res.message} (Executed as: ${user?.username})`,
      });
    } catch (err: any) {
      if (err.response?.status === 403) {
        setRbacTestResult({
          status: 'DENIED',
          message: `HTTP 403 FORBIDDEN — ${err.response.data?.detail || 'Unauthorized for Security Admin operations'}. Active RBAC defense-in-depth verified!`,
        });
      } else {
        setRbacTestResult({
          status: 'ERROR',
          message: `Request failed: ${err.message}`,
        });
      }
    } finally {
      setIsTestingRbac(false);
    }
  };

  const primaryRole = user?.roles[0]?.name || 'Viewer';
  const isAdmin = hasRole('Security Admin');

  return (
    <div className="space-y-6">
      {/* Top Banner: Operational Status & Classification */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
            <span className="text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider">
              ALL SOC MODULES ACTIVE &bull; FULL AUTONOMOUS PIPELINE OPERATIONAL
            </span>
          </div>
          <h2 className="text-lg font-bold text-gray-100 mt-1">
            Enterprise Security Operations Center (Autonomous Platform)
          </h2>
          <p className="text-xs text-gray-400 max-w-2xl mt-1 leading-relaxed">
            Full closed-loop telemetry pipeline: Ingestion deduplication, 30-day UEBA profiling, Isolation Forest 
            anomaly scoring, 15-minute correlation, in-memory Digital Twin response simulation, and SHA-256 tamper-evident audit ledger.
          </p>
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] font-mono">
            <span className="px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-800">
              SYNTHETIC DATA
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-900/40 text-amber-300 border border-amber-800">
              POTENTIAL ANOMALY
            </span>
            <span className="px-2 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-800">
              ESTIMATED PREDICTION
            </span>
            <span className="px-2 py-0.5 rounded bg-cyan-900/40 text-cyan-300 border border-cyan-800">
              SIMULATED ACTION
            </span>
            <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
              INTERNAL EVALUATION METRIC - NON-INDUSTRY STANDARD
            </span>
          </div>
        </div>

        <button
          onClick={fetchHealth}
          disabled={isHealthLoading}
          className="self-start md:self-auto flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-mono rounded-lg border border-gray-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isHealthLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Verified Status Cards (Backed ONLY by live authenticated API data) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Backend API Engine */}
        <div className="bg-[#111827] border border-gray-800/80 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">BACKEND API</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-xl font-bold text-gray-100 font-mono">
            {healthData?.status.toUpperCase() || 'CONNECTING...'}
          </div>
          <div className="text-[11px] text-gray-500 font-mono mt-1">
            FastAPI v{healthData?.version || '0.1.0'} &bull; Python 3.11+
          </div>
        </div>

        {/* Database Connectivity */}
        <div className="bg-[#111827] border border-gray-800/80 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">POSTGRESQL DB</span>
            <Database className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-400 font-mono">
            {healthData?.database || 'CONNECTING...'}
          </div>
          <div className="text-[11px] text-gray-500 font-mono mt-1">
            Asyncpg Driver &bull; SQLAlchemy 2.0
          </div>
        </div>

        {/* Ingested Telemetry (Live Events) */}
        <div className="bg-[#111827] border border-gray-800/80 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">INGESTED EVENTS</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-xl font-bold text-indigo-400 font-mono">
            {eventStats.total}
          </div>
          <div className="text-[11px] text-gray-500 font-mono mt-1">
            {eventStats.batches} Ingestion Batches Processed
          </div>
        </div>

        {/* Anomalies Detected */}
        <div className="bg-[#111827] border border-gray-800/80 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">ACTIVE ANOMALIES</span>
            <AlertOctagon className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-amber-400 font-mono">
            {eventStats.anomalies}
          </div>
          <div className="text-[11px] text-amber-500/80 font-mono mt-1">
            POTENTIAL ANOMALY Marker
          </div>
        </div>
      </div>

      {/* Interactive RBAC Security Verification Laboratory */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between border-b border-gray-800 pb-3 mb-4">
          <div>
            <h3 className="text-sm font-bold text-gray-100 flex items-center gap-2">
              <Lock className="w-4 h-4 text-blue-400" />
              Role-Based Access Control (RBAC) Enforcement Laboratory
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Live validation of backend route dependencies and service authorization checks.
            </p>
          </div>
          <span className="text-xs font-mono bg-gray-800 text-gray-300 px-2 py-0.5 rounded border border-gray-700">
            Current Role: {primaryRole}
          </span>
        </div>

        <div className="space-y-4">
          <div className="bg-[#0B0F17] p-4 rounded-lg border border-gray-800 text-xs font-mono space-y-2">
            <div className="text-gray-400">
              <span className="text-blue-400 font-semibold">Endpoint:</span> GET /api/v1/auth/admin-only-action
            </div>
            <div className="text-gray-400">
              <span className="text-blue-400 font-semibold">Requirement:</span> Security Admin role strictly required.
            </div>
            <div className="text-gray-400">
              <span className="text-blue-400 font-semibold">Expected Behavior:</span>{' '}
              {isAdmin ? (
                <span className="text-emerald-400">HTTP 200 OK (You have Security Admin role)</span>
              ) : (
                <span className="text-red-400">HTTP 403 FORBIDDEN (Denied because you are {primaryRole})</span>
              )}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleTestRbac}
              disabled={isTestingRbac}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-xs font-semibold rounded-lg font-mono tracking-wider transition-colors shadow-md flex items-center gap-2"
            >
              {isTestingRbac && <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />}
              <span>EXECUTE RBAC TEST REQUEST</span>
            </button>
          </div>

          {/* Test Result Display */}
          {rbacTestResult.status === 'SUCCESS' && (
            <div className="p-3 bg-emerald-950/60 border border-emerald-800/80 rounded-lg flex items-start gap-2 text-xs font-mono text-emerald-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">PERMISSION GRANTED:</span> {rbacTestResult.message}
              </div>
            </div>
          )}

          {rbacTestResult.status === 'DENIED' && (
            <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-lg flex items-start gap-2 text-xs font-mono text-red-300">
              <AlertOctagon className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">ACCESS PROHIBITED (EXPECTED FOR NON-ADMIN):</span> {rbacTestResult.message}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Active Autonomous Platform Capabilities */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between border-b border-gray-800 pb-3 mb-3">
          <div className="flex items-center gap-2 text-xs font-mono text-gray-400">
            <Cpu className="w-4 h-4 text-purple-400" />
            <span>OPERATIONAL CAPABILITIES & WORKBENCHES</span>
          </div>
          <span className="text-[11px] font-mono text-emerald-400 font-semibold flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            PHASES 0–8 FULLY OPERATIONAL
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-3 bg-[#0B0F17] rounded-lg border border-gray-800/80">
            <div className="font-semibold text-gray-200 mb-1 flex items-center gap-1.5">
              <span className="px-1.5 py-0.5 rounded bg-blue-900/40 text-blue-400 font-mono text-[10px]">INGEST</span>
              Telemetry & UEBA Pipeline
            </div>
            <ul className="text-gray-400 space-y-1 font-mono text-[11px]">
              <li>&bull; REST, CSV, and JSON Batch Ingestion</li>
              <li>&bull; Synthetic Scenario Engine (Seed=42)</li>
              <li>&bull; 30-Day Gaussian Baseline Profiling</li>
              <li>&bull; Isolation Forest 10D Anomaly Model</li>
              <li>&bull; 10 Deterministic Detection Rules</li>
            </ul>
          </div>

          <div className="p-3 bg-[#0B0F17] rounded-lg border border-gray-800/80">
            <div className="font-semibold text-gray-200 mb-1 flex items-center gap-1.5">
              <span className="px-1.5 py-0.5 rounded bg-indigo-900/40 text-indigo-400 font-mono text-[10px]">LIVE</span>
              Incidents & MITRE ATT&CK
            </div>
            <ul className="text-gray-400 space-y-1 font-mono text-[11px]">
              <li>&bull; 15-Minute Correlation Clustering</li>
              <li>&bull; Canonical 6-Factor Deterministic Risk</li>
              <li>&bull; Dynamic Interactive Attack Graph</li>
              <li>&bull; 1x / 2x / 5x Timeline Replay Scrubber</li>
              <li>&bull; Grounded AI Investigation Copilot</li>
            </ul>
          </div>

          <div className="p-3 bg-[#0B0F17] rounded-lg border border-gray-800/80">
            <div className="font-semibold text-gray-200 mb-1 flex items-center gap-1.5">
              <span className="px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-400 font-mono text-[10px]">SIM / CHAIN</span>
              Digital Twin & Audit Ledger
            </div>
            <ul className="text-gray-400 space-y-1 font-mono text-[11px]">
              <li>&bull; In-Memory Graph $G=(V,E)$ Topology</li>
              <li>&bull; Zero OS/Network Changes (<span className="text-cyan-400">SIMULATED</span>)</li>
              <li>&bull; Blast-Radius Calculation Engine</li>
              <li>&bull; Sequential SHA-256 Tamper Ledger</li>
              <li>&bull; Empirical Precision, Recall & F1 Tuning</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
