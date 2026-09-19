import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Lock, 
  AlertOctagon, 
  Cpu, 
  RefreshCw,
  Activity,
  ShieldAlert,
  Globe,
  ChevronRight
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';
import { HealthResponse } from '../types/health';
import axios from 'axios';
import { SecurityScoreHUD } from '../components/SecurityScoreHUD';
import { ThreatRadar, RadarEntity } from '../components/ThreatRadar';
import { MitreFingerprint, MitreMappedTechnique } from '../components/MitreFingerprint';
import { IPIntelligenceDrawer } from '../components/IPIntelligenceDrawer';

export const DashboardPage: React.FC = () => {
  const { user, hasRole, token } = useAuth();
  const navigate = useNavigate();

  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [isHealthLoading, setIsHealthLoading] = useState(true);

  // Security Score & Threat Telemetry State
  const [securityScoreData, setSecurityScoreData] = useState<any>({
    security_health_score: 88.5,
    health_status: 'OPTIMAL',
    factors: {
      incident_risk_factor: 25.0,
      critical_exposure_factor: 15.0,
      external_network_exposure: 20.0,
      unresolved_anomalies_factor: 18.0,
      containment_rate_factor: 92.0
    },
    active_incidents_count: 0,
    critical_incidents_count: 0,
    total_anomalies_count: 0,
    high_risk_ips_count: 0
  });

  const [radarEntities, setRadarEntities] = useState<RadarEntity[]>([]);
  const [ipSummaries, setIpSummaries] = useState<any[]>([]);
  const [mitreTechniques, setMitreTechniques] = useState<MitreMappedTechnique[]>([]);
  const [selectedDrawerIP, setSelectedDrawerIP] = useState<string | null>(null);

  // RBAC Test State
  const [rbacTestResult, setRbacTestResult] = useState<{
    status: 'IDLE' | 'SUCCESS' | 'DENIED' | 'ERROR';
    message: string;
  }>({ status: 'IDLE', message: '' });
  const [isTestingRbac, setIsTestingRbac] = useState(false);

  const fetchDashboardData = async () => {
    if (!token) return;
    setIsHealthLoading(true);
    const authHeaders = { headers: { Authorization: `Bearer ${token}` } };

    try {
      const [healthRes, scoreRes, radarRes, ipRes, incRes] = await Promise.allSettled([
        authService.getHealth(),
        axios.get('/api/v1/ip-intelligence/security-score', authHeaders),
        axios.get('/api/v1/ip-intelligence/threat-radar', authHeaders),
        axios.get('/api/v1/ip-intelligence/summary', authHeaders),
        axios.get('/api/v1/incidents?limit=10', authHeaders),
      ]);

      if (healthRes.status === 'fulfilled') setHealthData(healthRes.value);
      if (scoreRes.status === 'fulfilled') setSecurityScoreData(scoreRes.value.data);
      if (radarRes.status === 'fulfilled') setRadarEntities(radarRes.value.data.entities || []);
      if (ipRes.status === 'fulfilled') setIpSummaries(ipRes.value.data || []);

      if (incRes.status === 'fulfilled') {
        const incidents = incRes.value.data.incidents || [];
        const techList: MitreMappedTechnique[] = [];
        incidents.forEach((inc: any) => {
          (inc.mitre_techniques || []).forEach((t: any) => {
            if (!techList.some(existing => existing.technique_id === t.technique_id)) {
              techList.push(t);
            }
          });
        });
        setMitreTechniques(techList);
      }
    } catch (err) {
      console.error('Failed to load dashboard metrics:', err);
    } finally {
      setIsHealthLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
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
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
            <span className="text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider">
              CYBER THREAT INTELLIGENCE COMMAND CENTER &bull; AUTONOMOUS PIPELINE ACTIVE
            </span>
          </div>
          <h2 className="text-lg font-bold text-gray-100 mt-1">
            Autonomous Cybersecurity Incident Investigation & Reconnaissance Platform
          </h2>
          <p className="text-xs text-gray-400 max-w-2xl mt-1 leading-relaxed">
            Integrated SIEM ingestion, UEBA profiling, Isolation Forest anomaly scoring, passive IP intelligence, 
            interactive threat radar, MITRE ATT&CK kill-chain mapping, and in-memory Digital Twin response simulation.
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

        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="text-[11px] font-mono text-gray-400 bg-gray-900/80 px-3 py-1.5 rounded-lg border border-gray-800">
            API: <strong className="text-blue-400">{healthData?.status.toUpperCase() || 'HEALTHY'}</strong> &bull; DB: <strong className="text-emerald-400">{healthData?.database || 'ONLINE'}</strong>
          </div>
          <button
            onClick={fetchDashboardData}
            disabled={isHealthLoading}
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-mono rounded-lg border border-gray-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isHealthLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Radar & Metrics</span>
          </button>
        </div>
      </div>

      {/* TOP: Security Score HUD & Key Indicators */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Security Score HUD (8 cols on lg) */}
        <div className="lg:col-span-8">
          <SecurityScoreHUD
            score={securityScoreData.security_health_score}
            healthStatus={securityScoreData.health_status}
            factors={securityScoreData.factors}
          />
        </div>

        {/* 4 Critical Operational Gauges (4 cols on lg) */}
        <div className="lg:col-span-4 grid grid-cols-2 gap-3">
          <div 
            onClick={() => navigate('/incidents')}
            className="bg-[#111827] border border-gray-800/80 rounded-xl p-3.5 shadow hover:border-amber-500/40 transition-colors cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-400 mb-1">
              <span className="text-[10px] font-mono">ACTIVE INCIDENTS</span>
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400 font-mono">
              {securityScoreData.active_incidents_count}
            </div>
            <div className="text-[10px] text-gray-500 font-mono mt-0.5 flex items-center gap-1">
              <span>View Queue</span> &rarr;
            </div>
          </div>

          <div 
            onClick={() => navigate('/incidents?severity=CRITICAL')}
            className="bg-[#111827] border border-gray-800/80 rounded-xl p-3.5 shadow hover:border-red-500/40 transition-colors cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-400 mb-1">
              <span className="text-[10px] font-mono">CRITICAL THREATS</span>
              <AlertOctagon className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400 font-mono">
              {securityScoreData.critical_incidents_count}
            </div>
            <div className="text-[10px] text-red-400/80 font-mono mt-0.5">SLA Escalation</div>
          </div>

          <div 
            onClick={() => navigate('/ip-intelligence')}
            className="bg-[#111827] border border-gray-800/80 rounded-xl p-3.5 shadow hover:border-purple-500/40 transition-colors cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-400 mb-1">
              <span className="text-[10px] font-mono">HIGH-RISK IPS</span>
              <Globe className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400 font-mono">
              {securityScoreData.high_risk_ips_count}
            </div>
            <div className="text-[10px] text-purple-400/80 font-mono mt-0.5">Recon Active</div>
          </div>

          <div 
            onClick={() => navigate('/ingestion-demo')}
            className="bg-[#111827] border border-gray-800/80 rounded-xl p-3.5 shadow hover:border-cyan-500/40 transition-colors cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-400 mb-1">
              <span className="text-[10px] font-mono">ML ANOMALIES</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-cyan-400 font-mono">
              {securityScoreData.total_anomalies_count}
            </div>
            <div className="text-[10px] text-cyan-400/80 font-mono mt-0.5">IsoForest Flagged</div>
          </div>
        </div>
      </div>

      {/* MIDDLE: Cyber Threat Radar & MITRE Visual Fingerprint */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7">
          <ThreatRadar
            entities={radarEntities}
            onSelectIP={(ip) => setSelectedDrawerIP(ip)}
            onSelectIncident={(incId) => navigate(`/incidents/${incId}`)}
          />
        </div>

        <div className="lg:col-span-5">
          <MitreFingerprint techniques={mitreTechniques} />
        </div>
      </div>

      {/* BOTTOM: IP Reconnaissance Quick Queue & Digital Twin Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Observed IP Intelligence Quick List (7 cols) */}
        <div className="lg:col-span-7 bg-[#111827] border border-gray-800 rounded-2xl p-5 shadow-xl space-y-3">
          <div className="flex items-center justify-between pb-3 border-b border-gray-800">
            <div>
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-200">
                  OBSERVED IP THREAT INTELLIGENCE &bull; RECON QUEUE
                </h3>
              </div>
              <p className="text-[11px] text-gray-400 mt-0.5">
                Click any IP address to launch the interactive passive intelligence drawer.
              </p>
            </div>

            <button
              onClick={() => navigate('/ip-intelligence')}
              className="flex items-center gap-1 text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              <span>Full IP Catalog</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-gray-800">
            {ipSummaries.slice(0, 5).map(ip => (
              <div
                key={ip.ip_address}
                onClick={() => setSelectedDrawerIP(ip.ip_address)}
                className="py-2.5 flex items-center justify-between hover:bg-gray-800/30 px-2 rounded-lg cursor-pointer transition-colors font-mono text-xs"
              >
                <div className="flex items-center gap-2.5">
                  <span className={`w-2 h-2 rounded-full ${
                    ip.ip_risk_score >= 70 ? 'bg-red-500' :
                    ip.ip_risk_score >= 40 ? 'bg-amber-500' : 'bg-blue-500'
                  }`} />
                  <div>
                    <span className="font-bold text-gray-100">{ip.ip_address}</span>
                    <span className="text-[10px] text-gray-500 ml-2">({ip.ip_type})</span>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-gray-400 text-[11px] hidden sm:inline">{ip.primary_location}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold ${
                    ip.threat_level === 'CRITICAL' ? 'bg-red-950 text-red-300 border-red-800' :
                    ip.threat_level === 'HIGH' ? 'bg-amber-950 text-amber-300 border-amber-800' :
                    'bg-blue-950 text-blue-300 border-blue-800'
                  }`}>
                    Risk: {ip.ip_risk_score.toFixed(0)}
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
                </div>
              </div>
            ))}

            {ipSummaries.length === 0 && (
              <div className="py-6 text-center text-xs font-mono text-gray-500">
                No IP telemetry recorded yet. Ingest events or run synthetic scenarios.
              </div>
            )}
          </div>
        </div>

        {/* Digital Twin & RBAC Enforcement Laboratory (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Digital Twin Sim Quick Card */}
          <div 
            onClick={() => navigate('/simulation')}
            className="bg-[#111827] border border-cyan-900/40 rounded-2xl p-4 shadow-xl hover:border-cyan-500/40 transition-colors cursor-pointer space-y-2"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-cyan-400 font-bold flex items-center gap-1.5">
                <Cpu className="w-4 h-4" /> DIGITAL TWIN SIMULATION CONSOLE
              </span>
              <span className="text-[9px] bg-cyan-950 text-cyan-300 px-1.5 py-0.5 rounded border border-cyan-800">
                SIMULATED ACTION
              </span>
            </div>
            <p className="text-xs text-gray-300">
              Calculate in-memory topological blast radius, stage <code className="text-cyan-400">SIMULATE_ISOLATE_DEVICE</code> or <code className="text-cyan-400">SIMULATE_BLOCK_IP</code>, and test zero-downtime rollbacks.
            </p>
            <div className="text-[11px] font-mono text-cyan-400 flex items-center gap-1 pt-1">
              <span>Launch In-Memory Topology Simulator</span> &rarr;
            </div>
          </div>

          {/* Interactive RBAC Security Verification Laboratory (Retained from base) */}
          <div className="bg-[#111827] border border-gray-800 rounded-2xl p-4 shadow-xl space-y-3">
            <div className="flex items-center justify-between border-b border-gray-800 pb-2">
              <span className="text-xs font-mono font-bold text-gray-200 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-blue-400" /> RBAC VERIFICATION LABORATORY
              </span>
              <span className="text-[10px] font-mono bg-gray-800 text-gray-300 px-2 py-0.5 rounded">
                Role: {primaryRole}
              </span>
            </div>

            <div className="bg-[#0B0F17] p-2.5 rounded-lg border border-gray-800 text-[11px] font-mono space-y-1">
              <div className="text-gray-400">
                <span className="text-blue-400 font-semibold">Endpoint:</span> GET /api/v1/auth/admin-only-action
              </div>
              <div className="text-gray-400">
                <span className="text-blue-400 font-semibold">Expected:</span>{' '}
                {isAdmin ? (
                  <span className="text-emerald-400">HTTP 200 OK (Security Admin)</span>
                ) : (
                  <span className="text-red-400">HTTP 403 FORBIDDEN (Denied for {primaryRole})</span>
                )}
              </div>
            </div>

            <button
              onClick={handleTestRbac}
              disabled={isTestingRbac}
              className="w-full flex items-center justify-center gap-2 px-3 py-1.5 bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 border border-blue-500/50 rounded-lg text-xs font-mono transition-colors"
            >
              {isTestingRbac ? 'Verifying RBAC...' : 'Execute RBAC Authorization Probe'}
            </button>

            {rbacTestResult.status !== 'IDLE' && (
              <div className={`p-2 rounded border text-[10px] font-mono ${
                rbacTestResult.status === 'SUCCESS' ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800' :
                rbacTestResult.status === 'DENIED' ? 'bg-amber-950/60 text-amber-300 border-amber-800' :
                'bg-red-950/60 text-red-300 border-red-800'
              }`}>
                {rbacTestResult.message}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Global IP Intelligence Drawer */}
      <IPIntelligenceDrawer
        ipAddress={selectedDrawerIP}
        onClose={() => setSelectedDrawerIP(null)}
      />
    </div>
  );
};
