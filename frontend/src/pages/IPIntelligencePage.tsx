import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Globe, 
  Search, 
  RefreshCw, 
  ChevronRight, 
  Network, 
  AlertTriangle, 
  CheckCircle2, 
  MapPin
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { IPIntelligenceDrawer } from '../components/IPIntelligenceDrawer';

interface IPSummaryItem {
  ip_address: string;
  ip_type: string;
  is_internal: boolean;
  version: number;
  total_events: number;
  total_anomalies: number;
  total_incidents: number;
  ip_risk_score: number;
  threat_level: string;
  primary_location?: string;
  last_seen?: string;
}

export const IPIntelligencePage: React.FC = () => {
  const { token } = useAuth();
  const [ips, setIps] = useState<IPSummaryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<'ALL' | 'EXTERNAL' | 'INTERNAL' | 'HIGH_RISK'>('ALL');
  const [selectedIP, setSelectedIP] = useState<string | null>(null);

  const fetchIPs = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await axios.get('/api/v1/ip-intelligence/summary', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setIps(res.data || []);
    } catch (err) {
      console.error('Failed to load IP summaries:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIPs();
  }, [token]);

  const filteredIPs = ips.filter(ip => {
    const matchesSearch = ip.ip_address.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ip.primary_location && ip.primary_location.toLowerCase().includes(searchQuery.toLowerCase()));

    if (!matchesSearch) return false;

    if (typeFilter === 'EXTERNAL') return !ip.is_internal;
    if (typeFilter === 'INTERNAL') return ip.is_internal;
    if (typeFilter === 'HIGH_RISK') return ip.ip_risk_score >= 50.0;
    return true;
  });

  const highRiskCount = ips.filter(i => i.ip_risk_score >= 50.0).length;
  const externalCount = ips.filter(i => !i.is_internal).length;
  const internalCount = ips.filter(i => i.is_internal).length;

  const getThreatBadge = (lvl: string) => {
    switch (lvl) {
      case 'CRITICAL': return 'bg-red-950 text-red-300 border-red-800';
      case 'HIGH': return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'MEDIUM': return 'bg-yellow-950 text-yellow-300 border-yellow-800';
      default: return 'bg-blue-950 text-blue-300 border-blue-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-ping" />
            <span className="text-xs font-mono text-blue-400 font-bold uppercase tracking-wider">
              DEFENSIVE PASSIVE INTELLIGENCE &bull; RECONNAISSANCE ENGINE
            </span>
          </div>
          <h2 className="text-lg font-bold text-gray-100 mt-1 flex items-center gap-2">
            <Globe className="w-5 h-5 text-blue-400" />
            IP Threat Intelligence Command Center
          </h2>
          <p className="text-xs text-gray-400 max-w-2xl mt-1 leading-relaxed">
            Passive RFC classification, internal evidence-derived IP risk profiles, entity relationship graphs, 
            and reconstructed attack paths without active scanning.
          </p>
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] font-mono">
            <span className="px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-800">
              INTERNAL SECURITY EVIDENCE
            </span>
            <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
              PASSIVE / NO PORT SCANNING
            </span>
            <span className="px-2 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-800">
              DERIVED IP RISK PROFILES
            </span>
          </div>
        </div>

        <button
          onClick={fetchIPs}
          disabled={loading}
          className="self-start md:self-auto flex items-center gap-2 px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-mono rounded-lg border border-gray-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">TRACKED IP ADDRESSES</span>
            <Globe className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-gray-100 font-mono">{ips.length}</div>
          <div className="text-[11px] text-gray-500 font-mono mt-1">Observed in ingested security logs</div>
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">HIGH-RISK EXTERNAL IPS</span>
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 font-mono">{highRiskCount}</div>
          <div className="text-[11px] text-red-500/80 font-mono mt-1">Score &ge; 50 (Critical / High threat)</div>
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">EXTERNAL WAN TARGETS</span>
            <Network className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400 font-mono">{externalCount}</div>
          <div className="text-[11px] text-purple-400/70 font-mono mt-1">Public & synthetic testbed WANs</div>
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-xs font-mono">INTERNAL SUBNET HOSTS</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">{internalCount}</div>
          <div className="text-[11px] text-emerald-500/80 font-mono mt-1">RFC 1918 Private Enterprise LAN</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 shadow-lg flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search IP, subnet, or location..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#0B0F17] border border-gray-800 rounded-lg text-xs font-mono text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex flex-wrap gap-2 w-full sm:w-auto text-xs font-mono">
          {[
            { id: 'ALL', label: 'All Addresses' },
            { id: 'EXTERNAL', label: 'External WAN' },
            { id: 'INTERNAL', label: 'Internal RFC1918' },
            { id: 'HIGH_RISK', label: 'High Risk' }
          ].map(btn => (
            <button
              key={btn.id}
              onClick={() => setTypeFilter(btn.id as any)}
              className={`px-3 py-1.5 rounded-lg border transition-all ${
                typeFilter === btn.id
                  ? 'bg-blue-600/30 text-blue-300 border-blue-500/50 font-bold'
                  : 'bg-gray-800/60 text-gray-400 hover:text-gray-200 border-gray-700/50'
              }`}
            >
              {btn.label}
            </button>
          ))}
        </div>
      </div>

      {/* IP Catalog Table */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-[#0B0F17] text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Observed Location</th>
                <th className="py-3 px-4 text-center">Events</th>
                <th className="py-3 px-4 text-center">Anomalies</th>
                <th className="py-3 px-4 text-center">Incidents</th>
                <th className="py-3 px-4">IP Risk Profile</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-gray-500">
                    Loading observed IP telemetry...
                  </td>
                </tr>
              ) : filteredIPs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-gray-500">
                    No IP addresses found matching filter criteria. Ingest telemetry or run synthetic demos.
                  </td>
                </tr>
              ) : (
                filteredIPs.map(ip => (
                  <tr 
                    key={ip.ip_address}
                    className="hover:bg-gray-800/40 transition-colors cursor-pointer"
                    onClick={() => setSelectedIP(ip.ip_address)}
                  >
                    <td className="py-3.5 px-4 font-bold text-gray-100 flex items-center gap-2">
                      <Globe className="w-3.5 h-3.5 text-blue-400" />
                      <span>{ip.ip_address}</span>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${
                        ip.is_internal 
                          ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800' 
                          : 'bg-purple-950/70 text-purple-300 border-purple-800'
                      }`}>
                        {ip.ip_type} ({ip.is_internal ? 'Internal' : 'External'})
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-gray-400">
                      <div className="flex items-center gap-1.5 truncate max-w-xs">
                        <MapPin className="w-3 h-3 text-gray-500 shrink-0" />
                        <span className="truncate">{ip.primary_location || 'Data unavailable'}</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-center text-gray-300">{ip.total_events}</td>
                    <td className="py-3.5 px-4 text-center">
                      <span className={ip.total_anomalies > 0 ? 'text-amber-400 font-bold' : 'text-gray-500'}>
                        {ip.total_anomalies}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <span className={ip.total_incidents > 0 ? 'text-purple-400 font-bold' : 'text-gray-500'}>
                        {ip.total_incidents}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              ip.ip_risk_score >= 75 ? 'bg-red-500' :
                              ip.ip_risk_score >= 50 ? 'bg-amber-500' :
                              ip.ip_risk_score >= 25 ? 'bg-yellow-500' : 'bg-blue-500'
                            }`}
                            style={{ width: `${ip.ip_risk_score}%` }}
                          />
                        </div>
                        <span className={`text-[10px] px-1.5 py-0.2 rounded border font-semibold ${getThreatBadge(ip.threat_level)}`}>
                          {ip.ip_risk_score.toFixed(0)} ({ip.threat_level})
                        </span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIP(ip.ip_address);
                        }}
                        className="px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 border border-blue-500/40 text-[11px] transition-colors inline-flex items-center gap-1"
                      >
                        <span>Recon Drawer</span>
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-out Intelligence Drawer */}
      <IPIntelligenceDrawer
        ipAddress={selectedIP}
        onClose={() => setSelectedIP(null)}
      />
    </div>
  );
};
