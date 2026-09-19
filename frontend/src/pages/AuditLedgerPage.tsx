import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  ShieldCheck, 
  AlertOctagon, 
  Download, 
  RefreshCw, 
  Lock, 
  Hash, 
  ChevronRight, 
  ChevronDown, 
  Copy, 
  Check, 
  Layers
} from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';

interface AuditRecord {
  ledger_index: number;
  audit_id: string;
  timestamp: string;
  actor_username: string;
  actor_role: string;
  action_taken: string;
  target_entity_type: string;
  target_entity_id: string;
  old_state_json: any;
  new_state_json: any;
  session_metadata: any;
  previous_hash: string;
  current_hash: string;
}

interface VerificationReport {
  status: string;
  is_valid: boolean;
  total_records: number;
  corrupted_records_count: number;
  genesis_hash: string;
  head_hash?: string;
  verification_timestamp: string;
  corrupted_entries: any[];
}

export const AuditLedgerPage: React.FC = () => {
  const { hasRole, user } = useAuth();
  const isAuthorized = hasRole('Security Analyst') || hasRole('Security Admin');

  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<VerificationReport | null>(null);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    if (isAuthorized) {
      fetchAuditLogs();
    }
  }, [isAuthorized]);

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const res = await api.get('/audit/logs?limit=50&offset=0');
      setRecords(res.data.records || []);
      setTotal(res.data.total || 0);
    } catch (err: any) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyLedger = async () => {
    setVerifying(true);
    try {
      const res = await api.get('/audit/verify');
      setVerificationResult(res.data);
    } catch (err: any) {
      console.error('Audit verification error:', err);
    } finally {
      setVerifying(false);
    }
  };

  const handleExportJSON = async () => {
    try {
      const res = await api.get('/audit/export');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-ledger-export-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Export failed:', err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  if (!isAuthorized) {
    return (
      <div className="bg-[#111827] border border-rose-900/50 rounded-xl p-8 text-center space-y-4 max-w-xl mx-auto mt-12">
        <div className="w-12 h-12 bg-rose-950/60 text-rose-400 rounded-full flex items-center justify-center mx-auto border border-rose-800/60">
          <Lock className="w-6 h-6" />
        </div>
        <h2 className="text-lg font-bold text-white">Cryptographic Audit Ledger Restricted</h2>
        <p className="text-xs text-gray-400 leading-relaxed">
          Access to the append-only cryptographic ledger is strictly restricted to the 
          <span className="text-blue-400 font-mono"> Security Analyst</span> and 
          <span className="text-purple-400 font-mono"> Security Admin</span> roles under corporate governance policy.
        </p>
        <div className="text-[11px] font-mono text-gray-500 bg-gray-900 p-2.5 rounded">
          Current Role: <span className="text-gray-300">{user?.roles[0]?.name || 'Viewer'}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-purple-950/40 via-gray-900 to-blue-950/40 border border-purple-500/30 rounded-xl p-5 shadow-lg backdrop-blur-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[10px] font-mono font-bold px-2 py-0.5 rounded flex items-center gap-1">
                <Hash className="w-3 h-3" /> SHA-256 (FIPS 180-4)
              </span>
              <span className="bg-gray-800 text-gray-400 text-[10px] font-mono px-2 py-0.5 rounded">
                APPEND-ONLY IMMUTABLE
              </span>
            </div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <FileText className="w-6 h-6 text-purple-400" />
              Cryptographic Tamper-Evident Audit Ledger
            </h1>
            <p className="text-xs text-gray-400 mt-1 max-w-3xl">
              Sequential cryptographic hash chain guaranteeing mathematical integrity across all SOC investigations, 
              response approvals, and simulation events. Verified via <code className="text-purple-300">Hash_n = SHA256(Hash_n-1 || Payload_n)</code>.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleVerifyLedger}
              disabled={verifying}
              className="flex items-center gap-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold px-3 py-2 rounded-lg transition shadow disabled:opacity-50"
            >
              <ShieldCheck className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
              {verifying ? 'Verifying Hashes...' : 'Verify Ledger Integrity'}
            </button>
            <button
              onClick={handleExportJSON}
              className="flex items-center gap-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 text-xs px-3 py-2 rounded-lg transition"
            >
              <Download className="w-3.5 h-3.5" />
              Export JSON
            </button>
            <button
              onClick={fetchAuditLogs}
              className="p-2 bg-gray-800 hover:bg-gray-700 text-gray-400 rounded-lg border border-gray-700 transition"
              title="Refresh ledger"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Verification Result Banner */}
      {verificationResult && (
        <div className={`p-4 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-lg ${
          verificationResult.is_valid
            ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
            : 'bg-rose-950/40 border-rose-500/40 text-rose-200'
        }`}>
          <div className="flex items-start gap-3">
            {verificationResult.is_valid ? (
              <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertOctagon className="w-6 h-6 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div>
              <h3 className="text-sm font-bold text-white">
                {verificationResult.is_valid ? 'Cryptographic Hash Continuity Verified' : 'INTEGRITY VIOLATION DETECTED'}
              </h3>
              <p className="text-xs text-gray-300 mt-0.5">
                {verificationResult.is_valid
                  ? `All ${verificationResult.total_records} audit entries successfully validated from Genesis Hash. Sequential SHA-256 links intact.`
                  : `Detected ${verificationResult.corrupted_records_count} corrupted or manipulated ledger entries.`}
              </p>
              <div className="flex flex-wrap gap-3 mt-2 text-[10px] font-mono text-gray-400">
                <span>Total Records: <strong className="text-white">{verificationResult.total_records}</strong></span>
                <span>Corrupted: <strong className={verificationResult.corrupted_records_count > 0 ? 'text-rose-400' : 'text-emerald-400'}>{verificationResult.corrupted_records_count}</strong></span>
                <span>Verified At: <span className="text-gray-300">{verificationResult.verification_timestamp}</span></span>
              </div>
            </div>
          </div>

          <div className="text-right shrink-0">
            <span className="text-[10px] font-mono text-gray-400 block mb-1">Head Block Hash:</span>
            <div className="font-mono text-[11px] bg-black/40 px-2 py-1 rounded border border-gray-700 text-purple-300">
              {verificationResult.head_hash?.slice(0, 16)}...{verificationResult.head_hash?.slice(-8)}
            </div>
          </div>
        </div>
      )}

      {/* Genesis Block Marker Card */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 flex items-center justify-between shadow">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-purple-950/60 border border-purple-800/60 flex items-center justify-center text-purple-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Genesis Block Initializer</div>
            <div className="font-mono text-xs text-gray-300">
              0000000000000000000000000000000000000000000000000000000000000000
            </div>
          </div>
        </div>
        <div className="text-[11px] font-mono text-gray-500">
          Immutable Anchor
        </div>
      </div>

      {/* Ledger Table */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-gray-800 flex items-center justify-between bg-gray-900/60">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-gray-200">Cryptographic Chain Log</h2>
            <span className="text-[10px] bg-gray-800 text-gray-400 font-mono px-2 py-0.5 rounded">
              {total} Total Committed Blocks
            </span>
          </div>
          <div className="text-[11px] text-gray-500 font-mono">
            Chronological Descending
          </div>
        </div>

        {records.length === 0 ? (
          <div className="text-center py-12 text-xs text-gray-500">
            No audit records found in the ledger yet. Actions executed in the Digital Twin will appear here.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-900/90 text-[10px] font-mono uppercase text-gray-400 border-b border-gray-800">
                <tr>
                  <th className="py-2.5 px-3">Idx</th>
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Actor & Role</th>
                  <th className="py-2.5 px-3">Action Taken</th>
                  <th className="py-2.5 px-3">Target Entity</th>
                  <th className="py-2.5 px-3">Previous SHA-256</th>
                  <th className="py-2.5 px-3">Current Block SHA-256</th>
                  <th className="py-2.5 px-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/80 font-mono text-[11px]">
                {records.map((r) => {
                  const isExpanded = expandedIndex === r.ledger_index;
                  return (
                    <React.Fragment key={r.audit_id}>
                      <tr className="hover:bg-gray-900/50 transition">
                        <td className="py-2.5 px-3 text-purple-400 font-bold">#{r.ledger_index}</td>
                        <td className="py-2.5 px-3 text-gray-400">{new Date(r.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</td>
                        <td className="py-2.5 px-3">
                          <span className="text-white font-semibold">{r.actor_username}</span>
                          <span className="text-[9px] text-blue-400 ml-1">({r.actor_role})</span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="bg-gray-800 text-gray-200 px-1.5 py-0.5 rounded text-[10px]">
                            {r.action_taken}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="text-amber-400">{r.target_entity_id}</span>
                          <span className="text-[9px] text-gray-500 ml-1">[{r.target_entity_type}]</span>
                        </td>
                        <td className="py-2.5 px-3 text-gray-500 font-mono text-[10px]">
                          <span title={r.previous_hash}>
                            {r.previous_hash.slice(0, 8)}...{r.previous_hash.slice(-6)}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[10px]">
                          <div className="flex items-center gap-1 text-purple-300">
                            <span title={r.current_hash}>
                              {r.current_hash.slice(0, 8)}...{r.current_hash.slice(-6)}
                            </span>
                            <button
                              onClick={() => copyToClipboard(r.current_hash)}
                              className="text-gray-500 hover:text-gray-300 p-0.5"
                              title="Copy SHA-256 Hash"
                            >
                              {copiedHash === r.current_hash ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() => setExpandedIndex(isExpanded ? null : r.ledger_index)}
                            className="text-gray-400 hover:text-white transition inline-flex items-center gap-1"
                          >
                            <span>Payload</span>
                            {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Payload Inspection Row */}
                      {isExpanded && (
                        <tr className="bg-gray-950/70 border-b border-gray-800">
                          <td colSpan={8} className="p-4 space-y-3">
                            <div className="text-[10px] font-mono text-purple-400 uppercase tracking-wider">
                              Block #{r.ledger_index} Deterministic Canonical Payload Inspection
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="bg-gray-900 border border-gray-800 rounded p-3">
                                <span className="text-[10px] font-mono text-gray-400 block mb-1">Old State (JSON)</span>
                                <pre className="text-[10px] text-gray-300 font-mono overflow-x-auto">
                                  {JSON.stringify(r.old_state_json, null, 2)}
                                </pre>
                              </div>

                              <div className="bg-gray-900 border border-gray-800 rounded p-3">
                                <span className="text-[10px] font-mono text-emerald-400 block mb-1">New State (JSON)</span>
                                <pre className="text-[10px] text-gray-300 font-mono overflow-x-auto">
                                  {JSON.stringify(r.new_state_json, null, 2)}
                                </pre>
                              </div>
                            </div>

                            <div className="bg-gray-900/60 border border-gray-800/80 rounded p-2 text-[10px] text-gray-400 font-mono">
                              <div><strong>Audit ID:</strong> {r.audit_id}</div>
                              <div className="mt-0.5"><strong>Full Previous Hash:</strong> {r.previous_hash}</div>
                              <div className="mt-0.5"><strong>Full Current Hash:</strong> {r.current_hash}</div>
                              {r.session_metadata && Object.keys(r.session_metadata).length > 0 && (
                                <div className="mt-0.5"><strong>Session Metadata:</strong> {JSON.stringify(r.session_metadata)}</div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
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

export default AuditLedgerPage;
