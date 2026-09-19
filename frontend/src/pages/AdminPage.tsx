import React, { useState } from 'react';
import { Sliders, ShieldCheck, Database, Key, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';

export const AdminPage: React.FC = () => {
  const { user } = useAuth();
  const [testOutput, setTestOutput] = useState<string | null>(null);

  const runAdminVerification = async () => {
    try {
      const res = await authService.testAdminAction();
      setTestOutput(res.message);
    } catch (err: any) {
      setTestOutput(`Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Admin Title Banner */}
      <div className="bg-[#111827] border border-red-950/80 rounded-xl p-5 shadow-lg flex items-center justify-between">
        <div>
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-red-950/80 border border-red-800 text-red-400 font-mono text-xs font-semibold mb-2">
            SECURITY ADMIN PRIVILEGED ZONE
          </div>
          <h2 className="text-lg font-bold text-gray-100">
            System Administration & Governance
          </h2>
          <p className="text-xs text-gray-400 mt-1">
            Privileged administrative operations, role configurations, and system-wide controls.
          </p>
        </div>

        <div className="p-3 bg-red-950/40 border border-red-800/60 rounded-xl text-red-400">
          <Sliders className="w-6 h-6" />
        </div>
      </div>

      {/* Admin Information Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 space-y-2">
          <div className="text-gray-400 font-mono flex items-center gap-2">
            <Key className="w-4 h-4 text-amber-400" />
            ADMINISTRATIVE IDENTITY
          </div>
          <div className="text-sm font-bold text-gray-200 font-mono">
            {user?.username}
          </div>
          <p className="text-[11px] text-gray-500 font-mono">
            ID: {user?.id}
          </p>
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 space-y-2">
          <div className="text-gray-400 font-mono flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            AUTHENTICATION SCHEME
          </div>
          <div className="text-sm font-bold text-gray-200 font-mono">
            JWT BEARER HS256
          </div>
          <p className="text-[11px] text-gray-500 font-mono">
            bcrypt Work Factor: 12
          </p>
        </div>

        <div className="bg-[#111827] border border-gray-800 rounded-xl p-4 space-y-2">
          <div className="text-gray-400 font-mono flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-400" />
            GOVERNANCE STATE
          </div>
          <div className="text-sm font-bold text-emerald-400 font-mono">
            MIGRATIONS CURRENT (001)
          </div>
          <p className="text-[11px] text-gray-500 font-mono">
            Alembic Head Revision
          </p>
        </div>
      </div>

      {/* Admin Action Verification */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
        <h3 className="text-sm font-bold text-gray-200 font-mono">
          Privileged Action Execution Test
        </h3>
        <p className="text-xs text-gray-400">
          This test verifies that the authenticated user possesses the Security Admin role and can successfully execute endpoints restricted to administrators.
        </p>

        <button
          onClick={runAdminVerification}
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded-lg font-mono tracking-wider transition-colors shadow-md"
        >
          EXECUTE ADMIN PRIVILEGED PROBE
        </button>

        {testOutput && (
          <div className="p-3 bg-emerald-950/60 border border-emerald-800/80 rounded-lg text-xs font-mono text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{testOutput}</span>
          </div>
        )}
      </div>
    </div>
  );
};
