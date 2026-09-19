import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Cpu, 
  FileText, 
  Sliders, 
  Database,
  Lock
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Sidebar: React.FC = () => {
  const { hasRole, user } = useAuth();
  const isAdmin = hasRole('Security Admin');

  const navItemClass = ({ isActive }: { isActive: boolean }) => `
    flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all
    ${isActive 
      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30' 
      : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
    }
  `;

  return (
    <aside className="w-64 bg-[#111827] border-r border-gray-800/80 p-4 flex flex-col justify-between shrink-0 shadow-lg">
      <div className="space-y-6">
        {/* Core Operational Modules */}
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider px-3 mb-2">
            Operations & Triage
          </div>
          <nav className="space-y-1">
            <NavLink to="/" end className={navItemClass}>
              <LayoutDashboard className="w-4 h-4 text-blue-400" />
              <span>SOC Dashboard</span>
            </NavLink>

            <NavLink to="/incidents" className={navItemClass}>
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <div className="flex items-center justify-between w-full">
                <span>Incidents & Timeline</span>
                <span className="text-[9px] bg-amber-950 text-amber-400 font-mono px-1 rounded border border-amber-800/60">LIVE</span>
              </div>
            </NavLink>

            <NavLink to="/simulation" className={navItemClass}>
              <Cpu className="w-4 h-4 text-emerald-400" />
              <div className="flex items-center justify-between w-full">
                <span>Digital Twin Sim</span>
                <span className="text-[9px] bg-emerald-950 text-emerald-400 font-mono px-1 rounded border border-emerald-800/60">SIM</span>
              </div>
            </NavLink>
          </nav>
        </div>

        {/* Forensic & Governance Modules */}
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider px-3 mb-2">
            Governance & Audit
          </div>
          <nav className="space-y-1">
            <NavLink to="/audit" className={navItemClass}>
              <FileText className="w-4 h-4 text-purple-400" />
              <div className="flex items-center justify-between w-full">
                <span>Audit Ledger</span>
                <span className="text-[9px] bg-purple-950 text-purple-400 font-mono px-1 rounded border border-purple-800/60">CHAIN</span>
              </div>
            </NavLink>

            <NavLink to="/ingestion-demo" className={navItemClass}>
              <Database className="w-4 h-4 text-cyan-400" />
              <div className="flex items-center justify-between w-full">
                <span>Synthetic Ingestion</span>
                <span className="text-[9px] bg-cyan-950 text-cyan-400 font-mono px-1 rounded border border-cyan-800/60">INGEST</span>
              </div>
            </NavLink>
          </nav>
        </div>

        {/* Administration Section */}
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider px-3 mb-2 flex items-center justify-between">
            <span>Administration</span>
            {isAdmin ? (
              <span className="text-[9px] text-emerald-400 font-mono">UNLOCKED</span>
            ) : (
              <span className="text-[9px] text-gray-500 font-mono flex items-center gap-0.5">
                <Lock className="w-2.5 h-2.5" /> GATED
              </span>
            )}
          </div>
          <nav className="space-y-1">
            <NavLink 
              to="/admin" 
              className={({ isActive }) => `
                flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all
                ${!isAdmin 
                  ? 'opacity-40 cursor-not-allowed text-gray-500 hover:bg-transparent' 
                  : isActive 
                    ? 'bg-red-950/40 text-red-400 border border-red-800/40' 
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
                }
              `}
            >
              <Sliders className="w-4 h-4 text-red-400" />
              <div className="flex items-center justify-between w-full">
                <span>Admin Governance</span>
                <span className="text-[9px] bg-red-950/80 text-red-400 font-mono px-1.5 py-0.5 rounded border border-red-900/60">
                  ADMIN
                </span>
              </div>
            </NavLink>
          </nav>
        </div>
      </div>

      {/* Identity & Session Metadata Footer */}
      <div className="pt-4 border-t border-gray-800 text-[11px] font-mono text-gray-500">
        <div className="flex justify-between">
          <span>Active Identity:</span>
          <span className="text-gray-400 font-semibold">{user?.username}</span>
        </div>
        <div className="flex justify-between mt-1">
          <span>Role Scope:</span>
          <span className="text-blue-400 font-semibold">{user?.roles[0]?.name}</span>
        </div>
      </div>
    </aside>
  );
};
