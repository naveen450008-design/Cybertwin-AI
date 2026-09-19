import React, { useState, useEffect } from 'react';
import { Shield, Activity, LogOut, User as UserIcon } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const [backendStatus, setBackendStatus] = useState<'ONLINE' | 'OFFLINE' | 'CHECKING'>('CHECKING');

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const health = await authService.getHealth();
        if (health.status === 'healthy') {
          setBackendStatus('ONLINE');
        } else {
          setBackendStatus('ONLINE');
        }
      } catch {
        setBackendStatus('OFFLINE');
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const primaryRole = user?.roles[0]?.name || 'Viewer';

  const getRoleBadgeStyle = (role: string) => {
    switch (role) {
      case 'Security Admin':
        return 'bg-red-950/80 text-red-400 border-red-800/80';
      case 'Security Analyst':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/80';
      case 'Incident Responder':
        return 'bg-blue-950/80 text-blue-400 border-blue-800/80';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  return (
    <header className="bg-[#111827] border-b border-gray-800/80 px-4 lg:px-6 py-3 flex items-center justify-between shadow-md">
      {/* Brand & Mission Classification */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-blue-950/50 border border-blue-800/60 rounded-lg text-blue-400 shadow-inner">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold text-gray-100 tracking-wide">
              CYBER AUTONOMOUS SOC
            </h1>
            <span className="text-[10px] bg-gray-800 text-gray-400 font-mono px-1.5 py-0.5 rounded border border-gray-700">
              PHASE 1 FOUNDATION
            </span>
          </div>
          <p className="text-xs text-gray-400 hidden sm:block">
            Incident Investigation & Safe Simulation Framework
          </p>
        </div>
      </div>

      {/* Backend Health Status & User Profile */}
      <div className="flex items-center gap-4">
        {/* Backend Live Telemetry Status */}
        <div className="flex items-center gap-2 bg-[#0B0F17] px-2.5 py-1 rounded-md border border-gray-800 text-xs font-mono">
          <Activity className={`w-3.5 h-3.5 ${backendStatus === 'ONLINE' ? 'text-emerald-400 animate-pulse' : 'text-red-400'}`} />
          <span className="text-gray-400 hidden md:inline">API ENGINE:</span>
          <span className={backendStatus === 'ONLINE' ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
            {backendStatus}
          </span>
        </div>

        {/* User Role Badge & Actions */}
        {user && (
          <div className="flex items-center gap-3 pl-2 border-l border-gray-800">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-semibold text-gray-200 flex items-center justify-end gap-1">
                <UserIcon className="w-3 h-3 text-gray-400" />
                {user.username}
              </div>
              <div className="mt-0.5">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-medium ${getRoleBadgeStyle(primaryRole)}`}>
                  {primaryRole}
                </span>
              </div>
            </div>

            <button
              onClick={logout}
              title="Sign out of SOC console"
              className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
