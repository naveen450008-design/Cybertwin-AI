import React from 'react';
import { ShieldAlert, ArrowLeft, Lock } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { UserRoleName } from '../types/auth';

interface ForbiddenPageProps {
  requiredRole?: UserRoleName;
  allowedRoles?: UserRoleName[];
}

export const ForbiddenPage: React.FC<ForbiddenPageProps> = ({
  requiredRole,
  allowedRoles,
}) => {
  const { user } = useAuth();
  const userRoles = user?.roles.map((r) => r.name).join(', ') || 'None';

  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] px-4 text-center">
      <div className="p-4 bg-red-950/40 border border-red-800/60 rounded-2xl text-red-400 mb-4 shadow-xl">
        <ShieldAlert className="w-12 h-12 animate-pulse" />
      </div>

      <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-red-950/60 border border-red-800/80 text-red-400 text-xs font-mono font-medium mb-3">
        <Lock className="w-3.5 h-3.5" />
        HTTP 403 FORBIDDEN — RBAC POLICY ENFORCEMENT
      </div>

      <h2 className="text-xl font-bold text-gray-100 mb-2">
        Access Denied by Security Boundary
      </h2>

      <p className="text-sm text-gray-400 max-w-md mb-6 leading-relaxed">
        Your active security profile does not have authorization to access this operational capability.
      </p>

      <div className="bg-[#111827] border border-gray-800 rounded-lg p-4 max-w-md w-full text-left font-mono text-xs space-y-2 mb-6">
        <div className="flex justify-between border-b border-gray-800/80 pb-2">
          <span className="text-gray-500">Active User:</span>
          <span className="text-gray-200">{user?.username}</span>
        </div>
        <div className="flex justify-between border-b border-gray-800/80 pb-2">
          <span className="text-gray-500">Your Roles:</span>
          <span className="text-amber-400 font-semibold">{userRoles}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-gray-500">Required Role:</span>
          <span className="text-red-400 font-semibold">
            {requiredRole || allowedRoles?.join(' or ')}
          </span>
        </div>
      </div>

      <Link
        to="/"
        className="inline-flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded-lg border border-gray-700 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Return to SOC Dashboard
      </Link>
    </div>
  );
};
