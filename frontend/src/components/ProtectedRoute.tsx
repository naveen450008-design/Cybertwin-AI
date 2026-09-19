import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { UserRoleName } from '../types/auth';
import { ForbiddenPage } from '../pages/ForbiddenPage';

interface ProtectedRouteProps {
  requiredRole?: UserRoleName;
  allowedRoles?: UserRoleName[];
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  requiredRole,
  allowedRoles,
}) => {
  const { isAuthenticated, isLoading, hasRole, hasAnyRole } = useAuth();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#0B0F17] text-gray-400">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
          <span className="text-xs font-mono tracking-wider">VALIDATING SECURE SESSION...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && !hasRole(requiredRole)) {
    return <ForbiddenPage requiredRole={requiredRole} />;
  }

  if (allowedRoles && !hasAnyRole(allowedRoles)) {
    return <ForbiddenPage allowedRoles={allowedRoles} />;
  }

  return <Outlet />;
};
