import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, KeyRound, User as UserIcon, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [requestedRole, setRequestedRole] = useState('Viewer');

  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);
    setIsLoading(true);

    try {
      if (isRegisterMode) {
        await authService.register(username, fullName, password, requestedRole);
        setSuccessMsg(`Account created for ${username}. Authenticating...`);
        // Auto-login after successful registration
        await login(username, password);
        navigate('/');
      } else {
        await login(username, password);
        navigate('/');
      }
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.message || 'Authentication failed';
      setErrorMsg(detail);
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickFillAdmin = () => {
    setIsRegisterMode(false);
    setUsername('admin');
    setPassword('AdminSecurePass123!');
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] flex flex-col justify-center items-center px-4 relative overflow-hidden">
      {/* Background Decorative Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-blue-900/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main Authentication Card */}
      <div className="w-full max-w-md bg-[#111827] border border-gray-800/90 rounded-xl p-6 sm:p-8 shadow-2xl relative z-10">
        {/* Header Branding */}
        <div className="text-center mb-6">
          <div className="inline-flex p-3 bg-blue-950/60 border border-blue-800/80 rounded-xl text-blue-400 mb-3 shadow-inner">
            <Shield className="w-8 h-8" />
          </div>
          <h2 className="text-lg font-bold text-gray-100 tracking-wide">
            CYBER SOC CONSOLE
          </h2>
          <p className="text-xs text-gray-400 mt-1">
            Autonomous Incident Investigation & Safe Simulation Framework
          </p>
        </div>

        {/* Error / Success Notifications */}
        {errorMsg && (
          <div className="mb-4 p-3 bg-red-950/60 border border-red-800/80 rounded-lg flex items-start gap-2 text-xs text-red-300">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div className="mb-4 p-3 bg-emerald-950/60 border border-emerald-800/80 rounded-lg flex items-start gap-2 text-xs text-emerald-300">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Form Controls */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegisterMode && (
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1">
                FULL OPERATOR NAME
              </label>
              <div className="relative">
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Sarah Connor"
                  className="w-full bg-[#0B0F17] border border-gray-800 focus:border-blue-500 rounded-lg px-3 py-2 text-xs text-gray-200 outline-none transition-colors"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono text-gray-400 mb-1">
              OPERATOR IDENTIFIER (USERNAME)
            </label>
            <div className="relative">
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="w-full bg-[#0B0F17] border border-gray-800 focus:border-blue-500 rounded-lg px-3 py-2 text-xs text-gray-200 outline-none transition-colors font-mono"
              />
              <UserIcon className="w-4 h-4 text-gray-600 absolute right-3 top-2.5" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-gray-400 mb-1">
              SECURITY CREDENTIAL (PASSWORD)
            </label>
            <div className="relative">
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="w-full bg-[#0B0F17] border border-gray-800 focus:border-blue-500 rounded-lg px-3 py-2 text-xs text-gray-200 outline-none transition-colors font-mono"
              />
              <KeyRound className="w-4 h-4 text-gray-600 absolute right-3 top-2.5" />
            </div>
          </div>

          {isRegisterMode && (
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1">
                ASSIGNED RBAC ROLE TIER
              </label>
              <select
                value={requestedRole}
                onChange={(e) => setRequestedRole(e.target.value)}
                className="w-full bg-[#0B0F17] border border-gray-800 focus:border-blue-500 rounded-lg px-3 py-2 text-xs text-gray-200 outline-none transition-colors font-mono"
              >
                <option value="Viewer">Viewer (Read-only masked PII)</option>
                <option value="Incident Responder">Incident Responder (Triage & Low-Impact Sim)</option>
                <option value="Security Analyst">Security Analyst (Full Investigation & Approval)</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-xs font-semibold rounded-lg tracking-wider transition-colors shadow-lg shadow-blue-900/30 flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
            ) : isRegisterMode ? (
              'REGISTER OPERATOR ACCOUNT'
            ) : (
              'AUTHENTICATE SESSION'
            )}
          </button>
        </form>

        {/* Quick-Fill Helpers for Testing */}
        <div className="mt-6 pt-4 border-t border-gray-800/80">
          <div className="text-[10px] font-mono text-gray-500 mb-2 uppercase text-center">
            Development Sandbox Credentials
          </div>
          <button
            type="button"
            onClick={handleQuickFillAdmin}
            className="w-full py-1.5 px-2 bg-gray-800/50 hover:bg-gray-800 text-gray-300 text-[11px] font-mono rounded border border-gray-700/60 transition-colors flex items-center justify-between"
          >
            <span>Bootstrap Admin:</span>
            <span className="text-emerald-400 font-semibold">admin / AdminSecurePass123!</span>
          </button>
        </div>

        {/* Toggle Register / Login */}
        <div className="mt-4 text-center">
          <button
            type="button"
            onClick={() => {
              setIsRegisterMode(!isRegisterMode);
              setErrorMsg(null);
            }}
            className="text-xs text-blue-400 hover:underline"
          >
            {isRegisterMode
              ? 'Already registered? Return to Login'
              : 'Need a test identity? Register Operator Profile'}
          </button>
        </div>
      </div>

      {/* Safety Guardrail Footnote */}
      <p className="mt-6 text-[11px] text-gray-500 font-mono text-center max-w-sm">
        ACADEMIC PROTOTYPE &bull; SAFE SIMULATION DOMAIN &bull; NO HARDCODED SECRETS
      </p>
    </div>
  );
};
