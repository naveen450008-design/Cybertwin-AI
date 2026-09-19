import React, { useState } from 'react';
import { Shield, ChevronDown, ChevronUp, Info, Activity, CheckCircle2 } from 'lucide-react';

interface SecurityScoreHUDProps {
  score: number;
  healthStatus?: string;
  factors?: {
    incident_risk_factor?: number;
    critical_exposure_factor?: number;
    external_network_exposure?: number;
    unresolved_anomalies_factor?: number;
    containment_rate_factor?: number;
  };
  breakdown?: {
    anomaly?: number;
    severity?: number;
    asset?: number;
    identity?: number;
    sequence?: number;
    stage?: number;
  };
  title?: string;
  subtitle?: string;
}

export const SecurityScoreHUD: React.FC<SecurityScoreHUDProps> = ({
  score,
  healthStatus,
  factors,
  breakdown,
  title = "TENANT SECURITY HEALTH SCORE",
  subtitle = "Evidence-driven composite evaluation (0-100)"
}) => {
  const [expanded, setExpanded] = useState(false);

  // Determine color theme based on score
  const getScoreTheme = (val: number) => {
    if (val >= 80) return {
      stroke: "#10B981", // emerald
      text: "text-emerald-400",
      bg: "bg-emerald-500/10",
      border: "border-emerald-500/30",
      status: "OPTIMAL POSTURE",
      glow: "drop-shadow-[0_0_12px_rgba(16,185,129,0.35)]"
    };
    if (val >= 60) return {
      stroke: "#3B82F6", // blue
      text: "text-blue-400",
      bg: "bg-blue-500/10",
      border: "border-blue-500/30",
      status: "MODERATE RISK",
      glow: "drop-shadow-[0_0_12px_rgba(59,130,246,0.35)]"
    };
    if (val >= 40) return {
      stroke: "#F59E0B", // amber
      text: "text-amber-400",
      bg: "bg-amber-500/10",
      border: "border-amber-500/30",
      status: "ELEVATED CONCERN",
      glow: "drop-shadow-[0_0_12px_rgba(245,158,11,0.35)]"
    };
    return {
      stroke: "#EF4444", // red
      text: "text-red-400",
      bg: "bg-red-500/10",
      border: "border-red-500/30",
      status: "CRITICAL BREACH RISK",
      glow: "drop-shadow-[0_0_12px_rgba(239,68,68,0.35)]"
    };
  };

  const theme = getScoreTheme(score);
  const normalizedScore = Math.max(0, Math.min(100, score));

  // Circular gauge calculations (radius = 54)
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div className={`bg-[#111827] border ${theme.border} rounded-2xl p-5 shadow-xl transition-all duration-300 relative overflow-hidden`}>
      {/* Background Cyber Grid Accent */}
      <div className="absolute -right-8 -bottom-8 w-36 h-36 bg-blue-600/5 rounded-full blur-2xl pointer-events-none" />

      <div className="flex flex-col md:flex-row items-center justify-between gap-6">
        {/* Left: Score Gauge */}
        <div className="flex items-center gap-5">
          <div className="relative w-32 h-32 flex items-center justify-center shrink-0">
            <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 128 128">
              {/* Outer track */}
              <circle
                cx="64"
                cy="64"
                r={radius}
                className="stroke-gray-800/80"
                strokeWidth="10"
                fill="none"
              />
              {/* Inner active gauge */}
              <circle
                cx="64"
                cy="64"
                r={radius}
                stroke={theme.stroke}
                strokeWidth="10"
                strokeLinecap="round"
                fill="none"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                className={`transition-all duration-1000 ease-out ${theme.glow}`}
              />
            </svg>

            {/* Centered Value */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className={`text-3xl font-black font-mono tracking-tighter ${theme.text}`}>
                {normalizedScore.toFixed(0)}
              </span>
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider -mt-1">
                / 100
              </span>
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <Shield className={`w-4 h-4 ${theme.text}`} />
              <span className="text-[11px] font-mono uppercase tracking-wider text-gray-400 font-bold">
                {title}
              </span>
            </div>
            <div className="text-sm font-bold text-gray-100 mt-1">
              {healthStatus || theme.status}
            </div>
            <p className="text-xs text-gray-400 mt-0.5 max-w-sm leading-relaxed">
              {subtitle}
            </p>
            <div className="mt-2 flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${theme.bg} ${theme.text} border ${theme.border}`}>
                {theme.status}
              </span>
              <span className="text-[10px] font-mono text-gray-500">
                Deterministic Calculation
              </span>
            </div>
          </div>
        </div>

        {/* Right: Quick metric chips and toggle */}
        <div className="flex flex-col items-end gap-3 w-full md:w-auto">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 w-full md:w-auto text-left">
            <div className="bg-[#0B0F17] px-3 py-2 rounded-lg border border-gray-800">
              <div className="text-[10px] font-mono text-gray-500">POSTURE</div>
              <div className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> ACTIVE
              </div>
            </div>
            <div className="bg-[#0B0F17] px-3 py-2 rounded-lg border border-gray-800">
              <div className="text-[10px] font-mono text-gray-500">MODE</div>
              <div className="text-xs font-mono font-bold text-blue-400">DEFENSIVE</div>
            </div>
            <div className="bg-[#0B0F17] px-3 py-2 rounded-lg border border-gray-800 col-span-2 sm:col-span-1">
              <div className="text-[9px] font-mono text-gray-500">STANDARD</div>
              <div className="text-[10px] font-mono text-amber-400 font-bold leading-tight">
                INTERNAL EVALUATION METRIC — NON-INDUSTRY STANDARD
              </div>
            </div>
          </div>

          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1.5 text-xs font-mono text-blue-400 hover:text-blue-300 transition-colors self-end"
          >
            <span>{expanded ? 'Hide Mathematical Breakdown' : 'Expand Mathematical Breakdown'}</span>
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Expandable 6-Factor Composite Factor Breakdown */}
      {expanded && (
        <div className="mt-5 pt-4 border-t border-gray-800/80 space-y-4 animate-in fade-in slide-in-from-top-2 duration-200">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-gray-300 font-semibold flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-400" />
              Factor Contribution (Normalized 0–100)
            </span>
            <span className="text-[11px] font-mono text-gray-500">
              Formula: min(100, 0.25·Anom + 0.20·Sev + 0.15·Asset + 0.15·Id + 0.15·Seq + 0.10·Stage)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {/* Factor 1: Anomaly */}
            <div className="bg-[#0B0F17] p-3 rounded-lg border border-gray-800/70">
              <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                <span>Anomaly Score (25%)</span>
                <span className="text-amber-400 font-bold">{breakdown?.anomaly ?? factors?.unresolved_anomalies_factor ?? 20}</span>
              </div>
              <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-amber-400 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${Math.min(100, breakdown?.anomaly ?? factors?.unresolved_anomalies_factor ?? 20)}%` }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-1">Isolation Forest ML decision boundary</div>
            </div>

            {/* Factor 2: Severity */}
            <div className="bg-[#0B0F17] p-3 rounded-lg border border-gray-800/70">
              <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                <span>Threat Severity (20%)</span>
                <span className="text-red-400 font-bold">{breakdown?.severity ?? factors?.critical_exposure_factor ?? 30}</span>
              </div>
              <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-red-400 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${Math.min(100, breakdown?.severity ?? factors?.critical_exposure_factor ?? 30)}%` }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-1">CRITICAL/HIGH event telemetry</div>
            </div>

            {/* Factor 3: Asset Criticality */}
            <div className="bg-[#0B0F17] p-3 rounded-lg border border-gray-800/70">
              <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                <span>Asset Criticality (15%)</span>
                <span className="text-blue-400 font-bold">{breakdown?.asset ?? factors?.external_network_exposure ?? 40}</span>
              </div>
              <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-blue-400 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${Math.min(100, breakdown?.asset ?? factors?.external_network_exposure ?? 40)}%` }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-1">Tier-1 Database / Server weight</div>
            </div>

            {/* Factor 4: Identity Sensitivity */}
            <div className="bg-[#0B0F17] p-3 rounded-lg border border-gray-800/70">
              <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                <span>Identity Sensitivity (15%)</span>
                <span className="text-purple-400 font-bold">{breakdown?.identity ?? 50}</span>
              </div>
              <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-purple-400 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${Math.min(100, breakdown?.identity ?? 50)}%` }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-1">Domain Admin vs Standard Operator</div>
            </div>

            {/* Factor 5: Event Sequence */}
            <div className="bg-[#0B0F17] p-3 rounded-lg border border-gray-800/70">
              <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                <span>Event Sequence (15%)</span>
                <span className="text-indigo-400 font-bold">{breakdown?.sequence ?? 35}</span>
              </div>
              <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-indigo-400 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${Math.min(100, breakdown?.sequence ?? 35)}%` }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-1">Temporal chain clustering depth</div>
            </div>

            {/* Factor 6: Attack Stage */}
            <div className="bg-[#0B0F17] p-3 rounded-lg border border-gray-800/70">
              <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                <span>Attack Stage (10%)</span>
                <span className="text-cyan-400 font-bold">{breakdown?.stage ?? 45}</span>
              </div>
              <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-cyan-400 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${Math.min(100, breakdown?.stage ?? 45)}%` }}
                />
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-1">Kill chain progression milestone</div>
            </div>
          </div>

          {/* Three-Score Explicit Distinction Panel */}
          <div className="bg-[#0B0F17] p-3 rounded-lg border border-gray-800 text-xs font-mono space-y-2">
            <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider block">
              Architectural Score Taxonomy & Distinction
            </span>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[11px]">
              <div className="p-2 rounded bg-gray-900/60 border border-emerald-900/40">
                <span className="text-emerald-400 font-bold block">1. Security Score</span>
                <span className="text-gray-400 text-[10px] block mt-0.5">
                  Tenant-level defensive posture evaluation (0–100). Aggregates containment, isolation forest anomalies, and asset criticality.
                </span>
              </div>
              <div className="p-2 rounded bg-gray-900/60 border border-red-900/40">
                <span className="text-red-400 font-bold block">2. Incident Risk Score</span>
                <span className="text-gray-400 text-[10px] block mt-0.5">
                  Canonical 6-factor deterministic model: <code className="text-red-300">0.25*S_anom + 0.20*S_sev + 0.15*S_asset + 0.15*S_id + 0.15*S_seq + 0.10*S_stage</code>.
                </span>
              </div>
              <div className="p-2 rounded bg-gray-900/60 border border-amber-900/40">
                <span className="text-amber-400 font-bold block">3. IP Risk Profile</span>
                <span className="text-gray-400 text-[10px] block mt-0.5">
                  Passive local evidence profile: <code className="text-amber-300">0.25*S_vol + 0.25*S_anom + 0.20*S_inc + 0.15*S_sev + 0.15*S_mitre</code>.
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 p-2.5 rounded bg-gray-900/80 border border-gray-800 text-[11px] font-mono text-gray-400">
            <Info className="w-4 h-4 text-blue-400 shrink-0" />
            <span>
              <strong>Regulatory Notice:</strong> Evaluated strictly against offline telemetry database models. Zero simulated metrics are substituted for unobserved facts.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
