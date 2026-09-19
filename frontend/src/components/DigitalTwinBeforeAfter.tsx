import React from 'react';
import { Cpu, RotateCcw, AlertTriangle, ShieldCheck } from 'lucide-react';

interface DigitalTwinBeforeAfterProps {
  targetEntity?: string;
  actionType?: string;
  preRiskScore?: number;
  postRiskScore?: number;
  severedSessions?: number;
  collateralUsers?: number;
  disruptionScore?: number;
  isTier1Disrupted?: boolean;
  rollbackAvailable?: boolean;
}

export const DigitalTwinBeforeAfter: React.FC<DigitalTwinBeforeAfterProps> = ({
  targetEntity = "192.168.1.105",
  actionType = "SIMULATE_ISOLATE_DEVICE",
  preRiskScore = 82.0,
  postRiskScore = 24.5,
  severedSessions = 3,
  collateralUsers = 1,
  disruptionScore = 75,
  isTier1Disrupted = false,
  rollbackAvailable = true,
}) => {
  const riskReductionPct = Math.round(((preRiskScore - postRiskScore) / preRiskScore) * 100);

  return (
    <div className="bg-[#111827] border border-cyan-900/50 rounded-2xl p-5 shadow-xl space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-gray-800">
        <div>
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-200">
              DIGITAL TWIN SIMULATION &bull; BEFORE vs AFTER ANALYSIS
            </h3>
          </div>
          <p className="text-[11px] text-gray-400 mt-0.5">
            Safe in-memory dependency graph traversal calculating operational blast radius and risk reduction.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono bg-cyan-950/80 text-cyan-300 px-2.5 py-0.5 rounded border border-cyan-800/60 font-semibold">
            SIMULATED ACTION
          </span>
        </div>
      </div>

      {/* Before vs After Split Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* BEFORE SIMULATION */}
        <div className="bg-[#0B0F17] p-4 rounded-xl border border-red-900/40 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-red-400 font-bold border-b border-gray-800/60 pb-2">
            <span className="flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4" /> BEFORE SIMULATION
            </span>
            <span className="text-[10px] text-red-500 font-normal">ACTIVE THREAT EXPOSURE</span>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-gray-400">Target Entity:</span>
              <span className="text-gray-200 font-semibold">{targetEntity}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Composite Risk Score:</span>
              <span className="text-red-400 font-bold">{preRiskScore.toFixed(1)} / 100</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Containment State:</span>
              <span className="text-amber-400 font-semibold">UNCONTAINED</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Active Host Sessions:</span>
              <span className="text-gray-200 font-semibold">{severedSessions} Live Links</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Attack Blast Radius:</span>
              <span className="text-red-400 font-semibold">Expanding Lateral Path</span>
            </div>
          </div>
        </div>

        {/* AFTER SIMULATION */}
        <div className="bg-[#0B0F17] p-4 rounded-xl border border-emerald-900/40 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-emerald-400 font-bold border-b border-gray-800/60 pb-2">
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" /> AFTER SIMULATION (DIGITAL TWIN)
            </span>
            <span className="text-[10px] text-emerald-500 font-normal">PROJECTED OUTCOME</span>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-gray-400">Simulated Action:</span>
              <span className="text-cyan-400 font-semibold">{actionType}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Projected Risk Score:</span>
              <span className="text-emerald-400 font-bold">{postRiskScore.toFixed(1)} / 100 (-{riskReductionPct}%)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Blast Disruption Score:</span>
              <span className="text-amber-400 font-semibold">{disruptionScore} / 100 {isTier1Disrupted ? '(Tier-1 Impact)' : ''}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Severed Sessions / Collateral:</span>
              <span className="text-gray-200 font-semibold">{severedSessions} Sessions &bull; {collateralUsers} Users</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Rollback Status:</span>
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <RotateCcw className="w-3 h-3" /> {rollbackAvailable ? 'Snapshot Ready' : 'N/A'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Mandatory Regulatory Banner */}
      <div className="p-3 bg-gray-900/80 rounded-xl border border-gray-800 text-[10px] font-mono text-gray-400 space-y-1">
        <div className="text-amber-400 font-bold uppercase tracking-wider">
          SIMULATED RESULT — NOT REAL-WORLD EXECUTION
        </div>
        <p className="leading-relaxed">
          Defensive operations execute exclusively within software-emulated topological dependency graphs. The platform maintains zero native OS subprocess bindings or firewall alteration drivers.
        </p>
      </div>
    </div>
  );
};
