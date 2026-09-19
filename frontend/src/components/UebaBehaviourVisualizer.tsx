import React from 'react';
import { UserCheck, AlertTriangle, Clock, HardDrive, Network, Terminal, CheckCircle2 } from 'lucide-react';

interface UebaComparisonProps {
  username?: string;
  anomalyScore?: number;
  observedHours?: string;
  observedVolume?: string;
  observedIp?: string;
  observedProcess?: string;
  isAfterHours?: boolean;
  isVolumeSpike?: boolean;
  isUnknownIp?: boolean;
  isSuspiciousProcess?: boolean;
}

export const UebaBehaviourVisualizer: React.FC<UebaComparisonProps> = ({
  username = "user_02",
  anomalyScore = 78.5,
  observedHours = "02:45 UTC (Night / Weekend)",
  observedVolume = "48.2 MB (Outbound Spike)",
  observedIp = "198.51.100.42 (External Non-RFC1918)",
  observedProcess = "powershell.exe -enc ...",
  isAfterHours = true,
  isVolumeSpike = true,
  isUnknownIp = true,
  isSuspiciousProcess = true,
}) => {
  return (
    <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5 shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-gray-800">
        <div>
          <div className="flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-200">
              UEBA BEHAVIOURAL PROFILE &bull; BASELINE vs OBSERVED
            </h3>
          </div>
          <p className="text-[11px] text-gray-400 mt-0.5">
            Statistical deviation of user '{username}' against 30-day historical behavioural baseline distributions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono bg-amber-950/70 text-amber-300 px-2.5 py-0.5 rounded border border-amber-800/50">
            ANOMALY INTENSITY: {anomalyScore.toFixed(1)} / 100
          </span>
        </div>
      </div>

      {/* Comparison Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Left: 30-Day Normal Baseline */}
        <div className="bg-[#0B0F17] p-4 rounded-xl border border-gray-800/80 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-emerald-400 font-bold border-b border-gray-800/60 pb-2">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" /> 30-DAY NORMAL BASELINE
            </span>
            <span className="text-[10px] text-gray-500 font-normal">HISTORICAL REFERENCE</span>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-gray-500" /> Active Hours:
              </span>
              <span className="text-gray-200 font-semibold text-right">09:00 – 18:00 UTC (Workdays)</span>
            </div>

            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <HardDrive className="w-3.5 h-3.5 text-gray-500" /> Typical Volume:
              </span>
              <span className="text-gray-200 font-semibold text-right">500 KB – 5.0 MB / transfer</span>
            </div>

            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Network className="w-3.5 h-3.5 text-gray-500" /> Subnet & Locations:
              </span>
              <span className="text-gray-200 font-semibold text-right">192.168.1.0/24 (Corp Site)</span>
            </div>

            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-gray-500" /> Allowed Binaries:
              </span>
              <span className="text-gray-200 font-semibold text-right">chrome.exe, outlook.exe, slack.exe</span>
            </div>
          </div>
        </div>

        {/* Right: Observed Activity Telemetry */}
        <div className="bg-[#0B0F17] p-4 rounded-xl border border-amber-900/40 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-amber-400 font-bold border-b border-gray-800/60 pb-2">
            <span className="flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" /> CURRENT OBSERVED TELEMETRY
            </span>
            <span className="text-[10px] text-amber-500 font-normal">DEVIATION DETECTED</span>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-gray-500" /> Active Hours:
              </span>
              <span className={`font-semibold text-right ${isAfterHours ? 'text-amber-400' : 'text-gray-200'}`}>
                {observedHours}
              </span>
            </div>

            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <HardDrive className="w-3.5 h-3.5 text-gray-500" /> Typical Volume:
              </span>
              <span className={`font-semibold text-right ${isVolumeSpike ? 'text-amber-400' : 'text-gray-200'}`}>
                {observedVolume}
              </span>
            </div>

            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Network className="w-3.5 h-3.5 text-gray-500" /> Subnet & Locations:
              </span>
              <span className={`font-semibold text-right ${isUnknownIp ? 'text-red-400' : 'text-gray-200'}`}>
                {observedIp}
              </span>
            </div>

            <div className="flex items-start justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-gray-500" /> Observed Binary:
              </span>
              <span className={`font-semibold text-right truncate max-w-[180px] ${isSuspiciousProcess ? 'text-amber-400' : 'text-gray-200'}`} title={observedProcess}>
                {observedProcess}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 pt-1">
        <span>POTENTIAL ANOMALY marker generated by unsupervised Isolation Forest (10-dimensional feature vector).</span>
        <span className="text-amber-400 font-semibold">NO GUARANTEED MALICE</span>
      </div>
    </div>
  );
};
