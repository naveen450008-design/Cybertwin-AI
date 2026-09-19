import React from 'react';
import { ShieldCheck } from 'lucide-react';

export const TaxonomyBanner: React.FC = () => {
  return (
    <div className="bg-[#111827] border-b border-gray-800 px-4 py-2 text-xs flex flex-wrap items-center justify-between gap-2 shadow-inner">
      <div className="flex items-center gap-2 text-gray-300">
        <ShieldCheck className="w-4 h-4 text-blue-400 shrink-0" />
        <span className="font-semibold text-gray-200">ACADEMIC PROTOTYPE:</span>
        <span className="text-gray-400 hidden sm:inline">
          Evidence-driven SIEM, UEBA & incident investigation research platform. Safe simulation only.
        </span>
      </div>

      <div className="flex items-center gap-1.5 flex-wrap">
        <span className="bg-purple-900/60 text-purple-300 border border-purple-700/50 px-2 py-0.5 rounded font-mono font-medium tracking-wide">
          SYNTHETIC DATA
        </span>
        <span className="bg-amber-900/60 text-amber-300 border border-amber-700/50 px-2 py-0.5 rounded font-mono font-medium tracking-wide">
          POTENTIAL ANOMALY
        </span>
        <span className="bg-emerald-900/60 text-emerald-300 border border-emerald-700/50 px-2 py-0.5 rounded font-mono font-medium tracking-wide">
          SIMULATED ACTION
        </span>
        <span className="bg-blue-900/60 text-blue-300 border border-blue-700/50 px-2 py-0.5 rounded font-mono font-medium tracking-wide">
          INTERNAL EVALUATION METRIC
        </span>
      </div>
    </div>
  );
};
