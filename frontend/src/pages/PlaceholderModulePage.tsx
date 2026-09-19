import React from 'react';
import { Clock, Layers, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

interface PlaceholderModuleProps {
  moduleName: string;
  targetPhase: string;
  description: string;
  expectedDeliverables: string[];
}

export const PlaceholderModulePage: React.FC<PlaceholderModuleProps> = ({
  moduleName,
  targetPhase,
  description,
  expectedDeliverables,
}) => {
  return (
    <div className="space-y-6">
      {/* Module Title Banner */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-6 shadow-lg">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-[10px] bg-purple-900/60 text-purple-300 font-mono px-2 py-0.5 rounded border border-purple-700/60 font-semibold uppercase">
            SCHEDULED FOR {targetPhase}
          </span>
          <span className="text-[10px] bg-gray-800 text-gray-400 font-mono px-2 py-0.5 rounded border border-gray-700">
            SPECIFICATION LOCKED IN PHASE 0
          </span>
        </div>

        <h2 className="text-xl font-bold text-gray-100 mb-2">
          {moduleName}
        </h2>
        <p className="text-xs text-gray-400 max-w-2xl leading-relaxed">
          {description}
        </p>
      </div>

      {/* Scope Details */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl p-6 shadow-lg space-y-4">
        <div className="flex items-center gap-2 text-sm font-bold text-gray-200 font-mono border-b border-gray-800 pb-3">
          <Layers className="w-4 h-4 text-blue-400" />
          <span>Planned Architecture Deliverables for {targetPhase}</span>
        </div>

        <ul className="space-y-2">
          {expectedDeliverables.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2 text-xs text-gray-300 font-mono">
              <span className="text-blue-400 font-bold shrink-0">&bull;</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>

        <div className="pt-4 border-t border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-gray-500 font-mono">
            <Clock className="w-3.5 h-3.5" />
            <span>Strict Phase Gate: Development commences upon Phase 1 sign-off.</span>
          </div>

          <Link
            to="/"
            className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:underline font-mono"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Dashboard</span>
          </Link>
        </div>
      </div>
    </div>
  );
};
