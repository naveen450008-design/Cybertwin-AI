import React, { useState } from 'react';
import { Target, ShieldAlert, ChevronRight, Info } from 'lucide-react';

export interface MitreMappedTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence?: number;
}

interface MitreFingerprintProps {
  techniques: MitreMappedTechnique[];
  title?: string;
}

const TACTIC_PIPELINE = [
  { id: 'INITIAL_ACCESS', label: 'Initial Access', short: 'Access' },
  { id: 'EXECUTION', label: 'Execution', short: 'Exec' },
  { id: 'PERSISTENCE', label: 'Persistence', short: 'Persist' },
  { id: 'PRIVILEGE_ESCALATION', label: 'Privilege Escalation', short: 'PrivEsc' },
  { id: 'DEFENSE_EVASION', label: 'Defense Evasion', short: 'Evasion' },
  { id: 'CREDENTIAL_ACCESS', label: 'Credential Access', short: 'Creds' },
  { id: 'DISCOVERY', label: 'Discovery', short: 'Disc' },
  { id: 'LATERAL_MOVEMENT', label: 'Lateral Movement', short: 'Lateral' },
  { id: 'COLLECTION', label: 'Collection', short: 'Collect' },
  { id: 'EXFILTRATION', label: 'Exfiltration', short: 'Exfil' },
  { id: 'IMPACT', label: 'Impact', short: 'Impact' },
];

export const MitreFingerprint: React.FC<MitreFingerprintProps> = ({
  techniques = [],
  title = "MITRE ATT&CK® VISUAL ATTACK FINGERPRINT"
}) => {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

  // Group techniques by tactic
  const tacticMap = new Map<string, MitreMappedTechnique[]>();
  techniques.forEach(tech => {
    const normTactic = tech.tactic.toUpperCase().replace(/\s+/g, '_');
    if (!tacticMap.has(normTactic)) {
      tacticMap.set(normTactic, []);
    }
    tacticMap.get(normTactic)!.push(tech);
  });

  const activeTacticCount = Array.from(tacticMap.keys()).length;

  return (
    <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5 shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-gray-800">
        <div>
          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-purple-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-200">
              {title}
            </h3>
          </div>
          <p className="text-[11px] text-gray-400 mt-0.5">
            Stage-by-stage tactical mapping of verified incident evidence to Enterprise ATT&CK matrix.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono bg-purple-950/60 text-purple-300 px-2.5 py-0.5 rounded border border-purple-800/50">
            {activeTacticCount} / 11 TACTICS ACTIVE
          </span>
        </div>
      </div>

      {/* Horizontal Pipeline Steps */}
      <div className="overflow-x-auto pb-2">
        <div className="flex items-center gap-1.5 min-w-[760px]">
          {TACTIC_PIPELINE.map((stage, idx) => {
            const matches = tacticMap.get(stage.id) || [];
            const isActive = matches.length > 0;
            const isSelected = selectedTactic === stage.id;

            return (
              <React.Fragment key={stage.id}>
                <div
                  onClick={() => isActive && setSelectedTactic(isSelected ? null : stage.id)}
                  className={`flex-1 min-w-[65px] p-2 rounded-lg border text-center transition-all cursor-pointer ${
                    isActive
                      ? isSelected
                        ? 'bg-purple-900/50 border-purple-400 text-purple-200 ring-2 ring-purple-500/50 shadow-[0_0_15px_rgba(168,85,247,0.3)]'
                        : 'bg-purple-950/30 border-purple-700/60 text-purple-300 hover:border-purple-500 hover:bg-purple-900/30'
                      : 'bg-[#080C14] border-gray-800/50 text-gray-600 cursor-not-allowed opacity-50'
                  }`}
                >
                  <div className="text-[9px] font-mono uppercase tracking-tight text-gray-400 mb-0.5">
                    Stage {idx + 1}
                  </div>
                  <div className="text-[11px] font-bold font-mono truncate">
                    {stage.short}
                  </div>
                  <div className="mt-1 flex justify-center">
                    {isActive ? (
                      <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
                    ) : (
                      <span className="w-1.5 h-1.5 rounded-full bg-gray-700" />
                    )}
                  </div>
                </div>

                {idx < TACTIC_PIPELINE.length - 1 && (
                  <ChevronRight className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-purple-400' : 'text-gray-700'}`} />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Selected / Active Techniques Details Drawer */}
      <div className="bg-[#0B0F17] rounded-xl p-3.5 border border-gray-800 text-xs font-mono">
        <div className="text-[11px] font-semibold text-gray-400 mb-2 flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
          <span>EVIDENCE-GROUNDED ATT&CK TECHNIQUES ({techniques.length} REGISTERED):</span>
        </div>

        {techniques.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {techniques.map(t => (
              <div
                key={t.technique_id}
                className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-gray-900 border border-purple-900/60 text-gray-200"
              >
                <span className="font-bold text-purple-400">{t.technique_id}</span>
                <span className="text-gray-400 text-[11px]">{t.technique_name}</span>
                <span className="text-[9px] bg-purple-950 text-purple-300 px-1 rounded">
                  {t.tactic}
                </span>
                {t.confidence !== undefined && (
                  <span className="text-[9px] text-gray-500">
                    {(t.confidence * 100).toFixed(0)}% conf
                  </span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-gray-500 text-[11px]">
            No techniques mapped yet. Ingest telemetry or run synthetic attack scenarios to view live ATT&CK fingerprints.
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 text-[10px] font-mono text-gray-500">
        <Info className="w-3.5 h-3.5 text-purple-400" />
        <span>Grounded strictly against offline ATT&CK knowledge base. Unobserved stages remain non-highlighted.</span>
      </div>
    </div>
  );
};
