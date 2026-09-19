import React, { useState } from 'react';
import { Radio, Info, Crosshair } from 'lucide-react';

export interface RadarEntity {
  id: string;
  entity_type: string; // 'IP', 'INCIDENT', 'USER', 'DEVICE'
  label: string;
  threat_score: number;
  severity: string;
  distance: number; // 10 to 90 (smaller distance = closer to center)
  angle: number;    // 0 to 360 degrees
  metadata?: Record<string, any>;
}

interface ThreatRadarProps {
  entities: RadarEntity[];
  onSelectIP?: (ip: string) => void;
  onSelectIncident?: (incidentId: string) => void;
}

export const ThreatRadar: React.FC<ThreatRadarProps> = ({
  entities,
  onSelectIP,
  onSelectIncident,
}) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [hoveredEntity, setHoveredEntity] = useState<RadarEntity | null>(null);

  const filteredEntities = entities.filter(e => {
    if (filterType === 'ALL') return true;
    return e.entity_type === filterType;
  });

  const getEntityColor = (sev: string, type: string) => {
    if (sev === 'CRITICAL') return { fill: '#EF4444', ring: 'rgba(239, 68, 68, 0.4)', text: 'text-red-400' };
    if (sev === 'HIGH') return { fill: '#F59E0B', ring: 'rgba(245, 158, 11, 0.4)', text: 'text-amber-400' };
    if (type === 'IP') return { fill: '#3B82F6', ring: 'rgba(59, 130, 246, 0.4)', text: 'text-blue-400' };
    if (type === 'INCIDENT') return { fill: '#A855F7', ring: 'rgba(168, 85, 247, 0.4)', text: 'text-purple-400' };
    return { fill: '#10B981', ring: 'rgba(16, 185, 129, 0.4)', text: 'text-emerald-400' };
  };

  const center = 160;
  const maxRadius = 135;

  return (
    <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5 shadow-xl relative overflow-hidden">
      {/* Header & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-gray-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-gray-200 flex items-center gap-1.5">
              <Crosshair className="w-4 h-4 text-emerald-400" />
              CYBER THREAT RADAR &bull; OBSERVED ENTITIES
            </h3>
          </div>
          <p className="text-[11px] text-gray-400 mt-0.5">
            Polar proximity coordinates based on internal risk and anomaly scores (center = elevated threat).
          </p>
        </div>

        {/* Filter Chips */}
        <div className="flex flex-wrap gap-1.5 text-[11px] font-mono">
          {['ALL', 'IP', 'INCIDENT', 'USER', 'DEVICE'].map(t => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-2.5 py-1 rounded-md transition-all ${
                filterType === t
                  ? 'bg-blue-600/30 text-blue-300 border border-blue-500/50 font-bold'
                  : 'bg-gray-800/60 text-gray-400 hover:text-gray-200 border border-gray-700/50'
              }`}
            >
              {t === 'ALL' ? 'ALL TRACKED' : `${t}S`}
            </button>
          ))}
        </div>
      </div>

      {/* Radar Canvas View */}
      <div className="flex flex-col lg:flex-row items-center justify-center gap-6">
        {/* Radar Circular Screen */}
        <div className="relative w-80 h-80 shrink-0 bg-[#080C14] rounded-full border border-emerald-500/30 shadow-[0_0_35px_rgba(16,185,129,0.12)] p-2">
          {/* Concentric Coordinate Rings */}
          <svg className="w-full h-full" viewBox="0 0 320 320">
            <defs>
              {/* Radar Sweep Gradient */}
              <linearGradient id="sweepGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="rgba(16, 185, 129, 0.4)" />
                <stop offset="100%" stopColor="rgba(16, 185, 129, 0.0)" />
              </linearGradient>
            </defs>

            {/* Concentric Circles */}
            <circle cx={center} cy={center} r={maxRadius} fill="none" stroke="rgba(16, 185, 129, 0.2)" strokeWidth="1" strokeDasharray="3 3" />
            <circle cx={center} cy={center} r={maxRadius * 0.75} fill="none" stroke="rgba(16, 185, 129, 0.25)" strokeWidth="1" />
            <circle cx={center} cy={center} r={maxRadius * 0.50} fill="none" stroke="rgba(16, 185, 129, 0.3)" strokeWidth="1" strokeDasharray="2 2" />
            <circle cx={center} cy={center} r={maxRadius * 0.25} fill="none" stroke="rgba(239, 68, 68, 0.35)" strokeWidth="1.5" />

            {/* Crosshairs */}
            <line x1={center} y1={center - maxRadius} x2={center} y2={center + maxRadius} stroke="rgba(16, 185, 129, 0.25)" strokeWidth="1" />
            <line x1={center - maxRadius} y1={center} x2={center + maxRadius} y2={center} stroke="rgba(16, 185, 129, 0.25)" strokeWidth="1" />

            {/* Quadrant Labels */}
            <text x="210" y="70" fill="rgba(59, 130, 246, 0.7)" fontSize="9" fontFamily="monospace" fontWeight="bold">Q1: IP THREATS</text>
            <text x="200" y="270" fill="rgba(168, 85, 247, 0.7)" fontSize="9" fontFamily="monospace" fontWeight="bold">Q2: INCIDENTS</text>
            <text x="35" y="270" fill="rgba(245, 158, 11, 0.7)" fontSize="9" fontFamily="monospace" fontWeight="bold">Q3: USERS</text>
            <text x="35" y="70" fill="rgba(16, 185, 129, 0.7)" fontSize="9" fontFamily="monospace" fontWeight="bold">Q4: HOSTS</text>

            {/* Rotating Radar Sweep Line */}
            <g className="animate-[spin_4s_linear_infinite]" style={{ transformOrigin: `${center}px ${center}px` }}>
              <line x1={center} y1={center} x2={center + maxRadius} y2={center} stroke="rgba(16, 185, 129, 0.85)" strokeWidth="2" />
              {/* Sweep Cone */}
              <path
                d={`M ${center} ${center} L ${center + maxRadius} ${center} A ${maxRadius} ${maxRadius} 0 0 0 ${center + maxRadius * 0.707} ${center - maxRadius * 0.707} Z`}
                fill="url(#sweepGrad)"
              />
            </g>

            {/* Center Core */}
            <circle cx={center} cy={center} r="4" fill="#EF4444" />
            <circle cx={center} cy={center} r="8" fill="none" stroke="#EF4444" strokeWidth="1" opacity="0.6" />

            {/* Plotted Entity Blips */}
            {filteredEntities.map(entity => {
              // Convert polar (distance 0-100, angle in degrees) to cartesian (x, y)
              const r = (entity.distance / 100) * maxRadius;
              const rad = (entity.angle * Math.PI) / 180;
              const cx = center + r * Math.cos(rad);
              const cy = center + r * Math.sin(rad);
              const colorInfo = getEntityColor(entity.severity, entity.entity_type);
              const isHovered = hoveredEntity?.id === entity.id;

              return (
                <g 
                  key={entity.id}
                  className="cursor-pointer transition-transform duration-200"
                  onMouseEnter={() => setHoveredEntity(entity)}
                  onMouseLeave={() => setHoveredEntity(null)}
                  onClick={() => {
                    if (entity.entity_type === 'IP' && onSelectIP) {
                      onSelectIP(entity.label.replace('IP: ', ''));
                    } else if (entity.entity_type === 'INCIDENT' && onSelectIncident && entity.metadata?.incident_id) {
                      onSelectIncident(entity.metadata.incident_id);
                    }
                  }}
                >
                  {/* Outer pulse ring for high threat */}
                  {entity.threat_score >= 65 && (
                    <circle
                      cx={cx}
                      cy={cy}
                      r={isHovered ? 14 : 9}
                      fill="none"
                      stroke={colorInfo.fill}
                      strokeWidth="1.5"
                      opacity="0.4"
                      className="animate-ping"
                    />
                  )}
                  {/* Entity Dot */}
                  <circle
                    cx={cx}
                    cy={cy}
                    r={isHovered ? 7 : 5}
                    fill={colorInfo.fill}
                    stroke="#0B0F17"
                    strokeWidth="1.5"
                    className="transition-all duration-200"
                  />
                </g>
              );
            })}
          </svg>
        </div>

        {/* Entity Inspector Side Card */}
        <div className="flex-1 w-full max-w-sm space-y-3">
          <div className="bg-[#0B0F17] border border-gray-800 rounded-xl p-4 min-h-[160px] flex flex-col justify-between">
            {hoveredEntity ? (
              <div className="space-y-2 animate-in fade-in duration-150">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-800">
                    {hoveredEntity.entity_type} BLIP
                  </span>
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                    hoveredEntity.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                    hoveredEntity.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    'bg-blue-950 text-blue-300 border border-blue-800'
                  }`}>
                    {hoveredEntity.severity}
                  </span>
                </div>

                <div className="text-sm font-mono font-bold text-gray-100 break-all">
                  {hoveredEntity.label}
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-1">
                  <div className="bg-gray-900 p-2 rounded border border-gray-800">
                    <div className="text-gray-500">THREAT INTENSITY</div>
                    <div className="text-amber-400 font-bold">{hoveredEntity.threat_score.toFixed(1)} / 100</div>
                  </div>
                  <div className="bg-gray-900 p-2 rounded border border-gray-800">
                    <div className="text-gray-500">RADAR PROXIMITY</div>
                    <div className="text-emerald-400 font-bold">{hoveredEntity.distance.toFixed(0)}m (Range)</div>
                  </div>
                </div>

                {hoveredEntity.entity_type === 'IP' && (
                  <div className="text-[11px] font-mono text-blue-400 flex items-center gap-1 mt-1 cursor-pointer hover:underline"
                       onClick={() => onSelectIP && onSelectIP(hoveredEntity.label.replace('IP: ', ''))}>
                    &rarr; Click to open passive IP Intelligence Drawer
                  </div>
                )}
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-4 text-gray-500">
                <Radio className="w-8 h-8 text-gray-600 mb-2 animate-pulse" />
                <div className="text-xs font-mono text-gray-400 font-bold">RADAR TRACKING ACTIVE</div>
                <div className="text-[11px] font-mono text-gray-500 mt-1">
                  Hover over any blip on the radar canvas to inspect threat metrics and drill into IP intelligence.
                </div>
              </div>
            )}
          </div>

          {/* Mandatory Taxonomy Disclosures */}
          <div className="p-3 bg-gray-900/50 rounded-lg border border-gray-800 text-[10px] font-mono text-gray-400 space-y-1">
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <Info className="w-3.5 h-3.5" />
              VISUAL ANALYTICS &bull; INTERNAL OBSERVED ENTITIES
            </div>
            <p className="leading-relaxed">
              Entities reflect strictly local security database records and UEBA statistical outliers. This is not an external real-time feed.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
