import { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import type { GraphStats } from '../types/graph';
import { SEVERITY_COLORS } from '../types/graph';
import { useTheme } from '../hooks/useTheme';

interface Props {
  stats: GraphStats;
  scanPath?: string;
  onOpenAISettings?: () => void;
}

export default function StatsBar({ stats, scanPath, onOpenAISettings }: Props) {
  const { theme, toggleTheme } = useTheme();
  const [showRiskTooltip, setShowRiskTooltip] = useState(false);
  const riskRef = useRef<HTMLDivElement>(null);

  const riskColor =
    stats.risk_score >= 5 ? '#DC2626' :
    stats.risk_score >= 3 ? '#F97316' :
    stats.risk_score >= 1 ? '#EAB308' : '#10B981';

  const riskLabel =
    stats.risk_score >= 7 ? 'Critical' :
    stats.risk_score >= 5 ? 'High' :
    stats.risk_score >= 3 ? 'Moderate' :
    stats.risk_score >= 1 ? 'Low' : 'Excellent';

  // Close tooltip on click outside
  useEffect(() => {
    if (!showRiskTooltip) return;
    const handleClick = (e: MouseEvent) => {
      if (riskRef.current && !riskRef.current.contains(e.target as HTMLElement)) {
        setShowRiskTooltip(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [showRiskTooltip]);

  // Compute breakdown for tooltip
  const sevCounts = stats.severity_counts || {};
  const critCount = sevCounts['critical'] || 0;
  const highCount = sevCounts['high'] || 0;
  const medCount = sevCounts['medium'] || 0;
  const lowCount = sevCounts['low'] || 0;
  const totalNodes = stats.total_nodes || 1;
  const weightedSum = critCount * 10 + highCount * 5 + medCount * 2 + lowCount * 1;

  // Compute tooltip position from ref
  const tooltipPos = showRiskTooltip && riskRef.current
    ? riskRef.current.getBoundingClientRect()
    : null;

  return (
    <>
      <div
        className="backdrop-blur border-b px-5 py-2.5 flex items-center gap-4 text-sm shrink-0 flex-wrap min-h-[44px]"
        style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-primary)' }}
      >
        {/* Scanned path */}
        {scanPath && (
          <>
            <div className="flex items-center gap-2 shrink-0 max-w-[200px]" title={scanPath}>
              <span className="text-base">&#x1F4C2;</span>
              <span className="font-mono text-xs truncate" style={{ color: 'var(--text-primary)' }}>{scanPath}</span>
            </div>
            <div className="w-px h-6 shrink-0 hidden sm:block" style={{ background: 'var(--border-primary)' }} />
          </>
        )}

        {/* Risk Score with tooltip */}
        <div className="shrink-0" ref={riskRef}>
          <button
            className="flex items-center gap-1.5 cursor-pointer"
            onClick={() => setShowRiskTooltip(!showRiskTooltip)}
            onMouseEnter={() => setShowRiskTooltip(true)}
            onMouseLeave={() => setShowRiskTooltip(false)}
          >
            <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>Risk</span>
            <span className="font-bold text-lg" style={{ color: riskColor }}>
              {stats.risk_score.toFixed(1)}
            </span>
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ background: `${riskColor}20`, color: riskColor }}>
              {riskLabel}
            </span>
          </button>
        </div>

        <div className="w-px h-6 shrink-0 hidden sm:block" style={{ background: 'var(--border-primary)' }} />

        {/* Counts */}
        <div className="flex items-center gap-3 flex-wrap">
          <StatPill label="Files" value={stats.total_files_scanned} color="#9CA3AF" />
          <StatPill label="Endpoints" value={stats.entry_points} color="#3B82F6" />
          <StatPill label="APIs" value={stats.external_apis} color="#F97316" />
          <StatPill label="Stores" value={stats.data_stores} color="#10B981" />
          <StatPill label="Secrets" value={stats.secrets} color="#EF4444" />
          <StatPill label="Vulns" value={stats.vulnerabilities} color="#DC2626" />
          <StatPill label="Deps" value={stats.dependencies} color="#6B7280" />
        </div>

        {/* Severity breakdown */}
        {Object.keys(stats.severity_counts).length > 0 && (
          <>
            <div className="w-px h-6 shrink-0 hidden sm:block" style={{ background: 'var(--border-primary)' }} />
            <div className="flex items-center gap-1.5 flex-wrap">
              {Object.entries(stats.severity_counts).map(([sev, count]) => (
                <span
                  key={sev}
                  className="px-1.5 py-0.5 rounded text-white font-semibold uppercase text-[10px]"
                  style={{ background: SEVERITY_COLORS[sev as keyof typeof SEVERITY_COLORS] || '#6B7280' }}
                >
                  {sev}: {count}
                </span>
              ))}
            </div>
          </>
        )}

        {/* Languages */}
        {stats.languages_detected.length > 0 && (
          <>
            <div className="w-px h-6 shrink-0 hidden sm:block" style={{ background: 'var(--border-primary)' }} />
            <div className="flex items-center gap-1 flex-wrap">
              {stats.languages_detected.slice(0, 5).map((lang) => (
                <span
                  key={lang}
                  className="px-1.5 py-0.5 rounded text-[10px] capitalize"
                  style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
                >
                  {lang}
                </span>
              ))}
            </div>
          </>
        )}

        {/* Spacer */}
        <div className="flex-1 min-w-[8px]" />

        {/* AI Settings */}
        {onOpenAISettings && (
          <button
            onClick={onOpenAISettings}
            className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-sm transition-colors"
            style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
            title="AI Remediation Settings"
          >
            {'\u2699\uFE0F'}
          </button>
        )}

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-lg transition-colors"
          style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? '\u2600\uFE0F' : '\uD83C\uDF19'}
        </button>
      </div>

      {/* Risk tooltip — rendered via portal on document.body to escape stacking contexts */}
      {showRiskTooltip && tooltipPos && createPortal(
        <div
          className="fixed w-[320px] rounded-lg border shadow-2xl p-4"
          style={{
            top: tooltipPos.bottom + 8,
            left: tooltipPos.left,
            background: 'var(--bg-secondary)',
            borderColor: 'var(--border-primary)',
            zIndex: 99999,
          }}
          onMouseEnter={() => setShowRiskTooltip(true)}
          onMouseLeave={() => setShowRiskTooltip(false)}
        >
          <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
            Risk Score Breakdown
          </p>

          <div className="flex items-center gap-2 mb-3">
            <span className="text-2xl font-bold" style={{ color: riskColor }}>{stats.risk_score.toFixed(1)}</span>
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>/ 10.0</span>
          </div>

          <div className="h-2 rounded-full mb-3" style={{ background: 'var(--bg-tertiary)' }}>
            <div
              className="h-full rounded-full transition-all"
              style={{ width: `${Math.min(stats.risk_score * 10, 100)}%`, background: riskColor }}
            />
          </div>

          <div className="flex justify-between text-[10px] mb-3" style={{ color: 'var(--text-muted)' }}>
            <span>0.0 Excellent</span>
            <span>1-3 Low</span>
            <span>3-5 Moderate</span>
            <span>5-7 High</span>
            <span>7+ Critical</span>
          </div>

          <div className="rounded-lg p-3 mb-3" style={{ background: 'var(--bg-tertiary)' }}>
            <p className="text-[11px] font-mono mb-1" style={{ color: 'var(--text-secondary)' }}>
              score = weighted_sum / total_nodes
            </p>
            <p className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
              = ({critCount}×10 + {highCount}×5 + {medCount}×2 + {lowCount}×1) / {totalNodes}
            </p>
            <p className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
              = {weightedSum} / {totalNodes} = {(weightedSum / totalNodes).toFixed(2)} → {stats.risk_score.toFixed(1)}
            </p>
          </div>

          <p className="text-[11px] mb-2" style={{ color: 'var(--text-muted)' }}>Severity weights:</p>
          <div className="grid grid-cols-2 gap-1 text-[11px]">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: '#DC2626' }} />
              <span style={{ color: 'var(--text-secondary)' }}>Critical = 10 pts</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: '#F97316' }} />
              <span style={{ color: 'var(--text-secondary)' }}>High = 5 pts</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: '#EAB308' }} />
              <span style={{ color: 'var(--text-secondary)' }}>Medium = 2 pts</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: '#3B82F6' }} />
              <span style={{ color: 'var(--text-secondary)' }}>Low = 1 pt</span>
            </div>
          </div>

          <p className="text-[10px] mt-3 italic" style={{ color: 'var(--text-muted)' }}>
            Ideal score: 0.0 (no findings). Lower is better. The score is capped at 10.0.
          </p>
        </div>,
        document.body,
      )}
    </>
  );
}

function StatPill({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-1 shrink-0">
      <div className="w-2 h-2 rounded-full" style={{ background: color }} />
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <span className="font-bold text-xs" style={{ color: 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}
