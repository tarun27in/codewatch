import type { ScanResult } from '../types/graph';

interface Props {
  scan: ScanResult;
}

export default function ScanProgress({ scan }: Props) {
  const pct = Math.round(scan.progress * 100);

  return (
    <div className="w-full max-w-2xl mx-auto mt-4">
      <div
        className="border rounded-xl p-5"
        style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{scan.message}</span>
          <span className="text-sm font-mono text-blue-400">{pct}%</span>
        </div>
        <div className="w-full rounded-full h-2.5 overflow-hidden" style={{ background: 'var(--bg-tertiary)' }}>
          <div
            className="bg-blue-500 h-full rounded-full transition-all duration-300"
            style={{ width: `${pct}%` }}
          />
        </div>
        {scan.status === 'error' && scan.error && (
          <p className="mt-2 text-sm text-red-400">{scan.error}</p>
        )}
      </div>
    </div>
  );
}
