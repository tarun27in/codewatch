import { useScan } from './hooks/useScan';
import ScanForm from './components/ScanForm';
import ScanProgress from './components/ScanProgress';
import GraphView from './components/GraphView';

export default function App() {
  const { scan, graph, scanPath, loading, error, launch, reset, rescan, clearAndExit, loadFromJSON } = useScan();

  if (graph) {
    return (
      <GraphView
        graph={graph}
        scanPath={scanPath || ''}
        onBack={reset}
        onClearAndExit={clearAndExit}
        onRescan={rescan}
        rescanning={loading}
      />
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-8" style={{ background: 'var(--bg-primary)' }}>
      <ScanForm onScan={launch} loading={loading} onImport={loadFromJSON} />

      {scan && loading && <ScanProgress scan={scan} />}

      {error && (
        <div className="mt-4 w-full max-w-2xl bg-red-900/30 border border-red-800 rounded-lg p-4" style={{ borderColor: 'var(--border-primary)' }}>
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}
    </div>
  );
}
