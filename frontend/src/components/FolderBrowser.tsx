import { useState, useEffect, useCallback } from 'react';
import { browsePath, type DirEntry } from '../api/client';

interface Props {
  open: boolean;
  onClose: () => void;
  onSelect: (path: string) => void;
}

export default function FolderBrowser({ open, onClose, onSelect }: Props) {
  const [currentPath, setCurrentPath] = useState('');
  const [parentPath, setParentPath] = useState<string | null>(null);
  const [entries, setEntries] = useState<DirEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [manualPath, setManualPath] = useState('');

  const loadDir = useCallback(async (path: string) => {
    setLoading(true);
    setError('');
    try {
      const res = await browsePath(path);
      setCurrentPath(res.current);
      setParentPath(res.parent);
      setEntries(res.entries);
      setManualPath(res.current);
    } catch {
      setError('Failed to load directory');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      loadDir('~');
    }
  }, [open, loadDir]);

  if (!open) return null;

  const dirs = entries.filter((e) => e.is_dir);

  const handleNavigate = (path: string) => {
    loadDir(path);
  };

  const handleSelect = () => {
    onSelect(currentPath);
    onClose();
  };

  const handleManualGo = (e: React.FormEvent) => {
    e.preventDefault();
    if (manualPath.trim()) {
      loadDir(manualPath.trim());
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
        className="border rounded-xl w-full max-w-lg mx-4 shadow-2xl flex flex-col max-h-[80vh]"
        style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <h2 className="font-semibold text-lg" style={{ color: 'var(--text-primary)' }}>Select Folder</h2>
          <button
            onClick={onClose}
            className="text-xl leading-none transition-colors"
            style={{ color: 'var(--text-muted)' }}
          >
            &times;
          </button>
        </div>

        {/* Path bar */}
        <form onSubmit={handleManualGo} className="px-5 pt-4 flex gap-2">
          <input
            type="text"
            value={manualPath}
            onChange={(e) => setManualPath(e.target.value)}
            className="flex-1 border rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
            style={{ background: 'var(--bg-input)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
          />
          <button
            type="submit"
            className="px-3 py-2 rounded-lg text-sm transition-colors"
            style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
          >
            Go
          </button>
        </form>

        {/* Directory listing */}
        <div className="flex-1 overflow-y-auto styled-scrollbar px-5 py-3 min-h-0">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : error ? (
            <p className="text-red-400 text-sm text-center py-4">{error}</p>
          ) : (
            <div className="space-y-0.5">
              {parentPath && (
                <button
                  onClick={() => handleNavigate(parentPath)}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-blue-400 transition-colors text-left"
                  style={{ background: 'transparent' }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  <span className="text-base">&#x2190;</span>
                  <span>..</span>
                </button>
              )}
              {dirs.length === 0 && !parentPath && (
                <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>No subdirectories found</p>
              )}
              {dirs.map((entry) => (
                <button
                  key={entry.path}
                  onClick={() => handleNavigate(entry.path)}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors text-left"
                  style={{ color: 'var(--text-primary)', background: 'transparent' }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  <span className="text-yellow-400 text-base">&#x1F4C1;</span>
                  <span className="truncate">{entry.name}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t flex items-center justify-between gap-3" style={{ borderColor: 'var(--border-primary)' }}>
          <p className="text-xs truncate flex-1 font-mono" style={{ color: 'var(--text-muted)' }}>{currentPath}</p>
          <div className="flex gap-2 shrink-0">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-sm transition-colors"
              style={{ color: 'var(--text-secondary)', background: 'transparent' }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
            >
              Cancel
            </button>
            <button
              onClick={handleSelect}
              disabled={!currentPath}
              className="px-4 py-2 rounded-lg text-sm bg-blue-600 hover:bg-blue-700 text-white font-medium transition-colors disabled:opacity-50"
            >
              Select This Folder
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
