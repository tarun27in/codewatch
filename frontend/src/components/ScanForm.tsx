import { useState, useRef } from 'react';
import { useTheme } from '../hooks/useTheme';
import FolderBrowser from './FolderBrowser';
import { parseImportedFile } from '../utils/importReport';

interface Props {
  onScan: (path?: string, githubUrl?: string) => void;
  loading: boolean;
  onImport?: (data: { scan_path?: string; scanPath?: string; stats: unknown; nodes: unknown[]; edges: unknown[] }) => void;
}

export default function ScanForm({ onScan, loading, onImport }: Props) {
  const { theme, toggleTheme } = useTheme();
  const [mode, setMode] = useState<'local' | 'github'>('local');
  const [path, setPath] = useState('');
  const [githubUrl, setGithubUrl] = useState('');
  const [browseOpen, setBrowseOpen] = useState(false);
  const [importError, setImportError] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mode === 'local' && path.trim()) {
      onScan(path.trim(), undefined);
    } else if (mode === 'github' && githubUrl.trim()) {
      onScan(undefined, githubUrl.trim());
    }
  };

  const handleFolderSelect = (selectedPath: string) => {
    setPath(selectedPath);
  };

  const handleImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError('');
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = parseImportedFile(reader.result as string, file.name);
        onImport?.(data);
      } catch (err) {
        setImportError(err instanceof Error ? err.message : 'Failed to parse report file');
      }
    };
    reader.readAsText(file);
    // Reset input so the same file can be re-imported
    e.target.value = '';
  };

  return (
    <>
      <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
        <div
          className="border rounded-xl p-6 shadow-2xl relative"
          style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
        >
          {/* Theme toggle */}
          <button
            type="button"
            onClick={toggleTheme}
            className="absolute top-4 right-4 w-8 h-8 rounded-lg flex items-center justify-center text-lg transition-colors"
            style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? '\u2600\uFE0F' : '\uD83C\uDF19'}
          </button>

          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center text-xl">
              &#x1F6E1;
            </div>
            <div>
              <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Security Knowledge Graph</h1>
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>Scan any codebase to visualize its security posture</p>
            </div>
          </div>

          {/* Mode tabs */}
          <div className="flex gap-1 rounded-lg p-1 mb-4" style={{ background: 'var(--bg-tertiary)' }}>
            <button
              type="button"
              onClick={() => setMode('local')}
              className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                mode === 'local'
                  ? 'bg-blue-600 text-white'
                  : ''
              }`}
              style={mode !== 'local' ? { color: 'var(--text-secondary)' } : undefined}
            >
              Local Folder
            </button>
            <button
              type="button"
              onClick={() => setMode('github')}
              className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                mode === 'github'
                  ? 'bg-blue-600 text-white'
                  : ''
              }`}
              style={mode !== 'github' ? { color: 'var(--text-secondary)' } : undefined}
            >
              GitHub URL
            </button>
          </div>

          {/* Input */}
          {mode === 'local' ? (
            <div className="flex gap-2">
              <input
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/path/to/your/project"
                className="flex-1 border rounded-lg px-4 py-3 placeholder-gray-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono text-sm"
                style={{ background: 'var(--bg-input)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
              />
              <button
                type="button"
                onClick={() => setBrowseOpen(true)}
                className="px-4 py-3 rounded-lg text-sm font-medium transition-colors border shrink-0 flex items-center gap-1.5"
                style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
              >
                <span>&#x1F4C2;</span>
                Browse
              </button>
            </div>
          ) : (
            <input
              type="text"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="w-full border rounded-lg px-4 py-3 placeholder-gray-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono text-sm"
              style={{ background: 'var(--bg-input)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
            />
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={loading || (mode === 'local' ? !path.trim() : !githubUrl.trim())}
            className="mt-4 w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold py-3 px-6 rounded-lg transition-colors"
          >
            {loading ? 'Scanning...' : 'Scan Codebase'}
          </button>

          {/* Import previous report */}
          {onImport && (
            <div className="mt-3 flex items-center justify-center gap-2">
              <div className="flex-1 h-px" style={{ background: 'var(--border-primary)' }} />
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>or</span>
              <div className="flex-1 h-px" style={{ background: 'var(--border-primary)' }} />
            </div>
          )}
          {onImport && (
            <>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="mt-3 w-full border rounded-lg py-2.5 px-4 text-sm font-medium transition-colors flex items-center justify-center gap-2"
                style={{ background: 'transparent', color: 'var(--text-secondary)', borderColor: 'var(--border-primary)' }}
              >
                <span>&#x1F4E5;</span>
                Import Previous Report
              </button>
              <p className="mt-1.5 text-[10px] text-center" style={{ color: 'var(--text-muted)' }}>
                Supports JSON, SARIF, and Markdown formats
              </p>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.sarif,.md,.markdown"
                onChange={handleImport}
                className="hidden"
              />
            </>
          )}
          {importError && (
            <p className="mt-2 text-xs text-red-400 text-center">{importError}</p>
          )}

          {/* Privacy notice */}
          <div
            className="mt-4 rounded-lg px-4 py-3 flex items-start gap-2.5"
            style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-primary)' }}
          >
            <span className="text-sm shrink-0 mt-0.5">{'\uD83D\uDD12'}</span>
            <div>
              <p className="text-xs font-semibold mb-0.5" style={{ color: 'var(--text-primary)' }}>
                Your code stays private
              </p>
              <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                No database, no disk storage, no logging of your source code.
                Scan results are held in server memory only &mdash; click &ldquo;Clear &amp; Exit&rdquo; in the graph view to delete all data from the server when you&rsquo;re done.
                AI remediation (optional) sends finding details to your configured LLM provider.
              </p>
            </div>
          </div>
        </div>
      </form>

      <FolderBrowser
        open={browseOpen}
        onClose={() => setBrowseOpen(false)}
        onSelect={handleFolderSelect}
      />
    </>
  );
}
