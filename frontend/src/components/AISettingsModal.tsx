import { useState, useEffect } from 'react';

export type ProviderKey = 'anthropic' | 'openai' | 'google';

export interface ProviderConfig {
  model: string;
  apiKey: string;
}

export interface AISettings {
  provider: ProviderKey;
  model: string;
  apiKey: string;
}

/** Full multi-provider storage format */
interface AISettingsStore {
  activeProvider: ProviderKey;
  providers: Record<ProviderKey, ProviderConfig>;
}

const STORAGE_KEY = 'skg-ai-settings';

const PROVIDER_MODELS: Record<string, { label: string; models: { id: string; label: string }[] }> = {
  anthropic: {
    label: 'Anthropic (Claude)',
    models: [
      { id: 'claude-opus-4-6', label: 'Claude Opus 4.6' },
      { id: 'claude-sonnet-4-5-20250929', label: 'Claude Sonnet 4.5' },
      { id: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5' },
    ],
  },
  openai: {
    label: 'OpenAI (GPT)',
    models: [
      { id: 'gpt-5.2', label: 'GPT-5.2' },
      { id: 'gpt-5.2-pro', label: 'GPT-5.2 Pro' },
      { id: 'gpt-5.1', label: 'GPT-5.1' },
      { id: 'gpt-5-mini', label: 'GPT-5 Mini' },
      { id: 'o3', label: 'o3' },
      { id: 'o4-mini', label: 'o4 Mini' },
      { id: 'gpt-4.1', label: 'GPT-4.1' },
      { id: 'gpt-4.1-mini', label: 'GPT-4.1 Mini' },
      { id: 'gpt-4o', label: 'GPT-4o' },
    ],
  },
  google: {
    label: 'Google (Gemini)',
    models: [
      { id: 'gemini-3-pro-preview', label: 'Gemini 3 Pro (Preview)' },
      { id: 'gemini-3-flash-preview', label: 'Gemini 3 Flash (Preview)' },
      { id: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro' },
      { id: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash' },
      { id: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash' },
    ],
  },
};

const DEFAULT_STORE: AISettingsStore = {
  activeProvider: 'anthropic',
  providers: {
    anthropic: { model: 'claude-opus-4-6', apiKey: '' },
    openai: { model: 'gpt-5.2', apiKey: '' },
    google: { model: 'gemini-2.5-pro', apiKey: '' },
  },
};

function loadStore(): AISettingsStore {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_STORE };
    const data = JSON.parse(raw);
    // Migrate old single-provider format
    if (data && data.provider && data.apiKey && !data.providers) {
      const store: AISettingsStore = { ...DEFAULT_STORE, activeProvider: data.provider };
      store.providers[data.provider as ProviderKey] = { model: data.model, apiKey: data.apiKey };
      return store;
    }
    if (data && data.providers) return data as AISettingsStore;
  } catch { /* ignore */ }
  return { ...DEFAULT_STORE };
}

function saveStore(store: AISettingsStore) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

/** Public API — returns the active provider's settings (used by remediation calls) */
export function loadAISettings(): AISettings | null {
  const store = loadStore();
  const cfg = store.providers[store.activeProvider];
  if (!cfg?.apiKey) return null;
  return { provider: store.activeProvider, model: cfg.model, apiKey: cfg.apiKey };
}

export function saveAISettings(settings: AISettings) {
  const store = loadStore();
  store.activeProvider = settings.provider;
  store.providers[settings.provider] = { model: settings.model, apiKey: settings.apiKey };
  saveStore(store);
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function AISettingsModal({ open, onClose }: Props) {
  const [store, setStore] = useState<AISettingsStore>(DEFAULT_STORE);
  const [provider, setProvider] = useState<ProviderKey>('anthropic');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (open) {
      const s = loadStore();
      setStore(s);
      setProvider(s.activeProvider);
      setSaved(false);
    }
  }, [open]);

  const currentConfig = store.providers[provider];
  const model = currentConfig.model;
  const apiKey = currentConfig.apiKey;

  // When provider changes, switch to that provider's stored config (preserves keys)
  const handleProviderChange = (p: ProviderKey) => {
    setProvider(p);
  };

  const handleModelChange = (m: string) => {
    setStore((prev) => ({
      ...prev,
      providers: { ...prev.providers, [provider]: { ...prev.providers[provider], model: m } },
    }));
  };

  const handleApiKeyChange = (key: string) => {
    setStore((prev) => ({
      ...prev,
      providers: { ...prev.providers, [provider]: { ...prev.providers[provider], apiKey: key } },
    }));
  };

  const handleSave = () => {
    const updated = { ...store, activeProvider: provider };
    saveStore(updated);
    setSaved(true);
    setTimeout(() => onClose(), 600);
  };

  // Count configured providers for the badge
  const configuredCount = Object.values(store.providers).filter((c) => c.apiKey.trim()).length;

  if (!open) return null;

  const currentModels = PROVIDER_MODELS[provider].models;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
        className="border rounded-xl w-full max-w-md mx-4 shadow-2xl"
        style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <h2 className="font-semibold text-lg" style={{ color: 'var(--text-primary)' }}>AI Remediation Settings</h2>
          <button
            onClick={onClose}
            className="text-xl leading-none transition-colors"
            style={{ color: 'var(--text-muted)' }}
          >
            &times;
          </button>
        </div>

        <div className="px-5 py-5 space-y-5">
          {/* Provider */}
          <div>
            <label className="block text-xs uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
              Provider
            </label>
            <div className="flex gap-1 rounded-lg p-1" style={{ background: 'var(--bg-tertiary)' }}>
              {Object.entries(PROVIDER_MODELS).map(([key, { label }]) => {
                const hasKey = store.providers[key as ProviderKey]?.apiKey?.trim();
                return (
                  <button
                    key={key}
                    onClick={() => handleProviderChange(key as ProviderKey)}
                    className={`flex-1 px-3 py-2 rounded-md text-xs font-medium transition-colors relative ${
                      provider === key ? 'bg-blue-600 text-white' : ''
                    }`}
                    style={provider !== key ? { color: 'var(--text-secondary)' } : undefined}
                  >
                    {label}
                    {hasKey && (
                      <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-green-500" title="API key configured" />
                    )}
                  </button>
                );
              })}
            </div>
            {configuredCount > 0 && (
              <p className="text-[10px] mt-1.5" style={{ color: 'var(--text-muted)' }}>
                {configuredCount} provider{configuredCount !== 1 ? 's' : ''} configured &mdash; the selected provider will be used for AI remediation.
              </p>
            )}
          </div>

          {/* Model */}
          <div>
            <label className="block text-xs uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
              Model
            </label>
            <select
              value={model}
              onChange={(e) => handleModelChange(e.target.value)}
              className="w-full border rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue-500"
              style={{ background: 'var(--bg-input)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
            >
              {currentModels.map((m) => (
                <option key={m.id} value={m.id}>{m.label}</option>
              ))}
            </select>
          </div>

          {/* API Key */}
          <div>
            <label className="block text-xs uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
              API Key
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => handleApiKeyChange(e.target.value)}
              placeholder={provider === 'anthropic' ? 'sk-ant-...' : provider === 'openai' ? 'sk-...' : 'AIza...'}
              className="w-full border rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-blue-500"
              style={{ background: 'var(--bg-input)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
            />
            <p className="mt-1.5 text-[10px]" style={{ color: 'var(--text-muted)' }}>
              Your key is stored locally in your browser and sent per-request. It is never stored on the server.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-4 border-t flex items-center justify-end gap-3" style={{ borderColor: 'var(--border-primary)' }}>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm transition-colors"
            style={{ color: 'var(--text-secondary)' }}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={!apiKey?.trim()}
            className="px-5 py-2 rounded-lg text-sm bg-blue-600 hover:bg-blue-700 text-white font-medium transition-colors disabled:opacity-50"
          >
            {saved ? 'Saved!' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}
