import { useState, useEffect } from 'react';

const STORAGE_KEY = 'skg-welcome-dismissed';

interface Props {
  onDismiss: () => void;
}

const TIPS = [
  {
    icon: '\u{1F50D}',
    title: 'Explore the Graph',
    desc: 'Click any node to select it. Hover to highlight its connections. Scroll to zoom, drag to pan.',
  },
  {
    icon: '\u{1F5B1}',
    title: 'Right-Click for Actions',
    desc: 'Right-click any node for Deep Dive analysis, connection tracing, CVE lookup, and more.',
  },
  {
    icon: '\u{1F4CB}',
    title: 'Findings Panel',
    desc: 'The right panel lists all security findings sorted by severity. Expand any finding for remediation steps.',
  },
  {
    icon: '\u{1F3AF}',
    title: 'Filter & Focus',
    desc: 'Use the filter bar to show/hide node types. "Focus" mode hides noise and shows only high-signal nodes.',
  },
  {
    icon: '\u{2728}',
    title: 'AI Remediation',
    desc: 'Click the gear icon to configure your AI provider, then get tailored fix suggestions for any finding.',
  },
];

export function shouldShowWelcome(): boolean {
  return !localStorage.getItem(STORAGE_KEY);
}

export function dismissWelcome() {
  localStorage.setItem(STORAGE_KEY, '1');
}

export default function WelcomeOverlay({ onDismiss }: Props) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onDismiss();
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [onDismiss]);

  const handleNext = () => {
    if (step < TIPS.length - 1) {
      setStep(step + 1);
    } else {
      onDismiss();
    }
  };

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
        className="border rounded-xl w-full max-w-lg mx-4 shadow-2xl overflow-hidden"
        style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        {/* Header */}
        <div className="px-6 pt-6 pb-4">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 bg-blue-600 rounded-lg flex items-center justify-center text-lg">
              {'\u{1F6E1}'}
            </div>
            <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
              Quick Start Guide
            </h2>
          </div>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            Here are a few tips to get the most out of your security scan.
          </p>
        </div>

        {/* Tip card */}
        <div className="px-6 pb-4">
          <div
            className="rounded-lg p-5 border"
            style={{ background: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
          >
            <div className="flex items-start gap-4">
              <span className="text-2xl shrink-0 mt-0.5">{TIPS[step].icon}</span>
              <div>
                <h3 className="font-semibold text-sm mb-1" style={{ color: 'var(--text-primary)' }}>
                  {TIPS[step].title}
                </h3>
                <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  {TIPS[step].desc}
                </p>
              </div>
            </div>
          </div>

          {/* Progress dots */}
          <div className="flex items-center justify-center gap-1.5 mt-4">
            {TIPS.map((_, i) => (
              <button
                key={i}
                onClick={() => setStep(i)}
                className="w-2 h-2 rounded-full transition-all"
                style={{
                  background: i === step ? '#3B82F6' : 'var(--text-muted)',
                  opacity: i === step ? 1 : 0.3,
                  width: i === step ? 16 : 8,
                }}
              />
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t flex items-center justify-between" style={{ borderColor: 'var(--border-primary)' }}>
          <button
            onClick={onDismiss}
            className="text-sm transition-colors"
            style={{ color: 'var(--text-muted)' }}
          >
            Skip
          </button>
          <div className="flex items-center gap-3">
            {step > 0 && (
              <button
                onClick={() => setStep(step - 1)}
                className="px-4 py-2 rounded-lg text-sm transition-colors"
                style={{ color: 'var(--text-secondary)' }}
              >
                Back
              </button>
            )}
            <button
              onClick={handleNext}
              className="px-5 py-2 rounded-lg text-sm bg-blue-600 hover:bg-blue-700 text-white font-medium transition-colors"
            >
              {step === TIPS.length - 1 ? 'Get Started' : 'Next'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
