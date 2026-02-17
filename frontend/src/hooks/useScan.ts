import { useState, useRef, useCallback, useEffect } from 'react';
import { startScan, getScanStatus, getGraph, deleteScan } from '../api/client';
import type { ScanResult, SecurityGraph } from '../types/graph';

const STORAGE_KEY = 'skg-last-scan';

function persistScan(scanPath: string, graph: SecurityGraph) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ scanPath, graph }));
  } catch {
    // sessionStorage full or unavailable — ignore
  }
}

function loadPersistedScan(): { scanPath: string; graph: SecurityGraph } | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const data = JSON.parse(raw);
    if (data && data.graph && data.scanPath) return data;
  } catch {
    // corrupted data — ignore
  }
  return null;
}

function clearPersistedScan() {
  sessionStorage.removeItem(STORAGE_KEY);
}

export function useScan() {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [graph, setGraph] = useState<SecurityGraph | null>(null);
  const [scanPath, setScanPath] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const restoredRef = useRef(false);

  // On mount, restore last scan from sessionStorage
  useEffect(() => {
    if (restoredRef.current) return;
    restoredRef.current = true;

    const persisted = loadPersistedScan();
    if (persisted) {
      setGraph(persisted.graph);
      setScanPath(persisted.scanPath);
    }
  }, []);

  const stopPolling = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  const launch = useCallback(async (path?: string, githubUrl?: string) => {
    setLoading(true);
    setError(null);
    setGraph(null);
    stopPolling();

    try {
      const result = await startScan(path, githubUrl);
      setScan(result);
      setScanPath(result.scan_path || path || githubUrl || null);

      // Poll for status
      intervalRef.current = setInterval(async () => {
        try {
          const status = await getScanStatus(result.scan_id);
          setScan(status);

          if (status.status === 'complete') {
            stopPolling();
            const graphData = await getGraph(result.scan_id);
            setGraph(graphData);
            setLoading(false);
            // Persist for refresh survival
            const sp = result.scan_path || path || githubUrl || '';
            persistScan(sp, graphData);
          } else if (status.status === 'error') {
            stopPolling();
            setError(status.error || status.message);
            setLoading(false);
          }
        } catch (e) {
          stopPolling();
          setError(e instanceof Error ? e.message : 'Polling failed');
          setLoading(false);
        }
      }, 500);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to start scan');
      setLoading(false);
    }
  }, [stopPolling]);

  const reset = useCallback(() => {
    stopPolling();
    setScan(null);
    setGraph(null);
    setScanPath(null);
    setLoading(false);
    setError(null);
    clearPersistedScan();
  }, [stopPolling]);

  const clearAndExit = useCallback(() => {
    // Delete server-side data, then reset
    if (scan?.scan_id) {
      deleteScan(scan.scan_id).catch(() => {});
    }
    reset();
  }, [scan, reset]);

  const rescan = useCallback(async () => {
    if (!scanPath || scanPath === 'imported') return;
    setLoading(true);
    setError(null);
    stopPolling();
    // Keep the current graph visible while rescanning

    try {
      const result = await startScan(scanPath);
      setScan(result);

      intervalRef.current = setInterval(async () => {
        try {
          const status = await getScanStatus(result.scan_id);
          setScan(status);

          if (status.status === 'complete') {
            stopPolling();
            const graphData = await getGraph(result.scan_id);
            setGraph(graphData);
            setLoading(false);
            persistScan(scanPath, graphData);
          } else if (status.status === 'error') {
            stopPolling();
            setError(status.error || status.message);
            setLoading(false);
          }
        } catch (e) {
          stopPolling();
          setError(e instanceof Error ? e.message : 'Polling failed');
          setLoading(false);
        }
      }, 500);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to start rescan');
      setLoading(false);
    }
  }, [scanPath, stopPolling]);

  const loadFromJSON = useCallback((data: { scan_path?: string; scanPath?: string; stats: unknown; nodes: unknown[]; edges: unknown[] }) => {
    const imported: SecurityGraph = {
      nodes: data.nodes as SecurityGraph['nodes'],
      edges: data.edges as SecurityGraph['edges'],
      stats: data.stats as SecurityGraph['stats'],
    };
    const path = data.scan_path || data.scanPath || 'imported';
    setGraph(imported);
    setScanPath(path);
    setError(null);
    setLoading(false);
    persistScan(path, imported);
  }, []);

  return { scan, graph, scanPath, loading, error, launch, reset, rescan, clearAndExit, loadFromJSON };
}
