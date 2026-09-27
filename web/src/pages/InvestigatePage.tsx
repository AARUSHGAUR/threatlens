/**
 * Investigation console: submit an indicator, then stream the real pipeline
 * progress while it runs.
 *
 * Why polling instead of fake progress bars: POST /investigations returns
 * immediately with an investigation id, and GET /investigations/:id/progress
 * returns the accumulated timeline. What the analyst sees is therefore the
 * *actual* sequence of pipeline stages - a genuine CTI operations console
 * rather than a cosmetic loading animation.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiError, type ProgressResponse, type StartInvestigationResponse } from '../api/client';
import { useApp } from '../api/AppContext';
import { IocSearch } from '../components/IOCSearch';
import { Alert, Panel, RiskBadge } from '../components/ui';
import { formatDate } from '../lib/format';

const STAGES = [
  { key: 'validation', label: 'Validate', match: (k: string) => k === 'validation' },
  { key: 'enrichment', label: 'Enrich', match: (k: string) => k === 'provider' || k === 'provider-error' },
  { key: 'correlation', label: 'Correlate', match: (k: string) => k === 'correlation' },
  { key: 'scoring', label: 'Score', match: (k: string) => k === 'scoring' },
  { key: 'attack', label: 'ATT&CK', match: (k: string) => k === 'attack' },
  { key: 'done', label: 'Persist', match: (k: string) => k === 'investigation' },
];

const lineClass = (kind: string): string => {
  if (kind === 'provider-error') return 'err';
  if (kind === 'validation') return 'ok';
  if (kind === 'scoring' || kind === 'attack') return 'warn';
  return '';
};

export const InvestigatePage = () => {
  const { registry, demoMode } = useApp();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [started, setStarted] = useState<StartInvestigationResponse | null>(null);
  const [progress, setProgress] = useState<ProgressResponse | null>(null);
  const [error, setError] = useState<{ message: string; hint?: string } | null>(null);
  const [phase, setPhase] = useState<'idle' | 'starting' | 'running'>('idle');
  const [lastIndicator, setLastIndicator] = useState('');
  const consoleRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<number | null>(null);

  // Poll the investigation until it reaches a terminal state.
  useEffect(() => {
    if (phase !== 'running' || !started) return undefined;
    let cancelled = false;

    const tick = async () => {
      try {
        const result = await api.progress(started.investigationId);
        if (cancelled) return;
        setProgress(result);
        if (['completed', 'partial', 'failed'].includes(result.status)) {
          setPhase('idle');
          // Give the analyst a beat to read the final pipeline lines.
          window.setTimeout(() => navigate(`/investigation/${started.investigationId}`), 700);
          return;
        }
      } catch {
        if (!cancelled) {
          setError({ message: 'Lost contact with the investigation worker. Check the API.' });
          setPhase('idle');
          return;
        }
      }
      pollRef.current = window.setTimeout(tick, 500);
    };

    void tick();
    return () => {
      cancelled = true;
      if (pollRef.current) window.clearTimeout(pollRef.current);
    };
  }, [phase, started, navigate]);

  useEffect(() => {
    consoleRef.current?.scrollTo({ top: consoleRef.current.scrollHeight, behavior: 'smooth' });
  }, [progress]);

  const run = useCallback(
    async (indicator: string) => {
      setError(null);
      setProgress(null);
      setStarted(null);
      setLastIndicator(indicator);
      setPhase('starting');
      try {
        const result = await api.startInvestigation(indicator);
        setStarted(result);
        setPhase('running');
      } catch (err) {
        setPhase('idle');
        if (err instanceof ApiError) setError({ message: err.message, hint: err.hint });
        else setError({ message: 'The investigation could not be started.' });
      }
    },
    [],
  );

  // Deep link support: /investigate?q=<indicator> pre-fills and submits.
  const deepLink = searchParams.get('q');
  useEffect(() => {
    if (!deepLink) return;
    setSearchParams(new URLSearchParams(), { replace: true });
    void run(deepLink);
  }, [deepLink, run, setSearchParams]);

  const cancel = () => {
    if (pollRef.current) window.clearTimeout(pollRef.current);
    setPhase('idle');
    setProgress(null);
    setStarted(null);
  };

  // Index of the furthest stage the pipeline has reached.
  const events = progress?.timeline ?? [];
  const lastReached = STAGES.reduce((acc, stage, index) => (events.some((e) => stage.match(e.kind)) ? index : acc), -1);
  const busy = phase !== 'idle';

  return (
    <div className="flex flex-col gap-4">
      <IocSearch onSubmit={run} busy={busy} />

      {error ? (
        <Alert kind="danger" title="Investigation rejected">
          {error.message}
          {error.hint ? <div className="mt-2 small">{error.hint}</div> : null}
        </Alert>
      ) : null}

      {phase === 'starting' ? (
        <Panel title="Submitting indicator">
          <div className="flex items-center gap-3 small muted">
            <span className="spinner" />
            Validating <code className="inline-code">{lastIndicator}</code> and opening an investigation record…
          </div>
        </Panel>
      ) : null}

      {phase === 'running' && started ? (
        <div className="grid grid-2-1">
          <Panel
            title={
              <>
                Investigation console
                <span className="mono dim" style={{ marginLeft: 8, textTransform: 'none', letterSpacing: 0 }}>
                  {started.reference}
                </span>
              </>
            }
            actions={
              <>
                <span className="badge badge-accent">
                  <span className="pulse-dot" /> {progress?.status ?? 'starting'}
                </span>
                <button className="btn btn-sm btn-ghost" type="button" onClick={cancel}>
                  Stop watching
                </button>
              </>
            }
            bodyClass="flush"
          >
            <div className="panel-body">
              <div className="flex items-center gap-2 mb-3 wrap">
                <span className="mono" style={{ color: 'var(--ink-0)' }}>
                  {started.ioc.value}
                </span>
                <span className="badge badge-neutral">{started.ioc.typeLabel}</span>
                {started.mode === 'demo' ? <span className="badge badge-demo">DEMO DATA</span> : <span className="badge badge-clean">LIVE</span>}
              </div>
              <div className="stages mb-3">
                {STAGES.map((stage, index) => {
                  const done = index <= lastReached;
                  const active = index === lastReached + 1;
                  return (
                    <span key={stage.key} className={`stage ${done ? 'done' : ''} ${active ? 'active' : ''}`}>
                      {done ? (
                        <span style={{ color: 'var(--clean)' }}>✓</span>
                      ) : (
                        <span className="badge-dot" style={{ background: active ? 'var(--accent)' : 'var(--ink-3)' }} />
                      )}
                      {stage.label}
                    </span>
                  );
                })}
              </div>
            </div>
            <div className="console" ref={consoleRef}>
              {(progress?.timeline ?? []).map((event) => (
                <div key={event.seq} className={`console-line ${lineClass(event.kind)}`}>
                  <span className="t">{new Date(event.at).toLocaleTimeString()}</span>
                  <span className="m">
                    <span style={{ color: 'var(--accent)' }}>[{event.kind.toUpperCase()}]</span> {event.title}
                    {event.source ? <span className="dim"> · {event.source}</span> : null}
                    {event.description ? <div className="dim" style={{ fontSize: 11 }}>{event.description}</div> : null}
                  </span>
                </div>
              ))}
              {progress ? (
                <div className="console-line">
                  <span className="t" />
                  <span className="m">
                    <span className="console-cursor" />
                  </span>
                </div>
              ) : (
                <div className="console-line">
                  <span className="t" />
                  <span className="m dim">connecting to pipeline…</span>
                </div>
              )}
            </div>
          </Panel>

          <div className="flex flex-col gap-3">
            <Panel title="Pipeline">
              <dl className="kv">
                <dt>Reference</dt>
                <dd className="mono">{started.reference}</dd>
                <dt>Status</dt>
                <dd>{progress?.status ?? '—'}</dd>
                <dt>Mode</dt>
                <dd>{started.mode === 'demo' ? 'DEMO MODE (simulated)' : 'LIVE INTELLIGENCE'}</dd>
                <dt>Events</dt>
                <dd className="mono">{progress?.timeline.length ?? 0}</dd>
                {progress?.riskScore !== null && progress?.riskScore !== undefined ? (
                  <>
                    <dt>Risk</dt>
                    <dd className="flex items-center gap-2">
                      <span className="mono">{progress.riskScore}/100</span>
                      {progress.riskLevel ? <RiskBadge level={progress.riskLevel} size="sm" /> : null}
                    </dd>
                  </>
                ) : null}
              </dl>
            </Panel>

            {started.warnings.length ? (
              <Panel title="Validation warnings">
                <div className="flex flex-col gap-2">
                  {started.warnings.map((w) => (
                    <Alert key={w.code} kind="warning">
                      <strong className="mono">{w.code}</strong> — {w.message}
                    </Alert>
                  ))}
                </div>
              </Panel>
            ) : null}

            <Panel title="What happens next">
              <ol className="small muted" style={{ paddingLeft: 18, margin: 0, lineHeight: 1.8 }}>
                <li>Type detection and validation of the indicator</li>
                <li>Enrichment across {registry?.providers.length ?? 0} configured source(s)</li>
                <li>Correlation into a typed entity graph</li>
                <li>Explainable risk scoring and ATT&amp;CK mapping</li>
                <li>Persisted evidence, timeline and report generation</li>
              </ol>
              <div className="tiny dim mt-3">Started {formatDate(new Date().toISOString())}</div>
            </Panel>
          </div>
        </div>
      ) : null}

      {phase === 'idle' && !error && !started ? (
        <div className="grid grid-3">
          <Panel title="1 · Collect">
            <p className="small muted">
              The analyst supplies an indicator. ThreatLens normalises it (defanged values are re-fanged, URLs and hashes
              are canonicalised) and stores it as a reusable indicator entity, so re-investigating the same value keeps
              one indicator record with many intelligence snapshots.
            </p>
          </Panel>
          <Panel title="2 · Enrich &amp; correlate">
            <p className="small muted">
              Every applicable provider is queried in parallel with per-provider throttling and error isolation. Results
              are merged with field-level provenance, and indicator-to-indicator relationships are recorded so future
              investigations inherit the platform&apos;s correlation memory.
            </p>
          </Panel>
          <Panel title="3 · Assess &amp; produce">
            <p className="small muted">
              A deterministic engine scores risk 0-100 and shows every contributing factor. Behavioural evidence is mapped
              to MITRE ATT&amp;CK, defensive actions are generated, and a full report is available as PDF or JSON.
            </p>
          </Panel>
        </div>
      ) : null}

      {demoMode ? (
        <div className="tiny dim">
          Demo mode is active, so this investigation will use the built-in fictional dataset
          {registry?.hasLiveKeys ? ' even though provider keys are present (switch mode in Settings to query live sources).' : '.'}
        </div>
      ) : null}
    </div>
  );
};
