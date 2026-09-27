/**
 * MITRE ATT&CK view: the curated knowledge base plus coverage analytics
 * (which techniques this platform has actually observed, and how often).
 */
import { useMemo, useState } from 'react';
import { api } from '../api/client';
import { useFetch } from '../api/AppContext';
import { Alert, EmptyState, ErrorState, Loading, Panel } from '../components/ui';
import { TACTIC_ORDER, formatRelative, tacticColour } from '../lib/format';

const COVERAGE_COLOURS = [
  { min: 3, colour: '#ef4444' },
  { min: 2, colour: '#f97316' },
  { min: 1, colour: '#eab308' },
  { min: 0, colour: '#1f2733' },
];

export const MitrePage = () => {
  const { data, error, loading, reload } = useFetch(() => api.mitre(), []);
  const [search, setSearch] = useState('');
  const [onlyObserved, setOnlyObserved] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const grouped = useMemo(() => {
    if (!data) return [];
    const q = search.trim().toLowerCase();
    const filtered = data.techniques.filter((t) => {
      if (onlyObserved && t.investigationCount === 0) return false;
      if (!q) return true;
      return (
        t.id.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.tactic.toLowerCase().includes(q) ||
        (t.description ?? '').toLowerCase().includes(q)
      );
    });
    return TACTIC_ORDER.map((tactic) => ({ tactic, techniques: filtered.filter((t) => t.tactic === tactic) })).filter(
      (g) => g.techniques.length > 0,
    );
  }, [data, search, onlyObserved]);

  if (loading) return <Loading label="Loading ATT&CK knowledge base" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return null;

  const observed = data.techniques.filter((t) => t.investigationCount > 0);
  const coverage = data.techniques.length ? (observed.length / data.techniques.length) * 100 : 0;

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-4">
        <div className="stat c-accent">
          <div className="stat-label">Techniques in knowledge base</div>
          <div className="stat-value">{data.total}</div>
          <div className="stat-sub">curated offline subset</div>
        </div>
        <div className="stat c-high">
          <div className="stat-label">Observed by this platform</div>
          <div className="stat-value">{observed.length}</div>
          <div className="stat-sub">at least one investigation</div>
        </div>
        <div className="stat c-medium">
          <div className="stat-label">Coverage</div>
          <div className="stat-value">{coverage.toFixed(0)}%</div>
          <div className="stat-sub">of the curated subset</div>
        </div>
        <div className="stat c-low">
          <div className="stat-label">ATT&amp;CK version</div>
          <div className="stat-value" style={{ fontSize: 15, paddingTop: 6 }}>
            {data.version}
          </div>
          <div className="stat-sub">
            <a href="https://attack.mitre.org/" target="_blank" rel="noreferrer noopener">
              attack.mitre.org ↗
            </a>
          </div>
        </div>
      </div>

      <Alert kind="info" title="How mapping works">
        ThreatLens ships a curated, offline subset of the ATT&amp;CK matrix rather than the full STIX bundle, so that every
        mapping decision is traceable to a documented rule. A technique is only asserted when an intelligence source
        published the technique id, when an identified malware family has that publicly documented behaviour, or when a
        behavioural rule matched the enriched intelligence. Each mapping records which of those produced it.
      </Alert>

      <Panel
        title={`Techniques by tactic (${grouped.reduce((a, g) => a + g.techniques.length, 0)} shown)`}
        actions={
          <>
            <input
              className="input"
              style={{ width: 220 }}
              placeholder="Search technique, tactic, text…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <button
              type="button"
              className={`chip-toggle ${onlyObserved ? 'on' : ''}`}
              onClick={() => setOnlyObserved((v) => !v)}
            >
              Only observed ({observed.length})
            </button>
          </>
        }
        bodyClass="tight"
      >
        {grouped.length === 0 ? (
          <EmptyState>No techniques match this filter.</EmptyState>
        ) : (
          <div className="flex flex-col gap-4" style={{ marginTop: 8 }}>
            {grouped.map((group) => (
              <div key={group.tactic} className="tactic-group">
                <div className="tactic-header">
                  <span className="tactic-bar" style={{ background: tacticColour(group.tactic) }} />
                  {group.tactic}
                  <span className="dim">({group.techniques.length})</span>
                </div>
                <div className="tech-grid">
                  {group.techniques.map((t) => {
                    const coverageColour = COVERAGE_COLOURS.find((c) => t.investigationCount >= c.min)?.colour ?? '#1f2733';
                    const isSelected = selected === t.id;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => setSelected(isSelected ? null : t.id)}
                        style={{
                          textAlign: 'left',
                          fontFamily: 'inherit',
                          color: 'inherit',
                          cursor: 'pointer',
                          background: isSelected ? 'var(--accent-bg)' : 'var(--bg-2)',
                          border: `1px solid ${isSelected ? 'var(--accent-dim)' : 'var(--line)'}`,
                          borderRadius: 'var(--radius-sm)',
                          padding: 11,
                        }}
                      >
                        <div className="flex items-center gap-2 wrap mb-2">
                          <span className="tech-id">{t.id}</span>
                          {t.isSubtechnique ? <span className="badge badge-neutral tiny">sub</span> : null}
                          <span className="grow" />
                          {t.investigationCount > 0 ? (
                            <span className="badge tiny" style={{ background: 'var(--bg-3)', color: coverageColour, borderColor: coverageColour }}>
                              {t.investigationCount} seen
                            </span>
                          ) : null}
                        </div>
                        <div className="tech-name mb-2">{t.name}</div>

                        {isSelected ? (
                          <div className="flex flex-col gap-2 mt-2">
                            {t.description ? <div className="tech-desc">{t.description}</div> : null}
                            {t.dataSources.length ? (
                              <div>
                                <div className="label">Data sources</div>
                                <div className="flex gap-2 wrap">
                                  {t.dataSources.map((s) => (
                                    <span key={s} className="tag tiny">
                                      {s}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            ) : null}
                            {t.platforms.length ? (
                              <div>
                                <div className="label">Platforms</div>
                                <div className="flex gap-2 wrap">
                                  {t.platforms.map((s) => (
                                    <span key={s} className="tag tiny">
                                      {s}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            ) : null}
                            <div className="flex gap-3 tiny dim">
                              <span>{t.tactics.join(', ')}</span>
                              {t.lastObserved ? <span>last observed {formatRelative(t.lastObserved)}</span> : null}
                            </div>
                            <a className="btn btn-sm btn-ghost" href={t.reference} target="_blank" rel="noreferrer noopener">
                              Open official page ↗
                            </a>
                          </div>
                        ) : null}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
};
