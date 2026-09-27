/**
 * Investigation result page (`/investigation/:id`).
 *
 * This is the analyst workbench: the indicator header, the risk verdict with
 * its full explanation, per-source enrichment evidence, the correlation graph,
 * ATT&CK mappings, the timeline, defensive actions and the report generator.
 * Everything is read from the stored investigation - opening a historical result
 * never re-queries a provider.
 */
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { useApp, useFetch } from '../api/AppContext';
import { Alert, CopyButton, DemoBadge, ErrorState, IocTypeBadge, KV, Loading, Panel, PanelFlush, RiskBadge, StatusBadge, VerdictBadge } from '../components/ui';
import { RiskScoreCard, RiskBreakdown } from '../components/RiskScoreCard';
import { EnrichmentPanel, NetworkIntelCard, ReputationCard, ThreatIntelPanel } from '../components/EnrichmentCards';
import { MITRETechniqueList } from '../components/MITRETechniqueCard';
import { InvestigationTimeline } from '../components/InvestigationTimeline';
import { IOCRelationshipGraph } from '../components/IOCRelationshipGraph';
import { RecommendationsPanel, ReportGenerator, VerdictStrip } from '../components/ReportGenerator';
import { IocSearch } from '../components/IOCSearch';
import { formatDate, formatDuration, formatRelative } from '../lib/format';
import type { InvestigationDetail as Detail } from '../api/client';

const TABS = [
  { id: 'summary', label: 'Summary' },
  { id: 'intelligence', label: 'Intelligence' },
  { id: 'correlation', label: 'Correlation' },
  { id: 'attack', label: 'ATT&CK' },
  { id: 'actions', label: 'Defensive actions' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'report', label: 'Report' },
] as const;

type TabId = (typeof TABS)[number]['id'];

export const InvestigationPage = () => {
  const { id } = useParams();
  const investigationId = Number.parseInt(id ?? '', 10);
  const navigate = useNavigate();
  const { demoMode } = useApp();
  const [tab, setTab] = useState<TabId>('summary');
  const [reanalysing, setReanalysing] = useState(false);
  const [notes, setNotes] = useState<string | null>(null);
  const [rating, setRating] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const { data, error, loading, reload } = useFetch<Detail>(
    () => (Number.isFinite(investigationId) ? api.investigation(investigationId) : Promise.reject(new Error('Invalid investigation id'))),
    [investigationId],
  );

  if (loading) return <Loading label="Loading investigation" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return null;

  const d = data;
  const insufficient = d.counts.ok === 0;

  const reanalyse = async () => {
    setReanalysing(true);
    try {
      const result = await api.reanalyse(d.id);
      navigate(`/investigation/${result.investigationId}`);
    } finally {
      setReanalysing(false);
    }
  };

  const saveNotes = async () => {
    setSaving(true);
    try {
      await api.saveAnalystNotes(d.id, { notes, rating });
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* ---------------------------------------------------------- header */}
      <section className="result-hero">
        <div className="flex items-start justify-between gap-3 wrap">
          <div className="grow" style={{ minWidth: 260 }}>
            <div className="flex items-center gap-2 wrap mb-2">
              <span className="mono tiny dim">{d.reference}</span>
              <StatusBadge status={d.status} />
              {d.mode === 'demo' ? <DemoBadge /> : <span className="badge badge-clean">LIVE INTELLIGENCE</span>}
              {d.ioc.isDocumentation ? <span className="badge badge-neutral">documentation range</span> : null}
            </div>
            <div className="ioc-hero-value">{d.ioc.value}</div>
            <div className="flex items-center gap-2 mt-2 wrap">
              <IocTypeBadge type={d.ioc.type} />
              <span className="small muted">{d.ioc.description}</span>
              <CopyButton value={d.ioc.value} label="Copy IOC" />
            </div>
          </div>
          <div className="flex gap-2">
            <button className="btn btn-sm" type="button" onClick={reanalyse} disabled={reanalysing} title="Run a fresh investigation and open it">
              {reanalysing ? <span className="spinner" /> : <span aria-hidden="true">↻</span>} Re-analyse
            </button>
            <Link to="/history" className="btn btn-sm btn-ghost">
              History
            </Link>
          </div>
        </div>

        <div className="hero-metrics">
          <div>
            <div className="hero-metric-label">IOC type</div>
            <div className="hero-metric-value">{d.ioc.typeLabel}</div>
          </div>
          <div>
            <div className="hero-metric-label">Risk score</div>
            <div className="hero-metric-value">
              {insufficient ? '—' : d.assessment.score}
              <span className="dim" style={{ fontSize: 12 }}>
                /100
              </span>
            </div>
          </div>
          <div>
            <div className="hero-metric-label">Risk level</div>
            <div className="hero-metric-value">{insufficient ? <span className="badge badge-unknown">INSUFFICIENT</span> : <RiskBadge level={d.assessment.level} />}</div>
          </div>
          <div>
            <div className="hero-metric-label">Confidence</div>
            <div className="hero-metric-value">
              {d.assessment.confidenceScore}% <span className="dim" style={{ fontSize: 11 }}>({d.assessment.confidenceLabel})</span>
            </div>
          </div>
          <div>
            <div className="hero-metric-label">Verdict</div>
            <div className="hero-metric-value">
              <VerdictBadge verdict={d.assessment.verdict} />
            </div>
          </div>
          <div>
            <div className="hero-metric-label">Investigated</div>
            <div className="hero-metric-value" style={{ fontSize: 12 }}>
              {formatRelative(d.createdAt)}
            </div>
          </div>
        </div>

        <div className="mt-3">
          <VerdictStrip detail={d} />
        </div>
      </section>

      {d.status === 'failed' ? (
        <Alert kind="danger" title="Investigation did not complete">
          {d.status === 'failed'
            ? 'No intelligence source returned usable data, so no risk score was assigned. Review the per-source errors in the Intelligence tab, then re-analyse once the providers are reachable.'
            : ''}
        </Alert>
      ) : null}

      {d.demo ? (
        <Alert kind="demo" title={`DEMO DATA — ${d.demo.title}`} icon="◈">
          {d.demo.summary}
          <div className="small mt-2" style={{ fontStyle: 'italic' }}>
            Analyst note: {d.demo.analystNote}
          </div>
        </Alert>
      ) : null}

      {d.warnings.length > 0 ? (
        <div className="flex flex-col gap-2">
          {d.warnings.map((w) => (
            <Alert key={w.code} kind="warning">
              <strong className="mono">{w.code}</strong> — {w.message}
            </Alert>
          ))}
        </div>
      ) : null}

      {/* ----------------------------------------------------------- tabs */}
      <div className="flex gap-2 wrap" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={`chip-toggle ${tab === t.id ? 'on' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.id === 'attack' && d.techniques.length > 0 ? ` (${d.techniques.length})` : ''}
            {t.id === 'correlation' ? ` (${d.graph.nodes.length})` : ''}
            {t.id === 'actions' ? ` (${d.recommendations.length})` : ''}
          </button>
        ))}
      </div>

      {/* --------------------------------------------------------- summary */}
      {tab === 'summary' ? (
        <div className="flex flex-col gap-4">
          <div className="grid grid-3-2">
            <RiskScoreCard detail={d} />
            <Panel title="Investigation metadata">
              <KV
                items={[
                  { label: 'Reference', value: <span className="mono">{d.reference}</span> },
                  { label: 'Status', value: d.status },
                  { label: 'Analyst', value: d.requestedBy?.name ?? 'unknown' },
                  { label: 'Opened', value: formatDate(d.startedAt) },
                  { label: 'Completed', value: d.completedAt ? formatDate(d.completedAt) : '—' },
                  { label: 'Pipeline duration', value: formatDuration(d.durationMs) },
                  { label: 'Intelligence mode', value: d.mode === 'demo' ? 'DEMO MODE (simulated)' : 'LIVE INTELLIGENCE' },
                  { label: 'Sources queried', value: `${d.counts.providers} (${d.counts.ok} usable, ${d.counts.failed} failed)` },
                  { label: 'Indicator first stored', value: formatDate(d.ioc.firstSeenAt) },
                  { label: 'Times investigated', value: String(d.ioc.timesSeen) },
                ]}
              />
            </Panel>
          </div>

          <div className="grid grid-2">
            <ReputationCard detail={d} />
            <NetworkIntelCard detail={d} />
          </div>

          <RiskBreakdown detail={d} />

          <div className="grid grid-2">
            <Panel title="Investigated indicator detail" subtitle="Values ThreatLens measured directly from the submitted indicator">
              <KV
                items={[
                  { label: 'Canonical value', value: <span className="mono">{d.ioc.value}</span> },
                  ...(d.ioc.parsed.hostname ? [{ label: 'Host component', value: <span className="mono">{String(d.ioc.parsed.hostname)}</span> }] : []),
                  ...(d.ioc.parsed.registrableDomain ? [{ label: 'Registrable domain', value: <span className="mono">{String(d.ioc.parsed.registrableDomain)}</span> }] : []),
                  ...(d.ioc.parsed.scheme ? [{ label: 'Scheme', value: String(d.ioc.parsed.scheme) }] : []),
                  ...(d.ioc.parsed.port ? [{ label: 'Port', value: String(d.ioc.parsed.port) }] : []),
                  ...(d.ioc.parsed.path && d.ioc.parsed.path !== '/' ? [{ label: 'Path', value: <span className="mono">{String(d.ioc.parsed.path)}</span> }] : []),
                  ...(d.ioc.parsed.subdomainDepth ? [{ label: 'Subdomain depth', value: String(d.ioc.parsed.subdomainDepth) }] : []),
                  { label: 'Documentation range', value: d.ioc.isDocumentation ? 'Yes (RFC 5737 / 3849 / 2606)' : 'No' },
                  { label: 'Private / non-routable', value: d.ioc.isPrivate ? 'Yes' : 'No' },
                ]}
              />
            </Panel>

            <Panel title="Analyst assessment" subtitle="ThreatLens assessment, not a provider verdict">
              <div className="flex flex-col gap-3">
                {d.analyst.assessment ? (
                  <div className="small" style={{ color: 'var(--ink-1)' }}>
                    {d.analyst.assessment}
                  </div>
                ) : (
                  <span className="small dim">No analyst assessment recorded yet.</span>
                )}
                <div>
                  <div className="label">Analyst notes / actions taken</div>
                  <textarea
                    className="textarea"
                    value={notes ?? d.analyst.notes ?? ''}
                    placeholder="Record triage outcome, containment actions, or escalation notes…"
                    onChange={(e) => setNotes(e.target.value)}
                  />
                </div>
                <div>
                  <div className="label">Triage outcome</div>
                  <select
                    className="select"
                    value={rating ?? d.analyst.rating ?? ''}
                    onChange={(e) => setRating(e.target.value)}
                  >
                    <option value="">Unclassified</option>
                    <option value="true-positive">True positive</option>
                    <option value="suspicious">Suspicious</option>
                    <option value="false-positive">False positive</option>
                    <option value="benign">Benign</option>
                    <option value="unclassified">Needs triage</option>
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <button className="btn btn-sm btn-primary" type="button" onClick={saveNotes} disabled={saving}>
                    {saving ? <span className="spinner" /> : null} Save assessment
                  </button>
                  {saved ? <span className="small" style={{ color: 'var(--clean)' }}>✓ saved</span> : null}
                  {d.analyst.notes && notes === null ? <span className="tiny dim">stored notes loaded</span> : null}
                </div>
              </div>
            </Panel>
          </div>
        </div>
      ) : null}

      {/* ----------------------------------------------------- intelligence */}
      {tab === 'intelligence' ? (
        <div className="flex flex-col gap-4">
          <EnrichmentPanel detail={d} />
          <div className="grid grid-2">
            <ThreatIntelPanel detail={d} />
            <NetworkIntelCard detail={d} />
          </div>
          <ReputationCard detail={d} />
        </div>
      ) : null}

      {/* ------------------------------------------------------ correlation */}
      {tab === 'correlation' ? (
        <div className="flex flex-col gap-4">
          <PanelFlush
            title="Entity relationship graph"
            actions={<span className="tiny dim">drag nodes · scroll to zoom · click to focus</span>}
          >
            <IOCRelationshipGraph graph={d.graph} height={560} />
          </PanelFlush>
          <ThreatIntelPanel detail={d} />
          <Panel title="Correlation memory" subtitle="Indicator-to-indicator relationships learned across all investigations">
            {d.relatedIocs.length ? (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Related indicator</th>
                      <th>Type</th>
                      <th>Relationship</th>
                      <th>Confidence</th>
                      <th>Reported by</th>
                      <th className="right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.relatedIocs.map((r) => (
                      <tr key={`${r.iocId}-${r.relation}`}>
                        <td className="mono truncate" style={{ maxWidth: 300 }} title={r.value}>
                          {r.value}
                        </td>
                        <td>
                          <span className="badge badge-neutral">{r.typeLabel}</span>
                        </td>
                        <td className="small muted">{r.relation.replace(/_/g, ' ')}</td>
                        <td className="small">{r.confidence}</td>
                        <td className="tiny dim mono">{r.source}</td>
                        <td className="right">
                          <Link className="btn btn-sm btn-ghost" to={`/investigate?q=${encodeURIComponent(r.value)}`}>
                            Investigate
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <span className="small dim">
                No indicator-to-indicator relationships were reported for this value. Correlation edges are only created
                when a source explicitly associates entities.
              </span>
            )}
          </Panel>
        </div>
      ) : null}

      {/* ----------------------------------------------------------- attack */}
      {tab === 'attack' ? (
        <div className="flex flex-col gap-4">
          <Panel title="MITRE ATT&CK mapping" subtitle="Techniques inferred from the stored evidence only">
            <MITRETechniqueList techniques={d.techniques} />
          </Panel>
          <RiskBreakdown detail={d} showMethodology />
        </div>
      ) : null}

      {/* ---------------------------------------------------------- actions */}
      {tab === 'actions' ? <RecommendationsPanel detail={d} /> : null}

      {/* --------------------------------------------------------- timeline */}
      {tab === 'timeline' ? (
        <div className="grid grid-3-2">
          <Panel title="Investigation timeline" subtitle="Chronological record of processing and enrichment">
            <InvestigationTimeline entries={d.timeline} />
          </Panel>
          <Panel title="Evidence classes">
            <div className="flex flex-col gap-3 small">
              <div>
                <span className="evidence-class evidence-observed-fact">Observed fact</span>
                <div className="muted mt-2">
                  Pipeline rows (validation, correlation, scoring, completion) and every value ThreatLens measured
                  directly from the submitted indicator.
                </div>
              </div>
              <div>
                <span className="evidence-class evidence-external-intelligence">External intelligence</span>
                <div className="muted mt-2">
                  Provider rows. Third-party claims, reported verbatim with the source name attached so any single claim
                  can be traced back to the provider that made it.
                </div>
              </div>
              <div>
                <span className="evidence-class evidence-analyst-assessment">Analyst assessment</span>
                <div className="muted mt-2">
                  The risk score, its factor breakdown, ATT&amp;CK mappings and the recommended actions are ThreatLens
                  reasoning over that evidence — not provider output.
                </div>
              </div>
              {d.mode === 'demo' ? (
                <div>
                  <span className="evidence-class evidence-context">Demo data</span>
                  <div className="muted mt-2">
                    This investigation ran against the built-in simulated dataset. The pipeline is real; the
                    intelligence is not.
                  </div>
                </div>
              ) : null}
            </div>
          </Panel>
        </div>
      ) : null}

      {/* ----------------------------------------------------------- report */}
      {tab === 'report' ? <ReportGenerator detail={d} /> : null}

      {/* ---------------------------------------------------- investigate more */}
      <Panel title="Investigate another indicator">
        <IocSearch
          onSubmit={(indicator) => navigate(`/investigate?q=${encodeURIComponent(indicator)}`)}
          showSamples={false}
          autoFocus={false}
          compact
          placeholder="Submit another IOC for enrichment…"
        />
        {demoMode ? (
          <div className="tiny dim mt-2">
            Demo mode is active. Switch to LIVE INTELLIGENCE in Settings to query real providers.
          </div>
        ) : null}
      </Panel>
    </div>
  );
};
