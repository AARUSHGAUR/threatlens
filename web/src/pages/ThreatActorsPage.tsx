/**
 * Threat actor page: attributed actors plus the malware and campaigns seen
 * alongside them. The demo dataset's actors are explicitly fictional and are
 * labelled as such, so this page can be used as-is in a demonstration.
 */
import { useState } from 'react';
import { api } from '../api/client';
import { useFetch } from '../api/AppContext';
import { Alert, DemoBadge, EmptyState, ErrorState, Loading, Panel, PanelFlush } from '../components/ui';
import { formatRelative } from '../lib/format';
import type { ActorRecord, CampaignRecord, MalwareRecord } from '../api/client';

const TABS = ['Threat actors', 'Malware', 'Campaigns'] as const;
type Tab = (typeof TABS)[number];

export const ThreatActorsPage = () => {
  const [tab, setTab] = useState<Tab>('Threat actors');
  const actors = useFetch(() => api.actors(), []);
  const malware = useFetch(() => api.malware(), []);
  const campaigns = useFetch(() => api.campaigns(), []);
  const [selected, setSelected] = useState<ActorRecord | null>(null);

  const demoCount = actors.data?.actors.filter((a) => a.origin === 'demo').length ?? 0;

  return (
    <div className="flex flex-col gap-3">
      {demoCount > 0 ? (
        <Alert kind="demo" title="Fictional attribution data is in use" icon="◈">
          {demoCount} of the {actors.data?.actors.length ?? 0} actor records come from the built-in demonstration
          catalog. They are invented clusters with a <code className="inline-code">DEMO-</code> prefix and a{' '}
          <em>(fictional)</em> suffix — no real threat actor, group or malware family is impersonated. Live attribution
          appears here automatically once provider API keys are configured.
        </Alert>
      ) : null}

      <div className="flex gap-2 wrap">
        {TABS.map((t) => (
          <button key={t} type="button" className={`chip-toggle ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)}>
            {t}
            {t === 'Threat actors' && actors.data ? ` (${actors.data.actors.length})` : ''}
            {t === 'Malware' && malware.data ? ` (${malware.data.malware.length})` : ''}
            {t === 'Campaigns' && campaigns.data ? ` (${campaigns.data.campaigns.length})` : ''}
          </button>
        ))}
      </div>

      {tab === 'Threat actors' ? (
        actors.loading ? (
          <Loading label="Loading threat actors" />
        ) : actors.error ? (
          <ErrorState error={actors.error} onRetry={actors.reload} />
        ) : (
          <div className="grid grid-2-1">
            <PanelFlush bodyClass="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Actor</th>
                    <th>Origin</th>
                    <th className="right">Investigations</th>
                    <th className="right">Indicators</th>
                    <th className="right">Malware</th>
                    <th className="right">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {(actors.data?.actors ?? []).map((a) => (
                    <tr key={a.id} className="clickable" onClick={() => setSelected(a)} style={selected?.id === a.id ? { background: 'var(--accent-bg)' } : undefined}>
                      <td>
                        <div className="small" style={{ color: 'var(--ink-0)' }}>
                          {a.name}
                        </div>
                        <div className="tiny dim mono">{a.id}</div>
                      </td>
                      <td>{a.origin === 'demo' ? <DemoBadge label="FICTIONAL" /> : <span className="badge badge-accent">community</span>}</td>
                      <td className="right mono">{a.investigationCount}</td>
                      <td className="right mono">{a.indicatorCount}</td>
                      <td className="right mono">{a.malwareCount}</td>
                      <td className="right small dim nowrap">{formatRelative(a.lastSeen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!actors.data?.actors.length ? <EmptyState>No actors attributed yet.</EmptyState> : null}
            </PanelFlush>

            <div className="flex flex-col gap-3">
              {selected ? (
                <Panel title="Actor profile">
                  <div className="flex items-center gap-2 wrap mb-2">
                    <strong style={{ color: 'var(--ink-0)' }}>{selected.name}</strong>
                    {selected.origin === 'demo' ? <DemoBadge label="FICTIONAL" /> : null}
                  </div>
                  <p className="small muted">{selected.description}</p>
                  <dl className="kv mt-3">
                    <dt>External id</dt>
                    <dd className="mono">{selected.id}</dd>
                    {selected.aliases.length ? (
                      <>
                        <dt>Aliases</dt>
                        <dd>{selected.aliases.join(', ')}</dd>
                      </>
                    ) : null}
                    <dt>Sophistication</dt>
                    <dd>{selected.sophistication ?? 'not reported'}</dd>
                    <dt>Motivation</dt>
                    <dd>{selected.motivation.join(', ') || 'not reported'}</dd>
                    <dt>First seen</dt>
                    <dd>{selected.firstSeenYear ?? 'not reported'}</dd>
                    <dt>Investigations</dt>
                    <dd className="mono">{selected.investigationCount}</dd>
                    <dt>Distinct indicators</dt>
                    <dd className="mono">{selected.indicatorCount}</dd>
                    <dt>Linked malware</dt>
                    <dd className="mono">{selected.malwareCount}</dd>
                    <dt>Linked campaigns</dt>
                    <dd className="mono">{selected.campaignCount}</dd>
                    <dt>Last observed</dt>
                    <dd>{selected.lastSeen ? formatRelative(selected.lastSeen) : '—'}</dd>
                  </dl>
                  <div className="tiny dim mt-3" style={{ fontStyle: 'italic' }}>
                    Attribution comes from community intelligence reported by providers. It is an analytical judgement,
                    not a verified fact.
                  </div>
                </Panel>
              ) : (
                <Panel title="Actor profile">
                  <EmptyState>Select an actor to see its profile.</EmptyState>
                </Panel>
              )}
            </div>
          </div>
        )
      ) : null}

      {tab === 'Malware' ? (
        malware.loading ? (
          <Loading label="Loading malware families" />
        ) : malware.error ? (
          <ErrorState error={malware.error} onRetry={malware.reload} />
        ) : (
          <div className="tech-grid">
            {(malware.data?.malware ?? []).map((m: MalwareRecord) => (
              <Panel key={m.id} className="panel">
                <div className="panel-body">
                  <div className="flex items-center gap-2 wrap mb-2">
                    <strong style={{ color: 'var(--ink-0)' }}>{m.name}</strong>
                    {m.origin === 'demo' ? <DemoBadge label="FICTIONAL" /> : <span className="badge badge-accent">community</span>}
                    {m.type ? <span className="badge badge-neutral">{m.type}</span> : null}
                  </div>
                  <p className="small muted">{m.description}</p>
                  <div className="flex gap-2 wrap mt-3">
                    {m.platforms.map((p) => (
                      <span key={p} className="tag tiny">
                        {p}
                      </span>
                    ))}
                  </div>
                  {m.capabilities.length ? (
                    <div className="mt-3">
                      <div className="label">Documented capabilities</div>
                      <div className="flex gap-2 wrap">
                        {m.capabilities.map((c) => (
                          <span key={c} className="tag tiny">
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  <div className="flex gap-3 mt-3 tiny dim">
                    <span>{m.investigationCount} investigation(s)</span>
                    <span>{m.actorCount} actor link(s)</span>
                    {m.lastSeen ? <span>last seen {formatRelative(m.lastSeen)}</span> : null}
                  </div>
                </div>
              </Panel>
            ))}
            {!malware.data?.malware.length ? <EmptyState>No malware families recorded.</EmptyState> : null}
          </div>
        )
      ) : null}

      {tab === 'Campaigns' ? (
        campaigns.loading ? (
          <Loading label="Loading campaigns" />
        ) : campaigns.error ? (
          <ErrorState error={campaigns.error} onRetry={campaigns.reload} />
        ) : (
          <PanelFlush bodyClass="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Campaign</th>
                  <th>Origin</th>
                  <th>First seen</th>
                  <th className="right">Investigations</th>
                  <th className="right">Last observed</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {(campaigns.data?.campaigns ?? []).map((c: CampaignRecord) => (
                  <tr key={c.id}>
                    <td>
                      <div className="small" style={{ color: 'var(--ink-0)' }}>
                        {c.name}
                      </div>
                      <div className="tiny dim mono">{c.id}</div>
                    </td>
                    <td>{c.origin === 'demo' ? <DemoBadge label="FICTIONAL" /> : <span className="badge badge-accent">community</span>}</td>
                    <td className="small mono">{c.firstSeen ?? '—'}</td>
                    <td className="right mono">{c.investigationCount}</td>
                    <td className="right small dim nowrap">{formatRelative(c.lastSeen)}</td>
                    <td className="small muted">{c.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!campaigns.data?.campaigns.length ? <EmptyState>No campaigns recorded.</EmptyState> : null}
          </PanelFlush>
        )
      ) : null}
    </div>
  );
};
