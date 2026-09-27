/**
 * ReputationCard and EnrichmentCard.
 *
 * HONESTY PRINCIPLE: these components only render what a provider actually
 * returned. Where a source had no opinion, the field shows "not reported by any
 * source" instead of a zero, and per-source failures are shown in full with the
 * upstream error - never silently dropped.
 */
import { useState } from 'react';
import type { InvestigationDetail, ProviderSummary } from '../api/client';
import { Alert, ConfidenceBadge, DemoBadge, KV, TagList, VerdictBadge } from './ui';
import {
  PROVIDER_STATUS_LABEL,
  VERDICT_LABEL,
  clampText,
  formatDate,
  formatDuration,
  formatNumber,
  formatPercent,
  truncateMiddle,
} from '../lib/format';

const DETECT_COLOURS = { malicious: 'var(--critical)', suspicious: 'var(--medium)', harmless: 'var(--clean)', undetected: 'var(--ink-3)' };

export const ReputationCard = ({ detail }: { detail: InvestigationDetail }) => {
  const { reputation } = detail;
  const det = reputation.detections;

  return (
    <section className="panel">
      <header className="panel-head">
        <div className="panel-title">Reputation</div>
        <VerdictBadge verdict={reputation.verdict} />
      </header>
      <div className="panel-body">
        {det && det.total > 0 ? (
          <>
            <div className="detect-bar" role="img" aria-label={`${det.malicious} malicious, ${det.suspicious} suspicious, ${det.harmless} harmless of ${det.total} engines`}>
              {det.malicious > 0 ? <div className="detect-seg" style={{ width: `${(det.malicious / det.total) * 100}%`, background: DETECT_COLOURS.malicious }} /> : null}
              {det.suspicious > 0 ? <div className="detect-seg" style={{ width: `${(det.suspicious / det.total) * 100}%`, background: DETECT_COLOURS.suspicious }} /> : null}
              {det.harmless > 0 ? <div className="detect-seg" style={{ width: `${(det.harmless / det.total) * 100}%`, background: DETECT_COLOURS.harmless }} /> : null}
              {det.undetected > 0 ? <div className="detect-seg" style={{ width: `${(det.undetected / det.total) * 100}%`, background: DETECT_COLOURS.undetected }} /> : null}
            </div>
            <div className="detect-legend">
              <span className="detect-legend-item">
                <span className="detect-swatch" style={{ background: DETECT_COLOURS.malicious }} /> {det.malicious} malicious
              </span>
              <span className="detect-legend-item">
                <span className="detect-swatch" style={{ background: DETECT_COLOURS.suspicious }} /> {det.suspicious} suspicious
              </span>
              <span className="detect-legend-item">
                <span className="detect-swatch" style={{ background: DETECT_COLOURS.harmless }} /> {det.harmless} harmless
              </span>
              {det.undetected > 0 ? (
                <span className="detect-legend-item">
                  <span className="detect-swatch" style={{ background: DETECT_COLOURS.undetected }} /> {det.undetected} no detection
                </span>
              ) : null}
              <span className="detect-legend-item mono" style={{ marginLeft: 'auto' }}>
                ratio {formatPercent(det.ratio)}
              </span>
            </div>
          </>
        ) : (
          <Alert kind="info">
            No detection statistics were reported. This happens when every source either had no opinion about the
            indicator or failed — see the per-source breakdown below.
          </Alert>
        )}

        <div className="mt-4">
          <KV
            items={[
              { label: 'Detection ratio', value: det ? formatPercent(det.ratio) : '—' },
              { label: 'Total engines reporting', value: det ? formatNumber(det.total) : '—' },
              { label: 'Reports', value: reputation.reports === null ? '—' : formatNumber(reputation.reports) },
              {
                label: 'Reputation score',
                value: reputation.reputationScore === null ? '—' : `${reputation.reputationScore} / 100`,
              },
              { label: 'First seen', value: reputation.firstSeenAt ? formatDate(reputation.firstSeenAt) : 'Not reported' },
              { label: 'Last analysis', value: reputation.lastSeenAt ? formatDate(reputation.lastSeenAt) : 'Not reported' },
              {
                label: 'Corroboration',
                value: `${reputation.corroborationCount} source(s) with a verdict${
                  reputation.neutralSources.length ? `, ${reputation.neutralSources.length} neutral` : ''
                }`,
              },
            ]}
          />
        </div>
      </div>
    </section>
  );
};

export const NetworkIntelCard = ({ detail }: { detail: InvestigationDetail }) => {
  const { fields } = detail.network;
  return (
    <section className="panel">
      <header className="panel-head">
        <div className="panel-title">Network intelligence</div>
        <span className="tiny dim">field-level provenance</span>
      </header>
      <div className="panel-body">
        {fields.length === 0 ? (
          <Alert kind="info">
            No network attribution was reported for this indicator. File hashes and email addresses have no network
            context by definition; for other types it means no source returned geolocation or ASN data.
          </Alert>
        ) : (
          <KV
            items={fields.map((f) => ({
              label: f.label,
              value: (
                <span className="flex items-center gap-2 wrap">
                  <span className={/reverse|hostname/i.test(f.label) ? 'mono small' : ''}>{f.value}</span>
                  {f.source ? (
                    <span className="tag tiny" title="Source that reported this value">
                      {f.source}
                    </span>
                  ) : null}
                </span>
              ),
            }))}
          />
        )}
      </div>
    </section>
  );
};

const ProviderCard = ({ provider }: { provider: ProviderSummary }) => {
  const [open, setOpen] = useState(false);
  const det = provider.detections;
  const failed = provider.status !== 'ok';

  return (
    <div className="enrich-card">
      <div className="enrich-head">
        <div className="grow" style={{ minWidth: 0 }}>
          <div className="flex items-center gap-2 wrap">
            <strong className="small" style={{ color: 'var(--ink-0)' }}>
              {provider.name}
            </strong>
            {provider.origin === 'demo' ? <DemoBadge label="SIMULATED" /> : <span className="badge badge-clean">LIVE</span>}
          </div>
          <div className="tiny dim mono">{provider.id}</div>
        </div>
        <div className="flex items-center gap-2">
          {failed ? (
            <span className={`badge ${provider.status === 'not_found' ? 'badge-unknown' : provider.status === 'rate_limited' ? 'badge-medium' : 'badge-critical'}`}>
              {PROVIDER_STATUS_LABEL[provider.status] ?? provider.status}
            </span>
          ) : (
            <VerdictBadge verdict={provider.verdict} />
          )}
          <button className="btn btn-sm btn-ghost" type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
            {open ? 'Hide' : 'Details'}
          </button>
        </div>
      </div>

      <div className="enrich-body">
        {provider.error ? (
          <Alert kind={provider.status === 'not_found' ? 'info' : 'danger'} title={`${provider.error.code}${provider.error.retryable ? ' (retryable)' : ''}`}>
            {provider.error.message}
          </Alert>
        ) : det && det.total > 0 ? (
          <div>
            <div className="detect-bar">
              {det.malicious > 0 ? <div className="detect-seg" style={{ width: `${(det.malicious / det.total) * 100}%`, background: DETECT_COLOURS.malicious }} /> : null}
              {det.suspicious > 0 ? <div className="detect-seg" style={{ width: `${(det.suspicious / det.total) * 100}%`, background: DETECT_COLOURS.suspicious }} /> : null}
              {det.harmless > 0 ? <div className="detect-seg" style={{ width: `${(det.harmless / det.total) * 100}%`, background: DETECT_COLOURS.harmless }} /> : null}
            </div>
            <div className="detect-legend">
              <span className="detect-legend-item">
                <span className="detect-swatch" style={{ background: DETECT_COLOURS.malicious }} /> {det.malicious}/{det.total} malicious
              </span>
              <span className="detect-legend-item">
                <span className="detect-swatch" style={{ background: DETECT_COLOURS.suspicious }} /> {det.suspicious} suspicious
              </span>
              <span className="detect-legend-item">{formatPercent(det.ratio)}</span>
              {provider.reports !== null ? <span className="detect-legend-item">{formatNumber(provider.reports)} reports</span> : null}
              {provider.reputationScore !== null ? <span className="detect-legend-item">rep {provider.reputationScore}/100</span> : null}
              <span className="detect-legend-item" style={{ marginLeft: 'auto' }}>
                {formatDuration(provider.durationMs)}
              </span>
            </div>
          </div>
        ) : (
          <div className="small dim">
            Source responded but holds no reputation opinion for this indicator.
            {provider.lastAnalysisAt ? ` Last analysis ${formatDate(provider.lastAnalysisAt)}.` : ''}
          </div>
        )}

        {open ? (
          <div className="mt-4 flex flex-col gap-3">
            <KV
              items={[
                { label: 'Status', value: PROVIDER_STATUS_LABEL[provider.status] ?? provider.status },
                { label: 'Origin', value: provider.origin === 'demo' ? 'Simulated (ThreatLens demo dataset)' : 'Live API response' },
                { label: 'Latency', value: formatDuration(provider.durationMs) },
                { label: 'First seen', value: provider.firstSeenAt ? formatDate(provider.firstSeenAt) : 'Not reported' },
                { label: 'Last seen', value: provider.lastAnalysisAt ? formatDate(provider.lastAnalysisAt) : 'Not reported' },
              ]}
            />

            {provider.related.categories.length ? (
              <div>
                <div className="label">Categories</div>
                <TagList values={provider.related.categories} max={14} />
              </div>
            ) : null}
            {provider.related.behaviours.length ? (
              <div>
                <div className="label">Behavioural signals</div>
                <TagList values={provider.related.behaviours} max={14} />
              </div>
            ) : null}
            {provider.related.malware.length ? (
              <div>
                <div className="label">Malware associations</div>
                <TagList values={provider.related.malware} max={12} />
              </div>
            ) : null}
            {provider.related.actors.length ? (
              <div>
                <div className="label">Actors</div>
                <TagList values={provider.related.actors} max={8} />
              </div>
            ) : null}
            {provider.related.campaigns.length ? (
              <div>
                <div className="label">Campaigns / collections</div>
                <TagList values={provider.related.campaigns} max={8} />
              </div>
            ) : null}

            {provider.rawExcerpt ? (
              <div>
                <div className="label">Raw payload excerpt (audit trail)</div>
                <pre
                  className="console"
                  style={{ maxHeight: 200, margin: 0, fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
                >
                  {clampText(provider.rawExcerpt, 2000)}
                </pre>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
};

export const EnrichmentPanel = ({ detail }: { detail: InvestigationDetail }) => {
  const ok = detail.providers.filter((p) => p.status === 'ok');
  const notOk = detail.providers.filter((p) => p.status !== 'ok');

  return (
    <section className="panel">
      <header className="panel-head">
        <div className="panel-title">Enrichment by source</div>
        <div className="flex items-center gap-2">
          <span className="badge badge-clean">{ok.length} responded</span>
          {notOk.length > 0 ? <span className="badge badge-critical">{notOk.length} unusable</span> : null}
        </div>
      </header>
      <div className="panel-body">
        {detail.providers.length === 0 ? (
          <Alert kind="warning">No provider was queried for this indicator.</Alert>
        ) : (
          <div className="flex flex-col gap-3">
            {detail.providers.map((p) => (
              <ProviderCard key={p.id} provider={p} />
            ))}
          </div>
        )}

        {notOk.length > 0 ? (
          <div className="mt-4">
            <Alert kind="warning" title="Coverage gaps">
              {notOk.length} source(s) did not return usable intelligence
              {notOk.some((p) => p.status === 'unconfigured')
                ? ' — several are simply not configured. Add the matching environment variable in Settings.'
                : '.'}{' '}
              The confidence score has been reduced to reflect this.
            </Alert>
          </div>
        ) : null}
      </div>
    </section>
  );
};

export const ThreatIntelPanel = ({ detail }: { detail: InvestigationDetail }) => {
  const ti = detail.threatIntel;
  const hasAny =
    ti.malware.length > 0 || ti.actors.length > 0 || ti.campaigns.length > 0 || ti.relatedDomains.length > 0 || ti.relatedHashes.length > 0;

  return (
    <section className="panel">
      <header className="panel-head">
        <div className="panel-title">Threat intelligence</div>
        <span className="tiny dim">only values returned by sources</span>
      </header>
      <div className="panel-body">
        {!hasAny ? (
          <Alert kind="info" title="No threat associations reported">
            No source reported malware, actor, campaign or related indicators for this value. That is itself
            information: the indicator is either unknown to the intelligence community or benign.
          </Alert>
        ) : null}

        {ti.actors.length > 0 ? (
          <div className="mb-4">
            <div className="section-title">Threat actors</div>
            <div className="flex flex-col gap-2">
              {ti.actors.map((a) => (
                <div key={a.externalId} className="panel" style={{ background: 'var(--bg-2)' }}>
                  <div className="panel-body tight">
                    <div className="flex items-center gap-2 wrap mb-2">
                      <strong className="small" style={{ color: 'var(--ink-0)' }}>
                        {a.name}
                      </strong>
                      {a.origin === 'demo' ? <DemoBadge label="DEMO" /> : <span className="badge badge-accent">community</span>}
                      <ConfidenceBadge confidence={a.confidence} />
                      {a.sophistication ? <span className="badge badge-neutral">sophistication: {a.sophistication}</span> : null}
                    </div>
                    <div className="small muted">{a.description}</div>
                    <div className="flex gap-2 wrap mt-2 tiny dim">
                      {a.aliases.length ? <span>aliases: {a.aliases.join(', ')}</span> : null}
                      {a.motivation.length ? <span>· motivation: {a.motivation.join(', ')}</span> : null}
                      {a.firstSeenYear ? <span>· first seen {a.firstSeenYear}</span> : null}
                    </div>
                    <div className="tiny dim mt-2" style={{ fontStyle: 'italic' }}>
                      Basis: {a.basis}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {ti.malware.length > 0 ? (
          <div className="mb-4">
            <div className="section-title">Malware associations</div>
            <div className="flex flex-col gap-2">
              {ti.malware.map((m) => (
                <div key={m.name} className="panel" style={{ background: 'var(--bg-2)' }}>
                  <div className="panel-body tight">
                    <div className="flex items-center gap-2 wrap mb-2">
                      <strong className="small" style={{ color: 'var(--ink-0)' }}>
                        {m.name}
                      </strong>
                      {m.type ? <span className="badge badge-neutral">{m.type}</span> : null}
                      {m.origin === 'demo' ? <DemoBadge label="DEMO" /> : <span className="badge badge-accent">community</span>}
                      <ConfidenceBadge confidence={m.confidence} />
                    </div>
                    <div className="small muted">{m.description}</div>
                    {m.capabilities.length ? (
                      <div className="mt-2">
                        <TagList values={m.capabilities} />
                      </div>
                    ) : null}
                    <div className="tiny dim mt-2" style={{ fontStyle: 'italic' }}>
                      Basis: {m.basis}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {ti.campaigns.length > 0 ? (
          <div className="mb-4">
            <div className="section-title">Campaigns</div>
            <TagList values={ti.campaigns.map((c) => c.name)} />
          </div>
        ) : null}

        {ti.categories.length > 0 ? (
          <div className="mb-4">
            <div className="section-title">Threat categories</div>
            <TagList values={ti.categories} max={24} />
          </div>
        ) : null}

        {ti.behaviours.length > 0 ? (
          <div className="mb-4">
            <div className="section-title">Behavioural signals</div>
            <TagList values={ti.behaviours} />
          </div>
        ) : null}

        {detail.relatedIocs.length > 0 ? (
          <div>
            <div className="section-title">Related indicators</div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Relation</th>
                    <th>Confidence</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.relatedIocs.map((r) => (
                    <tr key={`${r.iocId}-${r.relation}`}>
                      <td className="mono truncate" style={{ maxWidth: 280 }} title={r.value}>
                        {truncateMiddle(r.value, 26, 14)}
                        {r.isDocumentation ? <span className="badge badge-demo" style={{ marginLeft: 6 }}>DEMO</span> : null}
                      </td>
                      <td>
                        <span className="badge badge-neutral">{r.typeLabel}</span>
                      </td>
                      <td className="small muted">{r.relation.replace(/_/g, ' ')}</td>
                      <td>
                        <ConfidenceBadge confidence={r.confidence} />
                      </td>
                      <td className="tiny dim mono">{r.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
};

export { VERDICT_LABEL };
