/**
 * Indicator library: every indicator the platform has stored, with the
 * correlation memory (indicator-to-indicator edges learned over time).
 */
import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useFetch } from '../api/AppContext';
import { Alert, EmptyState, IocTypeBadge, Loading, Panel, PanelFlush, ErrorState } from '../components/ui';
import { IOC_TYPE_LABEL, formatDate, formatRelative, relationLabel } from '../lib/format';
import type { IocType } from '../api/types';

interface IndicatorRow {
  id: number;
  type: IocType;
  value: string;
  is_documentation: number;
  is_private: number;
  times_seen: number;
  first_seen_at: string;
  last_seen_at: string;
  notes: string | null;
}

interface Relationship {
  otherIocId: number;
  otherValue: string;
  otherType: IocType;
  relation: string;
  confidence: string;
  sourceProvider: string;
  observations: number;
  firstObserved: string;
  lastObserved: string;
  sourceInvestigationId: number | null;
}

export const IndicatorsPage = () => {
  const navigate = useNavigate();
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState<IocType | ''>('');
  const [selected, setSelected] = useState<IndicatorRow | null>(null);
  const [relationships, setRelationships] = useState<Relationship[] | null>(null);

  const { data, error, loading, reload } = useFetch(() => api.indicators(500, 0), []);

  const rows = useMemo(() => {
    const items = data?.items ?? [];
    const q = filter.trim().toLowerCase();
    return items.filter((i) => {
      if (typeFilter && i.type !== typeFilter) return false;
      if (q && !i.value.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [data, filter, typeFilter]);

  const select = async (row: IndicatorRow) => {
    setSelected(row);
    setRelationships(null);
    try {
      const res = await fetch(`/api/iocs/${row.id}/relationships`, { credentials: 'same-origin' });
      if (res.ok) {
        const body = (await res.json()) as { items: Relationship[] };
        setRelationships(body.items);
      }
    } catch {
      setRelationships([]);
    }
  };

  if (loading) return <Loading label="Loading indicator library" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;

  return (
    <div className="grid grid-3-2">
      <PanelFlush
        title={`Indicator library${data ? ` (${data.total})` : ''}`}
        actions={
          <>
            <input
              className="input"
              style={{ width: 200 }}
              placeholder="Filter indicators…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <select className="select" style={{ width: 130 }} value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as IocType | '')}>
              <option value="">All types</option>
              {(['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'] as IocType[]).map((t) => (
                <option key={t} value={t}>
                  {IOC_TYPE_LABEL[t]}
                </option>
              ))}
            </select>
          </>
        }
        bodyClass="table-wrap"
      >
        {rows.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th className="right">Investigated</th>
                <th>First stored</th>
                <th>Last seen</th>
                <th>Flags</th>
                <th className="right">Open</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  className="clickable"
                  onClick={() => select(row)}
                  style={selected?.id === row.id ? { background: 'var(--accent-bg)' } : undefined}
                >
                  <td className="mono truncate" style={{ maxWidth: 300 }} title={row.value}>
                    {row.value}
                  </td>
                  <td>
                    <IocTypeBadge type={row.type} />
                  </td>
                  <td className="right mono">{row.times_seen}</td>
                  <td className="small dim nowrap">{formatRelative(row.first_seen_at)}</td>
                  <td className="small dim nowrap">{formatRelative(row.last_seen_at)}</td>
                  <td>
                    {row.is_documentation ? <span className="badge badge-demo">DOC RANGE</span> : null}
                    {row.is_private ? <span className="badge badge-neutral">PRIVATE</span> : null}
                  </td>
                  <td className="right">
                    <Link className="btn btn-sm btn-ghost" to={`/investigate?q=${encodeURIComponent(row.value)}`} onClick={(e) => e.stopPropagation()}>
                      Investigate
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState>No indicators match this filter.</EmptyState>
        )}
      </PanelFlush>

      <div className="flex flex-col gap-3">
        {selected ? (
          <Panel title="Indicator detail">
            <div className="mono" style={{ color: 'var(--ink-0)', wordBreak: 'break-all', marginBottom: 10 }}>
              {selected.value}
            </div>
            <div className="flex gap-2 wrap mb-3">
              <IocTypeBadge type={selected.type} />
              {selected.is_documentation ? <span className="badge badge-demo">DOCUMENTATION RANGE</span> : null}
            </div>
            <dl className="kv">
              <dt>Investigated</dt>
              <dd className="mono">{selected.times_seen} time(s)</dd>
              <dt>First stored</dt>
              <dd>{formatDate(selected.first_seen_at)}</dd>
              <dt>Last seen</dt>
              <dd>{formatDate(selected.last_seen_at)}</dd>
            </dl>
            <button
              className="btn btn-sm btn-primary btn-block mt-3"
              type="button"
              onClick={() => navigate(`/investigate?q=${encodeURIComponent(selected.value)}`)}
            >
              Investigate this indicator
            </button>
          </Panel>
        ) : (
          <Panel title="Indicator detail">
            <EmptyState>Select an indicator to inspect its correlation memory.</EmptyState>
          </Panel>
        )}

        {selected ? (
          <Panel title="Correlation memory" subtitle="Indicator-to-indicator relationships learned by enrichment">
            {relationships === null ? (
              <Loading label="Loading relationships" />
            ) : relationships.length === 0 ? (
              <Alert kind="info">
                No indicator-to-indicator relationships are stored for this value yet. Relationships are recorded when a
                source explicitly associates it with another indicator.
              </Alert>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Related</th>
                      <th>Relation</th>
                      <th className="right">Obs.</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relationships.map((r) => (
                      <tr key={`${r.otherIocId}-${r.relation}`}>
                        <td className="mono truncate" style={{ maxWidth: 170 }} title={r.otherValue}>
                          {r.otherValue.length > 24 ? `${r.otherValue.slice(0, 16)}…${r.otherValue.slice(-8)}` : r.otherValue}
                        </td>
                        <td className="small muted">{relationLabel(r.relation)}</td>
                        <td className="right mono dim">{r.observations}</td>
                        <td className="tiny dim mono">{r.sourceProvider}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        ) : null}
      </div>
    </div>
  );
};
