/**
 * Reports hub: pick an investigation, generate its report, export PDF / JSON /
 * Markdown, and see the log of reports previously generated.
 */
import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, type InvestigationDetail } from '../api/client';
import { useFetch } from '../api/AppContext';
import { EmptyState, ErrorState, IocTypeBadge, Loading, Panel, PanelFlush, RiskBadge, StatusBadge } from '../components/ui';
import { ReportGenerator } from '../components/ReportGenerator';
import { formatBytes, formatDate, formatRelative } from '../lib/format';

export const ReportsPage = () => {
  const navigate = useNavigate();
  const { data, error, loading, reload } = useFetch(() => api.reports(), []);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [search, setSearch] = useState('');

  const detail = useFetch<InvestigationDetail>(
    () => (selectedId ? api.investigation(selectedId) : Promise.reject(new Error('no selection'))),
    [selectedId],
  );

  const rows = useMemo(() => {
    const items = data?.investigations ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((i) => i.ioc.toLowerCase().includes(q) || i.reference.toLowerCase().includes(q));
  }, [data, search]);

  if (loading) return <Loading label="Loading reports" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-3-2">
        <PanelFlush
          title={`Reportable investigations (${data?.investigations.length ?? 0})`}
          actions={
            <>
              <input
                className="input"
                style={{ width: 200 }}
                placeholder="Filter by IOC or reference…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <Link to="/investigate" className="btn btn-sm btn-primary">
                New investigation
              </Link>
            </>
          }
          bodyClass="table-wrap"
        >
          {rows.length ? (
            <table className="table">
              <thead>
                <tr>
                  <th>Reference</th>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th className="right">Risk</th>
                  <th>Level</th>
                  <th>Status</th>
                  <th className="right">Investigated</th>
                  <th className="right">Report</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.id}
                    className="clickable"
                    onClick={() => setSelectedId(row.id)}
                    style={selectedId === row.id ? { background: 'var(--accent-bg)' } : undefined}
                  >
                    <td className="mono small nowrap">{row.reference}</td>
                    <td className="mono truncate" style={{ maxWidth: 250 }} title={row.ioc}>
                      {row.ioc}
                      {row.mode === 'demo' ? <span className="badge badge-demo" style={{ marginLeft: 6 }}>DEMO</span> : null}
                    </td>
                    <td>
                      <IocTypeBadge type={row.iocType.toLowerCase() as never} />
                    </td>
                    <td className="right mono">{row.riskScore ?? '—'}</td>
                    <td>{row.riskLevel ? <RiskBadge level={row.riskLevel} size="sm" /> : <span className="dim">—</span>}</td>
                    <td>
                      <StatusBadge status={row.status} />
                    </td>
                    <td className="right small dim nowrap">{formatRelative(row.createdAt)}</td>
                    <td className="right">
                      <span className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                        <a className="btn btn-sm btn-ghost" href={api.exportUrl(row.id, 'pdf')} title="Export PDF">
                          PDF
                        </a>
                        <a className="btn btn-sm btn-ghost" href={api.exportUrl(row.id, 'json')} title="Export JSON">
                          JSON
                        </a>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState>
              <p>No investigations available to report on.</p>
              <Link to="/investigate" className="btn btn-sm btn-primary">
                Run an investigation
              </Link>
            </EmptyState>
          )}
        </PanelFlush>

        <Panel title="Generated reports" subtitle="Audit log of exports produced by this platform">
          {data?.generated.length ? (
            <div className="flex flex-col gap-2 max-h-420 scroll-y">
              {data.generated.map((r) => (
                <div key={r.id} className="panel" style={{ background: 'var(--bg-2)' }}>
                  <div className="panel-body tight">
                    <div className="flex items-center gap-2 wrap">
                      <span className="badge badge-neutral">{r.format.toUpperCase()}</span>
                      <span className="badge badge-medium">{r.classification}</span>
                      <span className="tiny dim mono">{formatBytes(r.byte_size)}</span>
                    </div>
                    <div className="small mt-2 truncate" title={r.title}>
                      {r.title}
                    </div>
                    <div className="tiny dim mt-2">
                      #{r.investigation_id} · {formatDate(r.generated_at)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState>No reports generated yet. Select an investigation and click “Generate report”.</EmptyState>
          )}
        </Panel>
      </div>

      {selectedId ? (
        detail.loading ? (
          <Loading label="Loading investigation" />
        ) : detail.error ? (
          <ErrorState error={detail.error} onRetry={detail.reload} />
        ) : detail.data ? (
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <span className="mono small dim">{detail.data.reference}</span>
              <button
                className="btn btn-sm btn-ghost"
                type="button"
                onClick={() => {
                  setSelectedId(null);
                  navigate('/reports');
                }}
              >
                Close preview
              </button>
            </div>
            <ReportGenerator detail={detail.data} />
          </div>
        ) : null
      ) : null}
    </div>
  );
};
