/**
 * Investigation history with search, filtering, sorting and deletion.
 *
 * Filters are encoded into the query string so an analyst can bookmark or share
 * a filtered view, and so a dashboard tile can deep-link straight into
 * (for example) "all CRITICAL investigations".
 */
import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api, type InvestigationListItem } from '../api/client';
import { ErrorState, IocTypeBadge, Loading, PanelFlush, RiskBadge, StatusBadge, VerdictBadge } from '../components/ui';
import { IOC_TYPE_LABEL, formatDate, formatRelative } from '../lib/format';
import type { IocType, RiskLevel } from '../api/types';

const LEVELS: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'];
const TYPES: IocType[] = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'];
const SORTS = [
  { id: 'newest', label: 'Newest first' },
  { id: 'oldest', label: 'Oldest first' },
  { id: 'risk_desc', label: 'Highest risk' },
  { id: 'risk_asc', label: 'Lowest risk' },
  { id: 'ioc_asc', label: 'Indicator A→Z' },
];

const LEVEL_CLASS: Record<RiskLevel, string> = {
  CRITICAL: 'c-critical',
  HIGH: 'c-high',
  MEDIUM: 'c-medium',
  LOW: 'c-low',
  CLEAN: 'c-clean',
};

export const HistoryPage = () => {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const search = params.get('search') ?? '';
  const sort = params.get('sort') ?? 'newest';
  const types = useMemo(() => (params.get('type') ?? '').split(',').filter(Boolean) as IocType[], [params]);
  const levels = useMemo(() => (params.get('level') ?? '').split(',').filter(Boolean) as RiskLevel[], [params]);
  const modes = useMemo(() => (params.get('mode') ?? '').split(',').filter(Boolean) as Array<'live' | 'demo'>, [params]);

  const [items, setItems] = useState<InvestigationListItem[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [confirmId, setConfirmId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .history({ search: search || undefined, sort, type: types, level: levels, mode: modes, limit: 200 })
      .then((result) => {
        if (cancelled) return;
        setItems(result.items);
        setTotal(result.total);
        setLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err : new Error('Failed to load history'));
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [search, sort, types, levels, modes]);

  const update = (key: string, value: string | string[] | null) => {
    const next = new URLSearchParams(params);
    if (value === null || value === '' || (Array.isArray(value) && value.length === 0)) next.delete(key);
    else next.set(key, Array.isArray(value) ? value.join(',') : value);
    setParams(next, { replace: true });
  };

  const toggleIn = (key: string, current: string[], value: string) => {
    const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
    update(key, next);
  };

  const remove = async (id: number) => {
    setDeleting(true);
    try {
      await api.deleteInvestigation(id);
      setItems((prev) => (prev ? prev.filter((i) => i.id !== id) : prev));
      setTotal((t) => Math.max(0, t - 1));
      setConfirmId(null);
    } finally {
      setDeleting(false);
    }
  };

  const activeFilters = types.length + levels.length + modes.length + (search ? 1 : 0);

  return (
    <div className="flex flex-col gap-3">
      <PanelFlush
        title={`Investigation history${total ? ` (${total})` : ''}`}
        actions={
          <>
            {activeFilters > 0 ? (
              <button className="btn btn-sm btn-ghost" type="button" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
                Clear filters ({activeFilters})
              </button>
            ) : null}
            <Link to="/investigate" className="btn btn-sm btn-primary">
              New investigation
            </Link>
          </>
        }
        bodyClass="tight"
      >
        <div className="flex flex-col gap-3">
          <div className="filter-bar">
            <input
              className="input search"
              placeholder="Search indicator value…"
              value={search}
              onChange={(e) => update('search', e.target.value)}
            />
            <select className="select" value={sort} onChange={(e) => update('sort', e.target.value)}>
              {SORTS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
            <button className={`chip-toggle ${modes.includes('demo') ? 'on' : ''}`} type="button" onClick={() => toggleIn('mode', modes, 'demo')}>
              DEMO
            </button>
            <button className={`chip-toggle ${modes.includes('live') ? 'on' : ''}`} type="button" onClick={() => toggleIn('mode', modes, 'live')}>
              LIVE
            </button>
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 wrap">
              <span className="tiny dim" style={{ width: 46 }}>
                Risk
              </span>
              {LEVELS.map((level) => (
                <button
                  key={level}
                  type="button"
                  className={`chip-toggle ${LEVEL_CLASS[level]} ${levels.includes(level) ? 'on' : ''}`}
                  onClick={() => toggleIn('level', levels, level)}
                >
                  {level}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2 wrap">
              <span className="tiny dim" style={{ width: 46 }}>
                Type
              </span>
              {TYPES.map((type) => (
                <button
                  key={type}
                  type="button"
                  className={`chip-toggle ${types.includes(type) ? 'on' : ''}`}
                  onClick={() => toggleIn('type', types, type)}
                >
                  {IOC_TYPE_LABEL[type]}
                </button>
              ))}
            </div>
          </div>
        </div>
      </PanelFlush>

      {loading ? (
        <Loading label="Loading investigations" />
      ) : error ? (
        <ErrorState error={error} />
      ) : items && items.length > 0 ? (
        <PanelFlush bodyClass="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Indicator</th>
                <th>Type</th>
                <th>Verdict</th>
                <th className="right">Risk</th>
                <th>Level</th>
                <th className="right">Conf.</th>
                <th>Status</th>
                <th className="right">ATT&amp;CK</th>
                <th className="right">Investigated</th>
                <th className="right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="clickable row-link" onClick={() => navigate(`/investigation/${item.id}`)}>
                  <td className="mono small nowrap">{item.reference}</td>
                  <td className="mono truncate" style={{ maxWidth: 280 }} title={item.iocValue}>
                    {item.iocValue}
                    {item.mode === 'demo' ? <span className="badge badge-demo" style={{ marginLeft: 6 }}>DEMO</span> : null}
                  </td>
                  <td>
                    <IocTypeBadge type={item.iocType} />
                  </td>
                  <td>
                    <VerdictBadge verdict={item.verdict ?? 'unknown'} />
                  </td>
                  <td className="right mono">{item.riskScore ?? '—'}</td>
                  <td>{item.riskLevel ? <RiskBadge level={item.riskLevel} size="sm" /> : <span className="dim">—</span>}</td>
                  <td className="right mono dim">{item.confidenceScore !== null ? `${item.confidenceScore}%` : '—'}</td>
                  <td>
                    <StatusBadge status={item.status} />
                  </td>
                  <td className="right mono dim">{item.techniqueCount || '—'}</td>
                  <td className="right small dim nowrap" title={formatDate(item.createdAt)}>
                    {formatRelative(item.createdAt)}
                  </td>
                  <td className="right nowrap">
                    {confirmId === item.id ? (
                      <span className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                        <button className="btn btn-sm btn-danger" type="button" disabled={deleting} onClick={() => remove(item.id)}>
                          Confirm
                        </button>
                        <button className="btn btn-sm btn-ghost" type="button" onClick={() => setConfirmId(null)}>
                          No
                        </button>
                      </span>
                    ) : (
                      <span className="row-danger-btn" onClick={(e) => e.stopPropagation()}>
                        <button
                          className="btn btn-sm btn-ghost"
                          type="button"
                          title="Delete this investigation (evidence, timeline and mappings are removed; the shared indicator record is kept)"
                          onClick={() => setConfirmId(item.id)}
                        >
                          🗑
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </PanelFlush>
      ) : (
        <div className="empty-state">
          <p>No investigations match these filters.</p>
          {activeFilters > 0 ? (
            <button className="btn btn-sm" type="button" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
              Clear filters
            </button>
          ) : (
            <Link to="/investigate" className="btn btn-sm btn-primary">
              Run your first investigation
            </Link>
          )}
        </div>
      )}
    </div>
  );
};
