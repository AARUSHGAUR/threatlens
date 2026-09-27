/**
 * Analyst dashboard.
 *
 * Every number on this page is a live aggregate query over the normalised
 * schema - there is no cached/precomputed counter, so the dashboard can never
 * disagree with the investigation history it links to.
 */
import { Link } from 'react-router-dom';
import {
  Bar,
  BarChart,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import { api } from '../api/client';
import { useApp, useFetch } from '../api/AppContext';
import { ChartFrame, ChartTooltip, NO_DATA, dayTick } from '../components/charts/ChartParts';
import { Alert, ErrorState, IocTypeBadge, Loading, Panel, PanelFlush, RiskBadge, StatusBadge, VerdictBadge } from '../components/ui';
import { CHART_COLOUR, IOC_TYPE_ORDER, TYPE_COLOUR, formatNumber, formatRelative, tacticColour } from '../lib/format';
import type { RiskLevel } from '../api/types';

const RISK_ORDER: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'];

const StatTile = ({
  label,
  value,
  sub,
  tone = 'accent',
  to,
}: {
  label: string;
  value: number | string;
  sub?: string;
  tone?: 'accent' | 'critical' | 'high' | 'medium' | 'low' | 'clean';
  to?: string;
}) => {
  const body = (
    <div className={`stat c-${tone}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{typeof value === 'number' ? formatNumber(value) : value}</div>
      {sub ? <div className="stat-sub">{sub}</div> : null}
    </div>
  );
  return to ? <Link to={to} style={{ textDecoration: 'none' }}>{body}</Link> : body;
};

export const DashboardPage = () => {
  const { registry, demoMode } = useApp();
  const { data, error, loading, reload } = useFetch(() => api.dashboard(), []);

  if (loading) return <Loading label="Aggregating intelligence" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return <Emptyish />;

  const { stats, charts, techniques, mostInvestigated, recent } = data;

  // Order the risk distribution into the canonical severity order so the chart
  // reads CRITICAL -> CLEAN instead of alphabetically.
  const riskData = RISK_ORDER.map((level) => ({
    level,
    count: charts.riskDistribution.find((r) => r.key === level)?.count ?? 0,
  })).filter((r) => r.count > 0);

  const verdictData = ['malicious', 'suspicious', 'clean'].map((verdict) => ({
    verdict,
    count: charts.verdicts.find((v) => v.key === verdict)?.count ?? 0,
  }));

  const verdictColour: Record<string, string> = {
    malicious: '#ef4444',
    suspicious: '#eab308',
    clean: '#22c55e',
  };

  const typeData = IOC_TYPE_ORDER.map((type) => ({
    type,
    count: charts.iocTypes.find((t) => t.key === type)?.count ?? 0,
  })).filter((t) => t.count > 0);

  return (
    <div className="flex flex-col gap-4">
      <div className="stat-grid">
        <StatTile
          label="Total IOCs investigated"
          value={stats.totalIocsInvestigated}
          sub={`${formatNumber(stats.uniqueIndicators)} unique indicators`}
          to="/history"
        />
        <StatTile label="Malicious" value={stats.malicious} sub="verdict: malicious" tone="critical" to="/history?level=CRITICAL" />
        <StatTile label="Suspicious" value={stats.suspicious} sub="needs analyst review" tone="medium" to="/history" />
        <StatTile label="Clean" value={stats.clean} sub="verdict: clean / harmless" tone="clean" to="/history" />
        <StatTile label="Critical threats" value={stats.critical} sub="risk score 80-100" tone="critical" to="/history?level=CRITICAL" />
        <StatTile
          label="Investigations this week"
          value={stats.thisWeek}
          sub={`avg risk ${stats.averageRisk ?? '—'}/100`}
          to="/history"
        />
      </div>

      <div className="grid grid-3-2">
        <ChartFrame
          title="Investigations over time"
          subtitle="Daily investigations with critical/high breakdown (last 14 days)"
          height={244}
        >
          {charts.timeline.some((d) => d.count > 0) ? (
            <ResponsiveContainer width="100%" height={232}>
              <LineChart data={charts.timeline} margin={{ top: 6, right: 8, bottom: 0, left: -22 }}>
                <CartesianGrid strokeDasharray="2 4" vertical={false} />
                <XAxis dataKey="date" tickFormatter={dayTick} stroke="#2b3644" fontSize={10.5} interval="preserveStartEnd" />
                <YAxis stroke="#2b3644" fontSize={10.5} allowDecimals={false} />
                <Tooltip content={<ChartTooltip labelFormatter={dayTick} />} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="count" name="Investigations" stroke="#22d3ee" strokeWidth={2} dot={false} activeDot={{ r: 3 }} />
                <Line type="monotone" dataKey="critical" name="Critical" stroke="#ef4444" strokeWidth={1.5} dot={false} />
                <Line type="monotone" dataKey="high" name="High" stroke="#f97316" strokeWidth={1.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            NO_DATA
          )}
        </ChartFrame>

        <ChartFrame title="Risk distribution" subtitle="Investigations by assessed risk level" height={244}>
          {riskData.length ? (
            <ResponsiveContainer width="100%" height={232}>
              <BarChart data={riskData} margin={{ top: 6, right: 8, bottom: 0, left: -22 }}>
                <CartesianGrid strokeDasharray="2 4" vertical={false} />
                <XAxis dataKey="level" stroke="#2b3644" fontSize={10.5} />
                <YAxis stroke="#2b3644" fontSize={10.5} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(34,211,238,0.05)' }} />
                <Bar dataKey="count" name="Investigations" radius={[2, 2, 0, 0]} maxBarSize={48}>
                  {riskData.map((entry) => (
                    <Cell key={entry.level} fill={CHART_COLOUR[entry.level]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            NO_DATA
          )}
        </ChartFrame>
      </div>

      <div className="grid grid-3">
        <ChartFrame title="IOC types investigated" subtitle="Distribution across supported indicator classes">
          {typeData.length ? (
            <ResponsiveContainer width="100%" height={210}>
              <PieChart>
                <Pie data={typeData} dataKey="count" nameKey="type" innerRadius={44} outerRadius={74} paddingAngle={2} stroke="none">
                  {typeData.map((entry) => (
                    <Cell key={entry.type} fill={TYPE_COLOUR[entry.type]} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
                <Legend wrapperStyle={{ fontSize: 11 }} formatter={(value: string) => value.toUpperCase()} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            NO_DATA
          )}
        </ChartFrame>

        <ChartFrame title="Threat categories" subtitle="Categories reported by enrichment sources">
          {charts.categories.length ? (
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={charts.categories.slice(0, 8)} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 4 }}>
                <CartesianGrid strokeDasharray="2 4" horizontal={false} />
                <XAxis type="number" stroke="#2b3644" fontSize={10.5} allowDecimals={false} />
                <YAxis type="category" dataKey="label" stroke="#2b3644" fontSize={10.5} width={112} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(34,211,238,0.05)' }} />
                <Bar dataKey="count" name="Reports" fill="#22d3ee" radius={[0, 2, 2, 0]} maxBarSize={14} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            NO_DATA
          )}
        </ChartFrame>

        <ChartFrame title="Top malicious countries" subtitle="Geo attribution of malicious/suspicious indicators">
          {charts.countries.length ? (
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={charts.countries} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 4 }}>
                <CartesianGrid strokeDasharray="2 4" horizontal={false} />
                <XAxis type="number" stroke="#2b3644" fontSize={10.5} allowDecimals={false} />
                <YAxis type="category" dataKey="label" stroke="#2b3644" fontSize={10.5} width={92} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(34,211,238,0.05)' }} />
                <Bar dataKey="count" name="Malicious IOCs" radius={[0, 2, 2, 0]} maxBarSize={14}>
                  {charts.countries.map((entry) => (
                    <Cell key={entry.key} fill={entry.count >= 4 ? '#ef4444' : '#f97316'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            NO_DATA
          )}
        </ChartFrame>
      </div>

      <div className="grid grid-2">
        <PanelFlush title="Top associated ATT&CK techniques" actions={<Link to="/mitre" className="btn btn-sm">Open ATT&CK view</Link>}>
          {techniques.length ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Technique</th>
                    <th>Name</th>
                    <th>Tactic</th>
                    <th className="right">Investigations</th>
                  </tr>
                </thead>
                <tbody>
                  {techniques.map((t) => (
                    <tr key={t.external_id}>
                      <td>
                        <code className="inline-code">{t.external_id}</code>
                      </td>
                      <td className="truncate" style={{ maxWidth: 260 }} title={t.name}>
                        {t.name}
                      </td>
                      <td>
                        <span className="flex items-center gap-2">
                          <span className="tactic-bar" style={{ background: tacticColour(t.tactic) }} />
                          <span className="small muted">{t.tactic}</span>
                        </span>
                      </td>
                      <td className="right mono">{t.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">No techniques mapped yet.</div>
          )}
        </PanelFlush>

        <PanelFlush title="Most investigated indicators" actions={<Link to="/indicators" className="btn btn-sm">Indicator library</Link>}>
          {mostInvestigated.length ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th className="right">Times</th>
                    <th className="right">Max risk</th>
                  </tr>
                </thead>
                <tbody>
                  {mostInvestigated.map((m) => (
                    <tr key={m.value}>
                      <td className="mono truncate" style={{ maxWidth: 250 }} title={m.value}>
                        {m.value}
                      </td>
                      <td>
                        <IocTypeBadge type={m.type} />
                      </td>
                      <td className="right mono">{m.count}</td>
                      <td className="right">
                        {m.riskLevel ? <RiskBadge level={m.riskLevel} size="sm" /> : <span className="dim">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">No indicators investigated yet.</div>
          )}
        </PanelFlush>
      </div>

      <PanelFlush
        title="Recent investigations"
        actions={
          <>
            <Link to="/history" className="btn btn-sm">
              View all
            </Link>
            <Link to="/investigate" className="btn btn-sm btn-primary">
              Investigate IOC
            </Link>
          </>
        }
        bodyClass="table-wrap"
      >
        {recent.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Indicator</th>
                <th>Type</th>
                <th>Verdict</th>
                <th className="right">Risk</th>
                <th>Level</th>
                <th className="right">Confidence</th>
                <th>Status</th>
                <th className="right">Investigated</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((item) => (
                <tr key={item.id} className="clickable row-link" onClick={() => window.location.assign(`/investigation/${item.id}`)}>
                  <td className="mono small">{item.reference}</td>
                  <td className="mono truncate" style={{ maxWidth: 260 }} title={item.iocValue}>
                    {item.iocValue}
                    {item.mode === 'demo' ? <span className="badge badge-demo" style={{ marginLeft: 8 }}>DEMO</span> : null}
                  </td>
                  <td>
                    <IocTypeBadge type={item.iocType} />
                  </td>
                  <td>
                    <VerdictBadge verdict={item.verdict ?? 'unknown'} />
                  </td>
                  <td className="right mono">{item.riskScore ?? '—'}</td>
                  <td>{item.riskLevel ? <RiskBadge level={item.riskLevel} size="sm" /> : <span className="dim">—</span>}</td>
                  <td className="right mono">{item.confidenceScore !== null ? `${item.confidenceScore}%` : '—'}</td>
                  <td>
                    <StatusBadge status={item.status} />
                  </td>
                  <td className="right small dim nowrap">{formatRelative(item.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <p>No investigations yet.</p>
            <Link to="/investigate" className="btn btn-primary btn-sm">
              Start your first investigation
            </Link>
          </div>
        )}
      </PanelFlush>

      <div className="grid grid-2">
        <Panel title="Verdict breakdown" subtitle="Merged reputation verdict across all investigations">
          {verdictData.some((v) => v.count > 0) ? (
            <div className="flex flex-col gap-3">
              {verdictData.map((v) => {
                const total = verdictData.reduce((acc, x) => acc + x.count, 0) || 1;
                return (
                  <div key={v.verdict}>
                    <div className="flex justify-between small mb-2">
                      <span style={{ textTransform: 'capitalize' }}>{v.verdict}</span>
                      <span className="mono dim">
                        {v.count} ({((v.count / total) * 100).toFixed(0)}%)
                      </span>
                    </div>
                    <div className="meter">
                      <div className="meter-fill" style={{ width: `${(v.count / total) * 100}%`, background: verdictColour[v.verdict] }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <span className="dim small">No verdicts recorded.</span>
          )}
        </Panel>

        <Panel title="Enrichment source usage" subtitle="How often each provider was queried">
          {charts.providers.length ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th className="right">Lookups</th>
                    <th className="right">Failures</th>
                  </tr>
                </thead>
                <tbody>
                  {charts.providers.map((p) => (
                    <tr key={p.key}>
                      <td className="small">
                        {p.label}
                        {p.label.includes('DEMO') ? <span className="badge badge-demo" style={{ marginLeft: 6 }}>SIM</span> : null}
                      </td>
                      <td className="right mono">{p.count}</td>
                      <td className="right mono" style={{ color: p.errors > 0 ? 'var(--critical)' : 'var(--ink-3)' }}>
                        {p.errors > 0 ? p.errors : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <span className="dim small">No enrichment records.</span>
          )}
        </Panel>
      </div>
    </div>
  );
};

const Emptyish = () => (
  <Panel>
    <div className="empty-state">
      <p>Dashboard data is unavailable.</p>
      <Link to="/investigate" className="btn btn-sm">
        Run an investigation
      </Link>
    </div>
  </Panel>
);
