/**
 * Shared Recharts presentation bits.
 *
 * Colours are pulled from the CSS custom properties where possible so the charts
 * cannot drift from the semantic palette used by the badges.
 */
import type { ReactNode } from 'react';
import type { TooltipProps } from 'recharts';

export const ChartTooltip = ({ active, payload, label, labelFormatter }: TooltipProps<number, string> & { labelFormatter?: (l: string) => string }) => {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="chart-tooltip">
      {label !== undefined && label !== null ? (
        <div className="tt-label">{labelFormatter ? labelFormatter(String(label)) : String(label)}</div>
      ) : null}
      {payload.map((entry, index) => (
        <div key={index} className="flex items-center gap-2" style={{ marginTop: 2 }}>
          <span className="detect-swatch" style={{ background: entry.color ?? 'var(--accent)' }} />
          <span className="grow small muted">{entry.name}</span>
          <span className="tt-value">{entry.value}</span>
        </div>
      ))}
    </div>
  );
};

export const ChartFrame = ({
  title,
  subtitle,
  children,
  actions,
  height = 210,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  height?: number;
}) => (
  <section className="panel">
    <header className="panel-head">
      <div>
        <div className="panel-title">{title}</div>
        {subtitle ? <div className="tiny dim mt-2">{subtitle}</div> : null}
      </div>
      {actions}
    </header>
    <div className="panel-body tight" style={{ minHeight: height }}>
      {children}
    </div>
  </section>
);

export const NO_DATA = (
  <div className="empty-state" style={{ minHeight: 120 }}>
    No data yet — run an investigation to populate this chart.
  </div>
);

/** Axis tick formatter for day strings (2026-09-27 -> 27 Sep). */
export const dayTick = (value: string): string => {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { day: '2-digit', month: 'short' });
};
