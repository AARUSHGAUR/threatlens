/** Reusable analyst-facing UI primitives. */
import { useState, type ReactNode } from 'react';
import { RISK_CLASS, VERDICT_CLASS, VERDICT_LABEL, CONFIDENCE_LABEL } from '../lib/format';
import type { Confidence, IocType, RiskLevel, Verdict } from '../api/types';
import { copyToClipboard, IOC_TYPE_LABEL } from '../lib/format';

export const Panel = ({
  title,
  subtitle,
  actions,
  children,
  bodyClass = '',
  className = '',
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  bodyClass?: string;
  className?: string;
}) => (
  <section className={`panel ${className}`}>
    {(title || actions) && (
      <header className="panel-head">
        <div>
          {title ? <div className="panel-title">{title}</div> : null}
          {subtitle ? <div className="tiny dim" style={{ marginTop: 3 }}>{subtitle}</div> : null}
        </div>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </header>
    )}
    <div className={`panel-body ${bodyClass}`}>{children}</div>
  </section>
);

export const PanelFlush = ({
  title,
  subtitle,
  actions,
  children,
  bodyClass = '',
  className = '',
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  bodyClass?: string;
  className?: string;
}) => (
  <section className={`panel ${className}`}>
    {(title || actions) && (
      <header className="panel-head">
        <div>
          {title ? <div className="panel-title">{title}</div> : null}
          {subtitle ? <div className="tiny dim" style={{ marginTop: 3 }}>{subtitle}</div> : null}
        </div>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </header>
    )}
    <div className={bodyClass}>{children}</div>
  </section>
);

export const Alert = ({
  kind = 'info',
  title,
  children,
  icon,
}: {
  kind?: 'info' | 'danger' | 'warning' | 'success' | 'demo';
  title?: ReactNode;
  children?: ReactNode;
  icon?: ReactNode;
}) => (
  <div className={`alert alert-${kind}`}>
    <span className="alert-icon">{icon ?? (kind === 'danger' ? '!' : kind === 'warning' ? '!' : kind === 'success' ? '✓' : 'i')}</span>
    <div className="grow">
      {title ? <strong>{title}</strong> : null}
      {title && children ? <br /> : null}
      {children}
    </div>
  </div>
);

export const EmptyState = ({ children }: { children: ReactNode }) => <div className="empty-state">{children}</div>;

export const Loading = ({ label = 'Loading' }: { label?: string }) => (
  <div className="empty-state flex items-center gap-3" style={{ justifyContent: 'center' }}>
    <span className="spinner" />
    <span className="small">{label}…</span>
  </div>
);

export const ErrorState = ({ error, onRetry }: { error: Error; onRetry?: () => void }) => (
  <div className="empty-state">
    <Alert kind="danger" title="Request failed">
      {error.message}
      {onRetry ? (
        <div className="mt-2">
          <button className="btn btn-sm" onClick={onRetry} type="button">
            Retry
          </button>
        </div>
      ) : null}
    </Alert>
  </div>
);

/**
 * ThreatIndicatorBadge - the semantic indicator used everywhere.
 * Colour is reserved for risk/verdict state only.
 */
export const RiskBadge = ({ level, size }: { level: RiskLevel; size?: 'sm' }) => (
  <span className={`badge ${RISK_CLASS[level]}`} style={size === 'sm' ? { fontSize: 9.5, padding: '1px 6px' } : undefined}>
    <span className="badge-dot" />
    {level}
  </span>
);

export const VerdictBadge = ({ verdict }: { verdict: Verdict }) => (
  <span className={`badge ${VERDICT_CLASS[verdict]}`}>{VERDICT_LABEL[verdict]}</span>
);

export const ConfidenceBadge = ({ confidence }: { confidence: Confidence }) => (
  <span className={`badge ${confidence === 'high' ? 'badge-clean' : confidence === 'medium' ? 'badge-medium' : 'badge-unknown'}`}>
    {CONFIDENCE_LABEL[confidence]}
  </span>
);

export const IocTypeBadge = ({ type }: { type: IocType }) => (
  <span className="badge badge-neutral" title={`Indicator type: ${IOC_TYPE_LABEL[type]}`}>
    {IOC_TYPE_LABEL[type]}
  </span>
);

export const DemoBadge = ({ label = 'DEMO DATA' }: { label?: string }) => (
  <span className="badge badge-demo" title="Simulated intelligence from the built-in ThreatLens demonstration dataset - not a real API response.">
    {label}
  </span>
);

export const StatusBadge = ({ status }: { status: string }) => {
  const map: Record<string, string> = {
    completed: 'badge-clean',
    partial: 'badge-medium',
    failed: 'badge-critical',
    pending: 'badge-neutral',
    enriching: 'badge-accent',
    analyzing: 'badge-accent',
  };
  return <span className={`badge ${map[status] ?? 'badge-neutral'}`}>{status}</span>;
};

export const KV = ({ items }: { items: Array<{ label: ReactNode; value: ReactNode; empty?: boolean }> }) => (
  <dl className="kv">
    {items.map((item, index) => (
      <div key={index} style={{ display: 'contents' }}>
        <dt>{item.label}</dt>
        <dd className={item.empty || item.value === '—' || item.value === null || item.value === undefined ? 'empty' : ''}>
          {item.value ?? '—'}
        </dd>
      </div>
    ))}
  </dl>
);

export const TagList = ({
  values,
  mono = false,
  onClick,
  max,
}: {
  values: string[];
  mono?: boolean;
  onClick?: (value: string) => void;
  max?: number;
}) => {
  if (values.length === 0) return <span className="dim small">None reported</span>;
  const shown = max ? values.slice(0, max) : values;
  return (
    <div className="flex wrap gap-2">
      {shown.map((v) =>
        onClick ? (
          <button key={v} type="button" className={`tag ${mono ? 'tag-mono' : ''}`} onClick={() => onClick(v)} title={`Investigate ${v}`}>
            {v}
          </button>
        ) : (
          <span key={v} className={`tag ${mono ? 'tag-mono' : ''}`}>
            {v}
          </span>
        ),
      )}
      {max && values.length > max ? <span className="tag dim">+{values.length - max} more</span> : null}
    </div>
  );
};

export const CopyButton = ({ value, label = 'Copy' }: { value: string; label?: string }) => {
  const [copied, setCopied] = useState(false);
  const handle = async () => {
    if (await copyToClipboard(value)) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    }
  };
  return (
    <button type="button" className="btn btn-sm btn-ghost" onClick={handle} aria-label={`Copy ${value} to clipboard`}>
      {copied ? '✓ Copied' : label}
    </button>
  );
};

/** Horizontal risk meter with the five semantic bands marked. */
export const RiskMeter = ({ score, level }: { score: number; level: RiskLevel }) => (
  <div>
    <div className="meter-segments" role="img" aria-label={`Risk score ${score} of 100, level ${level}`}>
      {Array.from({ length: 20 }, (_, i) => {
        const position = (i + 1) * 5;
        const active = position <= score;
        const band = position <= 20 ? 'clean' : position <= 40 ? 'low' : position <= 60 ? 'medium' : position <= 80 ? 'high' : 'critical';
        return <span key={i} className={`meter-seg ${active ? `on-${band}` : ''}`} />;
      })}
    </div>
    <div className="flex justify-between tiny dim mt-2" style={{ marginTop: 4 }}>
      <span>0</span>
      <span>20</span>
      <span>40</span>
      <span>60</span>
      <span>80</span>
      <span>100</span>
    </div>
  </div>
);
