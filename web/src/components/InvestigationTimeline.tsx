/**
 * InvestigationTimeline - the audit trail of one investigation.
 *
 * Each row is classified by `kind` so the analyst can see at a glance which
 * steps were our own processing (validation, correlation, scoring) and which were
 * external intelligence (provider rows). That distinction is the backbone of the
 * "observed fact vs. external intelligence vs. analyst assessment" split that the
 * report formalises.
 */
import { formatDate, formatRelative } from '../lib/format';

export interface TimelineEntry {
  seq: number;
  at: string;
  kind: string;
  title: string;
  description: string;
  source?: string | null;
  meta?: Record<string, unknown> | null;
}

const KIND_LABEL: Record<string, string> = {
  investigation: 'Pipeline',
  validation: 'Validation',
  provider: 'Enrichment',
  'provider-error': 'Provider error',
  correlation: 'Correlation',
  scoring: 'Risk scoring',
  attack: 'ATT&CK',
  report: 'Report',
  note: 'Analyst note',
};

const KIND_CLASS: Record<string, string> = {
  provider: 'provider',
  'provider-error': 'provider-error',
  scoring: 'scoring',
  attack: 'attack',
  correlation: 'correlation',
  validation: 'validation',
  investigation: 'investigation',
  report: 'report',
};

export const InvestigationTimeline = ({
  entries,
  compact = false,
}: {
  entries: TimelineEntry[];
  compact?: boolean;
}) => {
  if (entries.length === 0) {
    return <div className="empty-state">No timeline events recorded.</div>;
  }

  return (
    <div className="timeline">
      {entries.map((entry) => (
        <div className="tl-item" key={entry.seq}>
          <span className={`tl-dot ${KIND_CLASS[entry.kind] ?? ''}`} />
          <div className="tl-time">
            {formatDate(entry.at)} · {formatRelative(entry.at)}
          </div>
          <div className="tl-title">
            <span className="badge badge-neutral tiny" style={{ marginRight: 8 }}>
              {KIND_LABEL[entry.kind] ?? entry.kind}
            </span>
            {entry.title}
          </div>
          {entry.description && !compact ? <div className="tl-desc">{entry.description}</div> : null}
          {entry.source ? <div className="tl-source">source: {entry.source}</div> : null}
        </div>
      ))}
    </div>
  );
};
