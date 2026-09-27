/**
 * ReportGenerator - produces and exports the CTI investigation report.
 *
 * The on-screen preview renders the *same* structured report object the server
 * sends to the PDF renderer, so what the analyst reviews is what gets exported.
 * Each section is tagged with its evidence class, which is the academic
 * requirement that the report separate observed facts, external intelligence and
 * analyst assessment.
 */
import { useState } from 'react';
import { api, type InvestigationDetail } from '../api/client';
import { Alert, Panel, PanelFlush, RiskBadge } from './ui';
import { ConfidenceBadge, DemoBadge } from './ui';
import { formatDate, formatNumber, formatPercent, relationLabel } from '../lib/format';

/** The report object as produced by server/src/services/reportBuilder.ts */
interface ReportSection {
  id: string;
  title: string;
  classification: 'observed-fact' | 'external-intelligence' | 'analyst-assessment' | 'context';
  body: string;
  bullets?: string[];
  table?: { headers: string[]; rows: string[][] };
}

interface Report {
  reportId: string;
  title: string;
  generatedAt: string;
  classification: { label: string; note: string };
  investigation: { reference: string; analyst: string; status: string; mode: string; openedAt: string; completedAt: string | null; durationMs: number | null };
  executiveSummary: { verdict: string; riskScore: number; riskLevel: string; confidenceScore: number; narrative: string; keyFindings: string[] };
  provenance: { dataOrigin: string; demoDataUsed: boolean; providers: string[]; notes: string[] };
  sections: ReportSection[];
}

const EVIDENCE_LABEL: Record<ReportSection['classification'], string> = {
  'observed-fact': 'Observed fact',
  'external-intelligence': 'External intelligence',
  'analyst-assessment': 'Analyst assessment',
  context: 'Context / caveat',
};

export const ReportGenerator = ({ detail }: { detail: InvestigationDetail }) => {
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = (await api.report(detail.id)) as unknown as Report;
      setReport(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The report could not be generated.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <Panel>
        <div className="flex items-center justify-between gap-3 wrap">
          <div>
            <div className="panel-title mb-2">Threat intelligence report</div>
            <p className="small muted" style={{ maxWidth: 620, margin: 0 }}>
              Generates an 11-section investigation report from the stored evidence. Every section is labelled with its
              evidence class, and the report records the provenance of every intelligence claim. Export as PDF for
              submission or JSON for machine ingestion.
            </p>
          </div>
          <div className="flex gap-2">
            <button className="btn" type="button" onClick={generate} disabled={loading}>
              {loading ? <span className="spinner" /> : <span aria-hidden="true">⎙</span>}
              {report ? 'Regenerate' : 'Generate report'}
            </button>
            <a
              className={`btn btn-primary ${report ? '' : 'btn-disabled'}`}
              href={api.exportUrl(detail.id, 'pdf')}
              aria-disabled={!report}
              onClick={(e) => {
                if (!report) e.preventDefault();
              }}
            >
              Export PDF
            </a>
            <a
              className="btn"
              href={api.exportUrl(detail.id, 'json')}
              aria-disabled={!report}
              onClick={(e) => {
                if (!report) e.preventDefault();
              }}
            >
              Export JSON
            </a>
            <a
              className="btn btn-ghost"
              href={api.exportUrl(detail.id, 'md')}
              aria-disabled={!report}
              onClick={(e) => {
                if (!report) e.preventDefault();
              }}
              title="Markdown export"
            >
              MD
            </a>
          </div>
        </div>

        {error ? (
          <div className="mt-3">
            <Alert kind="danger">{error}</Alert>
          </div>
        ) : null}

        {!report ? (
          <div className="mt-3 small dim">
            The preview is generated on demand so the page stays fast. Exports are always available directly from the API
            and are generated from the same report object.
          </div>
        ) : null}
      </Panel>

      {report ? (
        <div className="flex flex-col gap-3">
          <Panel>
            <div className="flex items-center gap-2 wrap mb-3">
              <span className="badge badge-medium">{report.classification.label}</span>
              {report.provenance.demoDataUsed ? <DemoBadge /> : <span className="badge badge-clean">LIVE INTELLIGENCE</span>}
              <span className="mono tiny dim">{report.reportId}</span>
              <span className="tiny dim">generated {formatDate(report.generatedAt)}</span>
            </div>
            <h2 style={{ marginBottom: 10 }}>{report.title}</h2>
            <p className="small" style={{ color: 'var(--ink-1)' }}>
              {report.executiveSummary.narrative}
            </p>
            <div className="flex gap-2 wrap mt-3">
              <span className="badge badge-neutral">
                Risk {report.executiveSummary.riskScore}/100
              </span>
              <RiskBadge level={report.executiveSummary.riskLevel as never} />
              <span className="badge badge-neutral">Confidence {report.executiveSummary.confidenceScore}%</span>
              <span className="badge badge-neutral">Verdict {report.executiveSummary.verdict}</span>
            </div>
            <ul className="small muted mt-3" style={{ paddingLeft: 18, lineHeight: 1.8 }}>
              {report.executiveSummary.keyFindings.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </Panel>

          <Panel title="Provenance and caveats" bodyClass="tight">
            <div className="small">
              <div className="mb-2">
                <span className="dim">Data origin: </span>
                <strong>{report.provenance.dataOrigin}</strong>
              </div>
              <div className="mb-3">
                <span className="dim">Sources: </span>
                <span className="mono tiny">{report.provenance.providers.join(', ')}</span>
              </div>
              <ul className="muted" style={{ paddingLeft: 18, lineHeight: 1.75 }}>
                {report.provenance.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
          </Panel>

          {report.sections.map((section) => (
            <section className="report-section" key={section.id}>
              <div className="report-heading">
                {section.title}
                <span className={`evidence-class evidence-${section.classification}`}>{EVIDENCE_LABEL[section.classification]}</span>
              </div>
              <p className="small muted">{section.body}</p>
              {section.table ? (
                <div className="table-wrap">
                  <table className="report-table">
                    <thead>
                      <tr>
                        {section.table.headers.map((h) => (
                          <th key={h}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {section.table.rows.map((row, i) => (
                        <tr key={i}>
                          {row.map((cell, j) => (
                            <td key={j} className={j === 0 ? 'mono' : undefined}>
                              {cell}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
              {section.bullets ? (
                <ul className="small muted" style={{ paddingLeft: 18, lineHeight: 1.75 }}>
                  {section.bullets.map((b) => (
                    <li key={b}>{b}</li>
                  ))}
                </ul>
              ) : null}
            </section>
          ))}
        </div>
      ) : null}
    </div>
  );
};

/** Compact defensive-actions panel (used on the result page, not the report). */
export const RecommendationsPanel = ({ detail }: { detail: InvestigationDetail }) => {
  const [copied, setCopied] = useState<string | null>(null);
  const byPriority = [1, 2, 3].map((p) => detail.recommendations.filter((r) => r.priority === p));

  return (
    <PanelFlush title="Recommended defensive actions" actions={<span className="badge badge-neutral">defensive only</span>}>
      <div className="panel-body">
        <p className="small muted">
          Actions are selected by rule from the indicator type, the assessed risk level and the observed behaviour, so the
          checklist is deterministic. Everything here is containment, detection engineering, eradication, hunting or
          monitoring.
        </p>
        <div className="flex flex-col gap-2 mt-3">
          {byPriority.map((group, gi) =>
            group.map((action) => (
              <div className="rec" key={action.id}>
                <div className={`rec-priority rec-p${action.priority}`} title={`Priority ${action.priority}`}>
                  P{action.priority}
                </div>
                <div className="grow">
                  <div className="flex items-center gap-2 wrap">
                    <span className="rec-title">{action.title}</span>
                    <span className="badge badge-neutral tiny">{action.category}</span>
                    {gi === 0 && action.priority === 1 ? <span className="badge badge-critical tiny">before end of shift</span> : null}
                  </div>
                  <div className="rec-detail">{action.detail}</div>
                  {action.searchQuery ? (
                    <div className="rec-query">
                      <span className="dim">hunt query: </span>
                      {action.searchQuery}
                      <button
                        className="btn btn-sm btn-ghost"
                        style={{ marginLeft: 8 }}
                        type="button"
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(action.searchQuery!);
                            setCopied(action.id);
                            window.setTimeout(() => setCopied(null), 1400);
                          } catch {
                            /* clipboard unavailable */
                          }
                        }}
                      >
                        {copied === action.id ? '✓' : 'copy'}
                      </button>
                    </div>
                  ) : null}
                </div>
              </div>
            )),
          )}
        </div>
      </div>
    </PanelFlush>
  );
};

/** Summary strip reused at the top of the result page. */
export const VerdictStrip = ({ detail }: { detail: InvestigationDetail }) => (
  <div className="flex gap-3 wrap">
    <span className="badge badge-neutral">
      {detail.counts.ok}/{detail.counts.providers} sources
    </span>
    {detail.counts.techniques > 0 ? (
      <span className="badge badge-accent">{detail.counts.techniques} ATT&CK techniques</span>
    ) : null}
    {detail.counts.related > 0 ? <span className="badge badge-neutral">{detail.counts.related} related indicators</span> : null}
    {detail.reputation.reports !== null ? (
      <span className="badge badge-neutral">{formatNumber(detail.reputation.reports)} reports</span>
    ) : null}
    {detail.reputation.detections ? (
      <span className="badge badge-neutral">{formatPercent(detail.reputation.detections.ratio)} detection ratio</span>
    ) : null}
    {detail.assessment.clamped ? <span className="badge badge-medium">raw {detail.assessment.rawScore} → clamped</span> : null}
    <ConfidenceBadge confidence={detail.assessment.confidenceLabel} />
    {detail.warnings.length > 0 ? <span className="badge badge-medium">{detail.warnings.length} validation warnings</span> : null}
  </div>
);

export { relationLabel };
