/**
 * RiskScoreCard - the headline verdict, and RiskBreakdown - the explanation.
 *
 * The breakdown is the academic centrepiece: it must be possible for a reviewer
 * to take the number away, look at the factors, and reproduce the arithmetic by
 * hand. Nothing here is hidden, rounded away, or "explained" vaguely.
 */
import { RISK_COLOUR, formatNumber, pluralise } from '../lib/format';
import type { InvestigationDetail } from '../api/client';
import { RiskBadge, VerdictBadge } from './ui';
import type { RiskFactor } from '../api/types';

export const RiskScoreCard = ({ detail }: { detail: InvestigationDetail }) => {
  const { assessment } = detail;
  const positives = assessment.factors.filter((f) => f.points > 0);
  const offsets = assessment.factors.filter((f) => f.points <= 0);
  const positiveSum = positives.reduce((acc, f) => acc + f.points, 0);
  const offsetSum = offsets.reduce((acc, f) => acc + f.points, 0);
  const colour = RISK_COLOUR[assessment.level];
  const insufficient = detail.counts.ok === 0;

  return (
    <section className="panel">
      <header className="panel-head">
        <div className="panel-title">Risk assessment</div>
        <div className="flex items-center gap-2">
          {detail.mode === 'demo' ? <span className="badge badge-demo">DEMO DATA</span> : <span className="badge badge-clean">LIVE</span>}
        </div>
      </header>

      <div className="panel-body">
        {insufficient ? (
          <div className="alert alert-danger mb-4">
            <span className="alert-icon">!</span>
            <div>
              <strong>Risk score not assigned — no usable intelligence.</strong>
              <div className="small mt-2">
                Every configured source either returned nothing or failed, so ThreatLens has no evidence to score. A score
                of 0 here would be misleading, so the platform reports insufficient intelligence instead of implying the
                indicator is clean.
              </div>
            </div>
          </div>
        ) : null}

        <div className="risk-dial">
          <div>
            <div className="risk-number" style={{ color: insufficient ? 'var(--unknown)' : colour }}>
              {insufficient ? '—' : assessment.score}
            </div>
            <div className="risk-max">/ 100</div>
          </div>
          <div className="grow">
            <div className="flex items-center gap-2 mb-2 wrap">
              {insufficient ? <span className="badge badge-unknown">INSUFFICIENT INTELLIGENCE</span> : <RiskBadge level={assessment.level} />}
              <VerdictBadge verdict={assessment.verdict} />
            </div>
            <div className="small muted">
              {insufficient
                ? 'No source returned a reputation verdict for this indicator.'
                : `Computed from ${pluralise(assessment.factors.length, 'scoring factor')} across ${pluralise(
                    detail.counts.ok,
                    'intelligence source',
                  )}.`}
            </div>
            {assessment.clamped && !insufficient ? (
              <div className="tiny mt-2" style={{ color: 'var(--medium)' }}>
                Raw factor sum {assessment.rawScore} was clamped to the 0-100 scale. The clamp is disclosed rather than
                hidden so the arithmetic can still be audited.
              </div>
            ) : null}
          </div>
        </div>

        <div className="grid grid-2 mt-4" style={{ marginTop: 18 }}>
          <div>
            <div className="tiny dim mb-2">Positive factors</div>
            <div className="flex items-baseline gap-2">
              <span className="mono" style={{ color: 'var(--high)', fontSize: 20, fontWeight: 700 }}>
                +{positiveSum}
              </span>
              <span className="small muted">from {pluralise(positives.length, 'rule')}</span>
            </div>
          </div>
          <div>
            <div className="tiny dim mb-2">Offsets</div>
            <div className="flex items-baseline gap-2">
              <span className="mono" style={{ color: 'var(--clean)', fontSize: 20, fontWeight: 700 }}>
                {offsetSum}
              </span>
              <span className="small muted">from {pluralise(offsets.length, 'rule')}</span>
            </div>
          </div>
        </div>

        <div className="flex gap-2 wrap mt-4" style={{ marginTop: 16 }}>
          <div className="kv grow" style={{ minWidth: 210 }}>
            <dt>Confidence</dt>
            <dd className="mono">
              {detail.assessment.confidenceScore}% <span className="dim">({detail.assessment.confidenceLabel})</span>
            </dd>
          </div>
          <div className="kv grow" style={{ minWidth: 210 }}>
            <dt>Corroborating sources</dt>
            <dd className="mono">{formatNumber(detail.reputation.corroborationCount)}</dd>
          </div>
        </div>
      </div>
    </section>
  );
};

const FactorRow = ({ factor }: { factor: RiskFactor }) => (
  <div className="factor">
    <div className={`factor-points ${factor.points > 0 ? 'pos' : 'neg'}`}>
      {factor.points > 0 ? `+${factor.points}` : factor.points}
    </div>
    <div className="grow">
      <div className="factor-label">{factor.label}</div>
      <div className="factor-evidence">{factor.evidence}</div>
      {factor.sources.length > 0 ? (
        <div className="factor-sources">
          {factor.sources.map((s) => (
            <span key={s} className="tag tiny">
              {s}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  </div>
);

export const RiskBreakdown = ({ detail, showMethodology = true }: { detail: InvestigationDetail; showMethodology?: boolean }) => {
  const { assessment } = detail;
  const positives = assessment.factors.filter((f) => f.points > 0);
  const offsets = assessment.factors.filter((f) => f.points <= 0);

  if (assessment.factors.length === 0) {
    return (
      <section className="panel">
        <header className="panel-head">
          <div className="panel-title">Risk score explanation</div>
        </header>
        <div className="panel-body">
          <AlertBox>
            No scoring rule matched the available evidence, so the score is 0/100. This is a *positive* result: every
            documented factor was evaluated and none applied.
          </AlertBox>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <header className="panel-head">
        <div className="panel-title">Risk score explanation</div>
        <span className="badge badge-neutral">deterministic</span>
      </header>
      <div className="panel-body">
        {positives.length > 0 ? (
          <>
            <div className="section-title">Contributing factors</div>
            {positives.map((f) => (
              <FactorRow key={f.id} factor={f} />
            ))}
          </>
        ) : null}

        {offsets.length > 0 ? (
          <>
            <div className="section-title mt-4" style={{ marginTop: 18 }}>
              Offsets (reduce risk)
            </div>
            {offsets.map((f) => (
              <FactorRow key={f.id} factor={f} />
            ))}
          </>
        ) : null}

        <div className="factor-total">
          <span>
            Total = {positives.reduce((a, f) => a + f.points, 0)} {offsets.length ? `${offsets.reduce((a, f) => a + f.points, 0)}` : ''}
            {assessment.clamped ? ` (raw ${assessment.rawScore} → clamped 100)` : ''}
          </span>
          <span style={{ color: RISK_COLOUR[assessment.level] }}>{assessment.score}/100 · {assessment.level}</span>
        </div>

        {showMethodology ? (
          <details className="mt-4" style={{ marginTop: 16 }}>
            <summary className="small muted" style={{ cursor: 'pointer' }}>
              Scoring methodology (all rules and caps)
            </summary>
            <p className="small dim mt-3" style={{ lineHeight: 1.7 }}>
              {assessment.methodology}
            </p>
          </details>
        ) : null}
      </div>
    </section>
  );
};

const AlertBox = ({ children }: { children: React.ReactNode }) => (
  <div className="alert alert-info">
    <span className="alert-icon">i</span>
    <div>{children}</div>
  </div>
);
