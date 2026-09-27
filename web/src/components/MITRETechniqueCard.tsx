/**
 * MITRETechniqueCard - renders a technique mapping with its full provenance.
 *
 * The `relationship` string and the `mappingBasis` badge are the whole point:
 * a mapping is only useful if the analyst can see WHY the platform believes the
 * technique applies and which class of evidence produced the claim.
 */
import type { TechniqueMapping } from '../api/types';
import { ConfidenceBadge } from './ui';
import { tacticColour } from '../lib/format';

const BASIS_LABEL: Record<TechniqueMapping['mappingBasis'], string> = {
  'provider-signal': 'Provider-published',
  'behavioural-rule': 'Behavioural rule',
  'malware-family-intel': 'Malware family intel',
};

const BASIS_EXPLAIN: Record<TechniqueMapping['mappingBasis'], string> = {
  'provider-signal': 'An intelligence source explicitly published this technique id for the indicator.',
  'behavioural-rule': 'A documented ThreatLens rule matched normalised intelligence fields for this indicator.',
  'malware-family-intel': 'Derived from publicly documented behaviour of the identified malware family.',
};

export const MITRETechniqueCard = ({ technique }: { technique: TechniqueMapping }) => (
  <article className="tech-card">
    <div className="tech-head">
      <span className="tech-id">{technique.techniqueId}</span>
      <span className="tech-name grow">{technique.name}</span>
      <span className="badge badge-neutral" style={{ borderColor: tacticColour(technique.tactic), color: tacticColour(technique.tactic) }}>
        {technique.tactic}
      </span>
      <ConfidenceBadge confidence={technique.confidence} />
    </div>
    <div className="tech-body">
      <div className="tech-rel">{technique.relationship}</div>
      <div className="tech-desc">{technique.description}</div>
      <div className="flex items-center gap-2 wrap mt-3">
        <span className="tag tiny" title={BASIS_EXPLAIN[technique.mappingBasis]}>
          {BASIS_LABEL[technique.mappingBasis]}
        </span>
        <a className="btn btn-sm btn-ghost" href={technique.reference} target="_blank" rel="noreferrer noopener">
          View on attack.mitre.org ↗
        </a>
      </div>
    </div>
  </article>
);

export const MITRETechniqueList = ({ techniques }: { techniques: TechniqueMapping[] }) => {
  if (techniques.length === 0) {
    return (
      <div className="alert alert-info">
        <span className="alert-icon">i</span>
        <div>
          <strong>No MITRE ATT&amp;CK technique identified.</strong>
          <div className="small mt-2">
            ThreatLens only maps a technique when a documented signal is present: a technique id published by a source, a
            documented behaviour of an identified malware family, or a behavioural rule over the enriched intelligence.
            For this indicator none of those rules matched, so no technique is asserted.
          </div>
        </div>
      </div>
    );
  }

  const byTactic = techniques.reduce<Record<string, TechniqueMapping[]>>((acc, t) => {
    (acc[t.tactic] ??= []).push(t);
    return acc;
  }, {});

  return (
    <div>
      <div className="small muted mb-3">
        {techniques.length} technique{techniques.length === 1 ? '' : 's'} mapped across {Object.keys(byTactic).length} tactic
        {Object.keys(byTactic).length === 1 ? '' : 's'}. Each mapping records the evidence that produced it.
      </div>
      <div className="flex flex-col gap-3">
        {Object.entries(byTactic).map(([tactic, list]) => (
          <div key={tactic} className="tactic-group">
            <div className="tactic-header">
              <span className="tactic-bar" style={{ background: tacticColour(tactic) }} />
              {tactic}
              <span className="dim">({list.length})</span>
            </div>
            <div className="flex flex-col gap-2">
              {list.map((t) => (
                <MITRETechniqueCard key={t.techniqueId} technique={t} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
