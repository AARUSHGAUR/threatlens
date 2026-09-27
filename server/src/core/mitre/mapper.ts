/**
 * ============================================================================
 * MITRE ATT&CK MAPPING ENGINE  (CTI lifecycle: "Analysis")
 * ============================================================================
 *
 * DESIGN PRINCIPLE: "Do not assign techniques randomly."
 *
 * A technique is only mapped when a *documented, observable* signal is present
 * in the investigation. Three kinds of evidence are accepted, and every mapping
 * records which one produced it (`mappingBasis`):
 *
 *   1. provider-signal     - an intelligence source explicitly published the
 *                            technique id (e.g. an OTX pulse tagged T1059.001).
 *                            Confidence: medium (a third-party assertion).
 *   2. malware-family-intel- a documented behaviour of an *identified* malware
 *                            family (either from the demo catalog or from the
 *                            public family reference table below).
 *                            Confidence: high / medium.
 *   3. behavioural-rule    - a deterministic rule over normalised intelligence
 *                            fields (verdict, behaviours, categories, IOC type,
 *                            parsed URL features). Confidence: medium / low.
 *
 * If no rule fires, the engine returns an empty list and the UI states
 * "No MITRE ATT&CK technique identified." - which is the correct, honest
 * outcome for e.g. a clean public DNS resolver.
 */
import type {
  Confidence,
  NormalizedIoc,
  ProviderVerdict,
  TechniqueMapping,
} from '../types.js';
import { techniqueView } from '../../providers/mitre/index.js';

/** Publicly documented technique behaviour of commonly reported malware families. */
const FAMILY_TECHNIQUES: Array<{ match: RegExp; techniques: string[]; note: string }> = [
  {
    match: /cobalt\s*strike|beacon/i,
    techniques: ['T1059.001', 'T1071.001', 'T1105', 'T1055', 'T1218', 'T1055.012'],
    note: 'Cobalt Strike Beacon is publicly documented to use PowerShell, HTTP(S) C2, tool transfer, process injection and signed-binary proxy execution.',
  },
  {
    match: /emotet/i,
    techniques: ['T1566.001', 'T1204.002', 'T1105', 'T1059.003', 'T1071.001'],
    note: 'Emotet is publicly documented to spread via malicious attachments, execute via the Windows command shell and distribute follow-on payloads.',
  },
  {
    match: /qakbot|qbot/i,
    techniques: ['T1566.001', 'T1059.001', 'T1105', 'T1071.001', 'T1218'],
    note: 'QakBot is publicly documented to use PowerShell, download payloads and communicate over HTTP(S).',
  },
  {
    match: /trickbot|trickloader/i,
    techniques: ['T1566.001', 'T1059.001', 'T1105', 'T1071.001', 'T1218', 'T1003'],
    note: 'TrickBot publicly uses malicious documents, PowerShell execution and web-protocol C2.',
  },
  {
    match: /agent\s*tesla/i,
    techniques: ['T1566.001', 'T1056.003', 'T1071.001', 'T1041', 'T1113', 'T1005'],
    note: 'Agent Tesla is publicly documented to phish credentials, keylog and exfiltrate over HTTP(S).',
  },
  {
    match: /redline|vidar|raccoon|stealc|vidar stealer/i,
    techniques: ['T1056.003', 'T1005', 'T1041', 'T1071.001', 'T1566.001'],
    note: 'Commodity stealer families are publicly documented to harvest browser credentials locally and exfiltrate over web protocols.',
  },
  {
    match: /asyncrat|njrat|remcos|quasar|darkcomet/i,
    techniques: ['T1059.001', 'T1071.001', 'T1105', 'T1113', 'T1547.001'],
    note: 'Commercial or leaked commodity RATs are publicly documented to run via PowerShell, persist through run keys and use web-protocol C2.',
  },
  {
    match: /formbook|formbook-xlsx| Snake ?Excel/i,
    techniques: ['T1566.002', 'T1204.002', 'T1105', 'T1059.001'],
    note: 'Formbook variants are publicly documented to use spearphishing links to deliver macro-enabled documents.',
  },
  {
    match: /icedid|bazarloader|aurora|evilnum/i,
    techniques: ['T1105', 'T1071.001', 'T1059.001', 'T1566.002'],
    note: 'Loader families publicly use web-protocol payload download and PowerShell execution.',
  },
  {
    match: /mimikatz|mimilib/i,
    techniques: ['T1003.001', 'T1059.001'],
    note: 'Credential dumping tooling of the Mimikatz family maps to LSASS memory access executed through PowerShell.',
  },
  {
    match: /netscaler|citrix|exchange|exchange server/i,
    techniques: ['T1190', 'T1059.001', 'T1218'],
    note: 'Publicly reported appliance exploitation chains begin with exploitation of an internet-facing application.',
  },
];

/** Technique ids that are not present in the curated catalog are filtered out. */
const isKnownTechnique = (id: string): boolean => techniqueView(id) !== null;

const ATTACK_ID_RE = /\b(T\d{4}(?:\.\d{3})?)\b/g;

interface Accumulator {
  mappings: Map<string, TechniqueMapping>;
}

const add = (
  acc: Accumulator,
  techniqueId: string,
  relationship: string,
  confidence: Confidence,
  basis: TechniqueMapping['mappingBasis'],
): void => {
  if (!isKnownTechnique(techniqueId)) return;
  const view = techniqueView(techniqueId);
  if (!view) return;
  const existing = acc.mappings.get(techniqueId);
  const rank: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };
  if (existing && rank[existing.confidence] >= rank[confidence]) {
    // Keep the strongest confidence but remember the additional rationale.
    if (!existing.relationship.includes(relationship)) {
      existing.relationship = `${existing.relationship} ${relationship}`;
    }
    return;
  }
  acc.mappings.set(techniqueId, {
    techniqueId,
    name: view.name,
    tactic: view.primaryTactic,
    tacticPhase: view.relation,
    description: view.description,
    relationship,
    confidence,
    reference: view.reference,
    mappingBasis: basis,
  });
};

export interface MappingInput {
  ioc: NormalizedIoc;
  verdicts: ProviderVerdict[];
  /** Behaviours derived by the aggregation layer (union of provider behaviours). */
  behaviours: string[];
  categories: string[];
  malwareNames: string[];
  actorNames: string[];
  /** Optional extra signal: non-standard port observed, high entropy host, ... */
  signals: {
    nonStandardPort: boolean;
    punycode: boolean;
    highEntropy: boolean;
    deepSubdomain: boolean;
    newlyRegistered: boolean;
    documentationRange: boolean;
  };
}

/**
 * Deterministic mapping. Same intelligence in -> same techniques out.
 */
export function mapTechniques(input: MappingInput): TechniqueMapping[] {
  const acc: Accumulator = { mappings: new Map() };
  const { ioc, verdicts, behaviours, categories, malwareNames, signals } = input;

  const behaviourSet = new Set(behaviours.map((b) => b.toLowerCase()));
  const categoryBlob = categories.join(' ').toLowerCase();
  const has = (...needles: string[]): boolean => needles.some((n) => behaviourSet.has(n));
  const cat = (...needles: string[]): boolean => needles.some((n) => categoryBlob.includes(n));

  const verdictIsMalicious = verdicts.some((v) => v.verdict === 'malicious');
  const anyReputationSignal =
    verdictIsMalicious || has('c2', 'malware-delivery', 'phishing', 'credential-harvesting') || cat('c2', 'phishing', 'malware', 'trojan', 'rat', 'downloader', 'infostealer');

  // ---------------------------------------------------------------------------
  // RULE GROUP 1 - explicit technique identifiers published by a provider.
  // ---------------------------------------------------------------------------
  for (const verdict of verdicts) {
    const blob = [
      ...verdict.related.categories,
      ...verdict.related.behaviours,
      ...verdict.related.campaigns,
    ].join(' ');
    for (const match of blob.matchAll(ATTACK_ID_RE)) {
      const id = match[1];
      if (!isKnownTechnique(id)) continue;
      add(
        acc,
        id,
        `Technique ${id} was explicitly published by ${verdict.providerName} for this indicator.`,
        verdict.origin === 'live' ? 'medium' : 'high',
        'provider-signal',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // RULE GROUP 2 - documented behaviour of an identified malware family.
  // ---------------------------------------------------------------------------
  for (const family of malwareNames) {
    if (!family) continue;
    const entry = FAMILY_TECHNIQUES.find((f) => f.match.test(family));
    if (!entry) continue;
    for (const id of entry.techniques) {
      if (!isKnownTechnique(id)) continue;
      add(acc, id, `${entry.note} (family reported as "${family}").`, 'medium', 'malware-family-intel');
    }
  }

  // ---------------------------------------------------------------------------
  // RULE GROUP 3 - behavioural rules over normalised intelligence.
  // ---------------------------------------------------------------------------

  // 3a. Command and control
  if (has('c2')) {
    const scheme = ioc.parsed.scheme?.toLowerCase();
    if (ioc.type === 'url') {
      if (scheme === 'https' || scheme === 'http') {
        add(
          acc,
          'T1071.001',
          'Intelligence sources classify this URL as command-and-control traffic carried over HTTP(S), which blends with normal web browsing.',
          'high',
          'behavioural-rule',
        );
      } else {
        add(acc, 'T1071', 'This URL is reported as a C2 endpoint using a non-web application protocol.', 'medium', 'behavioural-rule');
      }
    } else {
      add(
        acc,
        'T1071.001',
        `Sources tag this ${ioc.type.toUpperCase()} indicator as command-and-control infrastructure, which is characteristically reached over web protocols.`,
        'medium',
        'behavioural-rule',
      );
    }
    // Non-standard port alongside C2 is a separate, observable behaviour.
    if (signals.nonStandardPort) {
      add(
        acc,
        'T1571',
        `The C2 endpoint was observed on a non-standard port${ioc.parsed.port ? ` (${ioc.parsed.port})` : ''}, which is used to avoid default-service detection.`,
        'medium',
        'behavioural-rule',
      );
    }
  }

  // 3a-bis. Dynamic resolution. Deliberately OUTSIDE the C2 branch: an
  // algorithmically generated hostname is observable evidence of dynamic
  // resolution even when the host is not (yet) confirmed as C2.
  if (has('dga-like-hosting', 'fast-flux-like', 'dga')) {
    add(
      acc,
      'T1568.002',
      'Hosting indicators (algorithmically generated or rapidly rotated names) are consistent with dynamic DNS-based resolution used to survive blocklisting.',
      'low',
      'behavioural-rule',
    );
  }

  // 3b. Tool transfer / payload staging
  if (has('malware-delivery', 'payload-online', 'payload-offline') || (ioc.type === 'url' && cat('malware', 'downloader', 'payload', 'trojan'))) {
    add(
      acc,
      'T1105',
      ioc.type === 'url'
        ? 'This URL directly serves a malicious payload, which is the observable form of ingress tool transfer.'
        : 'This host is reported as distributing or serving malicious tooling, indicating an ingress transfer channel.',
      'high',
      'behavioural-rule',
    );
  }

  // 3c. Phishing
  if (has('phishing') || cat('phishing', 'spearphishing')) {
    const isLure =
      ioc.type === 'url' || ioc.type === 'domain' || ioc.type === 'email' || has('credential-harvesting');
    if (isLure) {
      add(
        acc,
        'T1566.002',
        ioc.type === 'email'
          ? 'This address was observed as the sender of spearphishing messages that direct victims to a malicious page.'
          : 'This indicator is a phishing lure (link or landing page) rather than a payload, which matches spearphishing-link delivery.',
        'high',
        'behavioural-rule',
      );
    } else {
      add(
        acc,
        'T1566',
        `Phishing was reported against infrastructure at this ${ioc.type.toUpperCase()} address; the host is a secondary artefact of the campaign rather than the lure itself.`,
        'medium',
        'behavioural-rule',
      );
    }
    if (has('credential-harvesting')) {
      add(
        acc,
        'T1056.003',
        'The indicator is associated with a web portal that captures credentials as they are typed.',
        'high',
        'behavioural-rule',
      );
      add(
        acc,
        'T1185',
        'Credential-harvesting kits commonly inject or steal session cookies so the session can be replayed, a documented companion behaviour.',
        'low',
        'behavioural-rule',
      );
    }
  }

  // 3d. Fake update / malicious file execution chain
  if (cat('fake-update') || has('malware-delivery')) {
    add(
      acc,
      'T1204.002',
      'The lure relies on a user executing a downloaded file (fake update or script), so user-execution behaviour is part of the chain.',
      'medium',
      'behavioural-rule',
    );
  }

  // 3e. Script-based indicator
  if (cat('powershell', 'script') || has('powershell')) {
    add(
      acc,
      'T1059.001',
      'Intelligence links this indicator to PowerShell-based execution, which is the command interpreter used for post-exploitation scripting.',
      'medium',
      'behavioural-rule',
    );
  }

  // 3f. Commodity stealer behaviours
  if (cat('infostealer', 'credential-theft')) {
    add(
      acc,
      'T1005',
      'A stealer family collects data from the local system (browsers, wallets, documents) before exfiltration.',
      'medium',
      'malware-family-intel',
    );
    add(
      acc,
      'T1041',
      'Stolen data is typically exfiltrated over the same HTTP(S) channel used for delivery and C2.',
      'low',
      'behavioural-rule',
    );
  }

  // 3g. RAT / implant behaviours
  if (cat('rat', 'implant') || has('c2') ) {
    if (has('c2')) {
      add(
        acc,
        'T1055',
        'Remote-access implants of this type are publicly documented to inject into a signed host process to evade endpoint controls.',
        'low',
        'malware-family-intel',
      );
      add(
        acc,
        'T1070.004',
        'The same implant family is publicly documented to delete its staging artefacts after execution, an anti-forensic behaviour.',
        'low',
        'malware-family-intel',
      );
    }
  }

  // 3h. Loader persistence
  if (cat('downloader', 'loader')) {
    add(
      acc,
      'T1053.005',
      'Loader stages commonly establish persistence with a scheduled task before fetching the second stage.',
      'low',
      'malware-family-intel',
    );
  }

  // 3i. Resource development: attribution implies infrastructure acquisition
  if (input.actorNames.length > 0 && (ioc.type === 'domain' || ioc.type === 'url')) {
    add(
      acc,
      signals.newlyRegistered ? 'T1583.001' : 'T1584.001',
      signals.newlyRegistered
        ? 'Attribution to a named cluster plus a young domain registration is consistent with infrastructure acquired for this campaign.'
        : 'Attribution to a named cluster indicates infrastructure deployed or hijacked for this campaign.',
      'low',
      'behavioural-rule',
    );
  }

  // 3j. Impact techniques from explicit categories
  if (cat('ransomware')) {
    add(acc, 'T1486', 'Intelligence classifies associated activity as ransomware, whose defining impact behaviour is encrypting data.', 'medium', 'behavioural-rule');
  }
  if (cat('cryptominer', 'miner', 'cryptojacking')) {
    add(acc, 'T1496', 'Associated activity is cryptomining, which hijacks victim compute resources for profit.', 'medium', 'behavioural-rule');
  }

  // 3k. Scanner + exploit chain
  if (has('internet-scanner') && has('known-malicious-scanner')) {
    add(
      acc,
      'T1190',
      'A host classified as a malicious scanner by an internet-wide scan index is consistent with exploitation attempts against internet-facing applications.',
      'low',
      'behavioural-rule',
    );
  }

  // 3l. Anonymiser / proxy
  if (has('anonymiser')) {
    add(acc, 'T1090', 'The host is reported as an anonymising or proxy service, which is used to relay and conceal command-and-control traffic.', 'low', 'behavioural-rule');
  }

  // 3m. Punycode / deep subdomain infrastructure anomaly
  if (signals.punycode) {
    add(
      acc,
      'T1583.001',
      'Internationalised (punycode) hostnames in this context are consistent with deceptive domain registration.',
      'low',
      'behavioural-rule',
    );
  }

  // ---------------------------------------------------------------------------
  // SAFETY GATE
  // A clean indicator with no malicious signal must not receive technique
  // mappings from generic infrastructure rules (e.g. a public resolver).
  // ---------------------------------------------------------------------------
  if (!anyReputationSignal) {
    const keep = [...acc.mappings.values()].filter(
      (m) => m.confidence === 'high' && m.mappingBasis === 'provider-signal',
    );
    acc.mappings = new Map(keep.map((m) => [m.techniqueId, m]));
  }

  return [...acc.mappings.values()].sort((a, b) => {
    const rank: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };
    if (rank[a.confidence] !== rank[b.confidence]) return rank[b.confidence] - rank[a.confidence];
    return a.techniqueId.localeCompare(b.techniqueId);
  });
}
