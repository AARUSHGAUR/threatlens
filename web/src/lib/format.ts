/** Formatting + presentation helpers shared across pages. */
import type { Confidence, IocType, RiskLevel, Verdict } from '../api/types';

export const RISK_COLOUR: Record<RiskLevel, string> = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
  CLEAN: 'var(--clean)',
};

export const RISK_CLASS: Record<RiskLevel, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  CLEAN: 'badge-clean',
};

/** Chart series colours reuse the semantic palette (the charts are all risk data). */
export const CHART_COLOUR: Record<RiskLevel, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#38bdf8',
  CLEAN: '#22c55e',
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  clean: 'Clean',
  harmless: 'Harmless',
  unknown: 'Unknown',
};

export const VERDICT_CLASS: Record<Verdict, string> = {
  malicious: 'badge-critical',
  suspicious: 'badge-medium',
  clean: 'badge-clean',
  harmless: 'badge-clean',
  unknown: 'badge-unknown',
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
};

export const IOC_TYPE_LABEL: Record<IocType, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA1',
  sha256: 'SHA256',
  email: 'Email',
};

export const IOC_TYPE_ORDER: IocType[] = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'];

/** Colour for an IOC-type slice in charts. Deliberately not risk-semantic. */
export const TYPE_COLOUR: Record<IocType, string> = {
  ipv4: '#22d3ee',
  ipv6: '#818cf8',
  domain: '#34d399',
  url: '#fbbf24',
  md5: '#f472b6',
  sha1: '#c084fc',
  sha256: '#fb7185',
  email: '#94a3b8',
};

export const formatDate = (iso: string | null | undefined): string => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
};

export const formatDateShort = (iso: string | null | undefined): string => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { month: 'short', day: '2-digit' });
};

export const formatRelative = (iso: string | null | undefined): string => {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const diff = Date.now() - then;
  const mins = Math.round(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 31) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
};

export const formatPercent = (ratio: number | null | undefined, digits = 1): string =>
  ratio === null || ratio === undefined ? '—' : `${(ratio * 100).toFixed(digits)}%`;

export const formatBytes = (bytes: number | null | undefined): string => {
  if (!bytes) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export const formatDuration = (ms: number | null | undefined): string => {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
};

export const formatNumber = (n: number | null | undefined): string =>
  n === null || n === undefined ? '—' : n.toLocaleString();

/** Human label for provider status codes. */
export const PROVIDER_STATUS_LABEL: Record<string, string> = {
  ok: 'Responded',
  not_found: 'No data',
  unconfigured: 'Not configured',
  error: 'Error',
  rate_limited: 'Rate limited',
  timeout: 'Timed out',
};

export const RELATION_LABEL: Record<string, string> = {
  resolves_to: 'resolves to',
  'reverse-resolves_to': 'reverse-resolves to',
  served_by: 'served by',
  staged_on: 'staged on',
  retrieved_from: 'retrieved from',
  delivered_to: 'delivered to',
  sender_domain: 'sender domain',
  communicates_with: 'communicates with',
  related_domain: 'related domain',
  related_url: 'related URL',
  related_hash: 'related hash',
  related_ip: 'related IP',
  related_email: 'related address',
  hosts: 'hosts',
  staged: 'staged',
  delivers: 'delivers',
  downloads: 'downloaded',
  served: 'served',
  'related-to': 'related to',
  'associated-malware': 'associated malware',
  'attributed-to': 'attributed to',
  'part-of-campaign': 'part of campaign',
  'contextually-associated': 'contextually associated',
  'mapped-technique': 'mapped technique',
  'hosted-in': 'hosted in',
};

export const relationLabel = (relation: string): string =>
  RELATION_LABEL[relation] ?? relation.replace(/_/g, ' ');

export const TACTIC_COLOUR: Record<string, string> = {
  'Reconnaissance': '#94a3b8',
  'Resource Development': '#a78bfa',
  'Initial Access': '#f472b6',
  Execution: '#fbbf24',
  Persistence: '#fb923c',
  'Privilege Escalation': '#f97316',
  'Defense Evasion': '#facc15',
  'Credential Access': '#fde047',
  Discovery: '#a3e635',
  'Lateral Movement': '#4ade80',
  Collection: '#2dd4bf',
  'Command and Control': '#22d3ee',
  Exfiltration: '#60a5fa',
  Impact: '#ef4444',
};

export const tacticColour = (tactic: string): string => TACTIC_COLOUR[tactic] ?? '#64748b';

/** Kill-chain ordering of ATT&CK tactics, used to group the knowledge base view. */
export const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

/** Copy-to-clipboard with a graceful fallback for non-secure contexts. */
export const copyToClipboard = async (text: string): Promise<boolean> => {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(area);
    return ok;
  } catch {
    return false;
  }
};

/** Middle-truncate a long indicator so the distinguishing part stays visible. */
export const truncateMiddle = (value: string, head = 18, tail = 12): string => {
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
};

export const pluralise = (n: number, singular: string, plural?: string): string =>
  `${n} ${n === 1 ? singular : plural ?? `${singular}s`}`;

/** Clamp long provider strings for compact display. */
export const clampText = (value: string | null | undefined, max = 160): string => {
  if (!value) return '—';
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
};
