/**
 * ============================================================================
 * DEFENSIVE RECOMMENDATION ENGINE  (CTI lifecycle: "Dissemination")
 * ============================================================================
 *
 * Converts an investigation result into *defensive* actions an analyst or SOC
 * team can execute. Strictly defensive: containment, detection engineering,
 * eradication, hunting and monitoring. No offensive or exploitation content is
 * produced by this module.
 *
 * Selection is rule-based on (IOC type x risk level x observed behaviour), so
 * the same investigation always yields the same checklist. Where a concrete
 * search expression is useful (SIEM/EDR hunting), it is emitted as a literal
 * query string the analyst can paste into their tooling.
 */
import type { DefensiveAction, IocType, RiskLevel } from '../types.js';
import type { AggregatedIntel } from '../aggregate.js';

interface RuleContext {
  iocType: IocType;
  value: string;
  riskLevel: RiskLevel;
  intel: AggregatedIntel;
  relatedDomains: string[];
  relatedIps: string[];
  relatedHashes: string[];
  relatedUrls: string[];
  actors: string[];
  malware: string[];
  isDocumentation: boolean;
}

let seq = 0;
const action = (
  title: string,
  detail: string,
  category: DefensiveAction['category'],
  priority: DefensiveAction['priority'],
  searchQuery?: string,
): DefensiveAction => ({
  id: `act_${(seq += 1)}`,
  title,
  detail,
  category,
  priority,
  searchQuery,
});

const isIp = (t: IocType) => t === 'ipv4' || t === 'ipv6';
const isHash = (t: IocType) => t === 'md5' || t === 'sha1' || t === 'sha256';

const esc = (value: string): string => value.replace(/["\\]/g, '\\$&');

export function buildDefensiveActions(ctx: RuleContext): DefensiveAction[] {
  seq = 0;
  const out: DefensiveAction[] = [];
  const { iocType, value, riskLevel, intel } = ctx;
  const v = esc(value);
  const level = riskLevel;
  const urgent = level === 'CRITICAL' || level === 'HIGH';
  const c2 = intel.behaviours.some((b) => /c2|beacon/i.test(b));
  const phishing = intel.behaviours.includes('phishing') || intel.categories.some((c) => /phish/i.test(c));
  const credentialHarvesting = intel.behaviours.includes('credential-harvesting');
  const malwareDelivery = intel.behaviours.includes('malware-delivery') || intel.categories.some((c) => /malware|downloader|trojan|rat|infostealer/i.test(c));
  const scanner = intel.behaviours.includes('internet-scanner');

  // ------------------------------------------------------------------ docs
  if (ctx.isDocumentation) {
    out.push(
      action(
        'No defensive action required (documentation range)',
        'This indicator sits inside an IETF documentation range (RFC 5737 / RFC 3849) or a reserved domain namespace (RFC 2606). It cannot be routed on the public Internet, so any sighting inside the environment is either synthetic test data or a misconfiguration worth checking with the owner.',
        'monitoring',
        3,
      ),
    );
  }

  // ------------------------------------------------------------------- IP
  if (isIp(iocType)) {
    if (urgent) {
      out.push(
        action(
          'Block the address at the perimeter',
          `Add ${value} to the firewall deny list (egress and ingress) and to the SIEM watchlist. Allow time for propagation if you rely on geo/CDN ACLs.`,
          'containment',
          1,
          `destination.ip:"${v}" OR source.ip:"${v}"`,
        ),
      );
      out.push(
        action(
          'Search historical logs for connections',
          `Hunt across firewall, proxy, DNS and EDR telemetry for any connection to ${value} in the last 30 days. Establish a first-seen/last-seen window before blocking so evidence is not destroyed by the block itself.`,
          'hunting',
          1,
          `destination.ip:"${v}" OR source.ip:"${v}"`,
        ),
      );
      out.push(
        action(
          'Investigate outbound connections from internal hosts',
          'Any internal host that initiated a connection is a potential victim. Collect the process tree, user and parent process for each hit and escalate to the endpoint queue.',
          'detection',
          1,
          `direction:"outbound" destination.ip:"${v}"`,
        ),
      );
    } else {
      out.push(
        action(
          'Monitor rather than block',
          `Risk is ${level}. Keep ${value} on a watchlist, alert on new outbound connections, and re-assess if the risk score or abuse confidence increases.`,
          'monitoring',
          2,
          `destination.ip:"${v}"`,
        ),
      );
    }

    if (c2) {
      out.push(
        action(
          'Treat as command-and-control: hunt for beaconing',
          'C2 infrastructure produces periodic, low-volume, jittered connections. Look for hosts contacting this address on a regular interval, and correlate with DNS and proxy logs to find the full domain set behind the address.',
          'hunting',
          1,
          `destination.ip:"${v}" | stats count by host, _time`,
        ),
      );
    }
    if (scanner) {
      out.push(
        action(
          'Check for exploitation attempts against exposed services',
          'Scanner-classified hosts are frequently probing for exploitable services. Correlate inbound connection attempts with WAF, IDS and vulnerability-scanner logs.',
          'detection',
          2,
          `source.ip:"${v}" direction:"inbound"`,
        ),
      );
    }
    if (ctx.relatedDomains.length) {
      out.push(
        action(
          'Block the related domains as well',
          `Blocking only the address leaves domain-based fallback in place. Add these hostnames to DNS filtering and proxy blocklists: ${ctx.relatedDomains.slice(0, 5).join(', ')}.`,
          'containment',
          1,
          `query:"${esc(ctx.relatedDomains[0] ?? value)}"`,
        ),
      );
    }
  }

  // ---------------------------------------------------------------- domain
  if (iocType === 'domain' || iocType === 'url') {
    if (urgent) {
      out.push(
        action(
          'Block in DNS filtering and proxy',
          `Add ${value} to the enterprise DNS filter deny list and the secure web gateway blocklist. Enforce an "NXDOMAIN" response policy so the resolution attempt itself is logged.`,
          'containment',
          1,
          `query:"${v}" OR url:"${v}"`,
        ),
      );
    } else {
      out.push(
        action(
          'Monitor the domain',
          `Keep ${value} on the DNS watchlist and alert on any resolution attempt from internal hosts.`,
          'monitoring',
          2,
          `query:"${v}"`,
        ),
      );
    }
    out.push(
      action(
        'Search proxy and DNS logs for prior access',
        'Establish whether internal users already reached this destination. Record user, device, timestamp and bytes transferred; repeated short sessions may indicate automated tooling rather than a user.',
        'hunting',
        urgent ? 1 : 2,
        `url:"${v}" OR hostname:"${v}"`,
      ),
    );
    if (phishing) {
      out.push(
        action(
          'Purge the message from mailboxes',
          'Search the mail gateway for messages containing this link and purge them, then release updated quarantine rules. Do not rely on the sender address alone - link and domain indicators survive mailbox rotation.',
          'containment',
          1,
          `header:"${v}" OR body:"${v}"`,
        ),
      );
      out.push(
        action(
          'Reset credentials for users who interacted',
          'Any user who entered credentials on the harvested page must perform an immediate password reset, revoke active sessions and re-enrol MFA.',
          'eradication',
          1,
        ),
      );
    }
    if (malwareDelivery) {
      out.push(
        action(
          'Hunt for the delivered payload',
          'The URL served malicious content. Search EDR for downloads originating from this host and match the resulting file hashes against the related hashes from this investigation.',
          'detection',
          1,
          ctx.relatedHashes.length ? `file.sha256:"${esc(ctx.relatedHashes[0])}"` : undefined,
        ),
      );
    }
    if (ctx.relatedIps.length) {
      out.push(
        action(
          'Block the resolved addresses',
          `This indicator resolves to or is associated with ${ctx.relatedIps.slice(0, 4).join(', ')}. Add them to the perimeter blocklist so the domain cannot be reached even before DNS filtering propagates.`,
          'containment',
          2,
          `destination.ip:"${esc(ctx.relatedIps[0])}"`,
        ),
      );
    }
  }

  // ------------------------------------------------------------------ hash
  if (isHash(iocType)) {
    out.push(
      action(
        'Search EDR for the file hash',
        `Query endpoint telemetry for this ${iocType.toUpperCase()} across the fleet, including historical snapshots. Record host, user, process tree and first-seen time for every match.`,
        'detection',
        1,
        `file.${iocType}:"${v}"`,
      ),
    );
    if (urgent) {
      out.push(
        action(
          'Quarantine affected files and hosts',
          'Isolate the file (and the host if execution is confirmed) through the EDR console, then preserve a copy for malware analysis before deletion. Do not delete the only sample.',
          'containment',
          1,
        ),
      );
    }
    out.push(
      action(
        'Investigate the parent process chain',
        'The parent process reveals the delivery vector (browser download, archive extractor, script host, service). Build the detection rule around the vector, not only the hash - hashes are cheap to change.',
        'detection',
        1,
        `file.${iocType}:"${v}" | parent.process.*`,
      ),
    );
    out.push(
      action(
        'Perform malware analysis on a copy',
        'Submit the sample to the internal sandbox. Extract configuration, C2 endpoints, mutexes and persistence mechanisms, and feed the results back into this platform as new indicators.',
        'eradication',
        2,
      ),
    );
    if (ctx.relatedDomains.length || ctx.relatedIps.length) {
      out.push(
        action(
          'Block the sample\'s network infrastructure',
          `The sample communicates with infrastructure recovered during enrichment. Pre-emptively block: ${[...ctx.relatedDomains, ...ctx.relatedIps].slice(0, 5).join(', ')}.`,
          'containment',
          1,
      ),
      );
    }
  }

  // ----------------------------------------------------------------- email
  if (iocType === 'email') {
    out.push(
      action(
        'Block the sender at the mail gateway',
        `Add ${value} to the inbound blocklist, but pair it with a rule on the linked domain and URL - sender addresses are disposable and are rarely the durable indicator.`,
        'containment',
        urgent ? 1 : 2,
        `sender:"${v}"`,
      ),
    );
    out.push(
      action(
        'Search the mail gateway for prior deliveries',
        'Identify every recipient so exposure can be scoped before the message is purged.',
        'hunting',
        1,
        `sender:"${v}"`,
      ),
    );
    if (phishing) {
      out.push(
        action(
          'Force credential reset for recipients who interacted',
          'Treat every recipient of a credential-harvesting message as a potential credential compromise until proven otherwise.',
          'eradication',
          1,
        ),
      );
      out.push(
        action(
          'Add a detection rule for the lure',
          'Write a mail rule matching the message structure, landing URL and attachment type so the campaign is caught on the next wave even if the sender changes.',
          'detection',
          2,
        ),
      );
    }
  }

  // ------------------------------------------------- cross-cutting by context
  if (ctx.actors.length || ctx.malware.length) {
    out.push(
      action(
        'Share the indicators with downstream teams',
        `Distribute this investigation to the SOC, network operations and incident response stakeholders${
          ctx.actors.length ? `, referencing the attributed actor (${ctx.actors.slice(0, 2).join(', ')})` : ''
        }. Record the distribution in the case file so the intelligence is reusable.`,
        'monitoring',
        2,
      ),
    );
  }
  if (level === 'CLEAN') {
    out.push(
      action(
        'Close with justification',
      `No containment is warranted: risk is ${level}. Record the indicators in a baseline allowlist for the campaign period and re-investigate if the reputation changes.`,
      'monitoring',
      3,
    ),
    );
  }
  out.push(
    action(
      'Re-investigate on a schedule',
      'Threat intelligence decays. Re-run this investigation in 7 days (or immediately if a related indicator is observed on the network) to refresh the risk assessment.',
      'monitoring',
      3,
    ),
  );

  // Deduplicate by title and order by priority.
  const seen = new Set<string>();
  return out
    .filter((a) => {
      if (seen.has(a.title)) return false;
      seen.add(a.title);
      return true;
    })
    .sort((a, b) => a.priority - b.priority);
}
