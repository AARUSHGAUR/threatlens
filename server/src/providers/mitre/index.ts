/**
 * ============================================================================
 * MITRE ATT&CK KNOWLEDGE BASE
 * ============================================================================
 *
 * A curated, offline subset of the MITRE ATT&CK matrix (Enterprise domain).
 *
 * Why a curated subset instead of the full 600+ technique dump?
 *  1. Reproducibility: the mapping engine must be deterministic and reviewable
 *     during a viva. Shipping the exact techniques the mapper can reason about
 *     makes every mapping decision traceable to a documented rule.
 *  2. It is a *subset of public, factual data* (technique IDs, names, tactics
 *     and links are not opinion), and every entry links back to the official
 *     page so an analyst can verify it.
 *  3. Size: the full STIX bundle is ~30 MB, which is unreasonable to ship inside
 *     a capstone repository.
 *
 * ATT&CK version stamped below; technique names/tactics follow that release.
 */
import type { Confidence, TechniqueRelation } from '../../core/types.js';

export const ATTACK_VERSION = 'v14.1 (curated subset, Enterprise domain)';

export interface TechniqueSeed {
  externalId: string;
  name: string;
  /** All tactics the technique is associated with (ATT&CK is many-to-many). */
  tactics: string[];
  description: string;
  platforms?: string[];
  dataSources?: string[];
  isSubtechnique?: boolean;
  parentExternalId?: string;
}

export const TECHNIQUES: TechniqueSeed[] = [
  // ---------------------------------------------------------- Execution
  {
    externalId: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactics: ['Execution'],
    description:
      'Adversaries may abuse command and script interpreters to execute commands, scripts or binaries. Interpreters provide a common interface for many artefacts, and their abuse is difficult to distinguish from legitimate administration without behavioural context.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Command Execution', 'Command: Command Execution'],
  },
  {
    externalId: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactics: ['Execution', 'Defense Evasion'],
    description:
      'Adversaries may abuse PowerShell commands and scripts for execution, defence evasion and credential theft. PowerShell can execute in-memory content, making it a frequent TTP of commodity loaders and hands-on-keyboard operators.',
    platforms: ['Windows'],
    dataSources: ['Command: Command Execution', 'Process: Process Creation'],
    isSubtechnique: true,
    parentExternalId: 'T1059',
  },
  {
    externalId: 'T1059.003',
    name: 'Command and Scripting Interpreter: Windows Command Shell',
    tactics: ['Execution'],
    description:
      'Adversaries may abuse the Windows command shell (cmd.exe) to execute commands, and may chain commands to stage payloads or perform reconnaissance.',
    platforms: ['Windows'],
    dataSources: ['Command: Command Execution', 'Process: Process Creation'],
    isSubtechnique: true,
    parentExternalId: 'T1059',
  },
  {
    externalId: 'T1204.002',
    name: 'User Execution: Malicious File',
    tactics: ['Execution'],
    description:
      'Adversaries may rely on a user executing a malicious file they were persuaded to download or open, which is the defining behaviour of phishing and fake-update lures.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Process Creation'],
    isSubtechnique: true,
    parentExternalId: 'T1204',
  },

  // ------------------------------------------------- Command and Control
  {
    externalId: 'T1071',
    name: 'Application Layer Protocol',
    tactics: ['Command and Control'],
    description:
      'Adversaries may communicate using OSI application layer protocols to avoid detection and network filtering by blending with existing traffic.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow', 'Network Traffic: Network Traffic Content'],
  },
  {
    externalId: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tactics: ['Command and Control'],
    description:
      'Adversaries may communicate using HTTP/HTTPS, which blends into normal web traffic and is the most common C2 channel observed in both targeted intrusions and commodity malware.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow', 'Network Traffic: Network Traffic Content'],
    isSubtechnique: true,
    parentExternalId: 'T1071',
  },
  {
    externalId: 'T1071.004',
    name: 'Application Layer Protocol: DNS',
    tactics: ['Command and Control'],
    description:
      'Adversaries may encode data within DNS queries or use DNS tunnels for C2 when the HTTP channel is monitored or blocked.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow'],
    isSubtechnique: true,
    parentExternalId: 'T1071',
  },
  {
    externalId: 'T1105',
    name: 'Ingress Tool Transfer',
    tactics: ['Command and Control'],
    description:
      'Adversaries may transfer tools or other files from an external system into a compromised environment. Download URLs, payload servers and TFTP/SMB staging are the usual mechanisms.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow', 'Network Traffic: Network Traffic Content'],
  },
  {
    externalId: 'T1571',
    name: 'Non-Standard Port',
    tactics: ['Command and Control'],
    description:
      'Adversaries may communicate using a protocol and service on a non-default port in order to evade host- and network-based detection of standard services.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow'],
  },
  {
    externalId: 'T1132',
    name: 'Data Encoding',
    tactics: ['Command and Control'],
    description:
      'Adversaries may encode data to make the content of command and control traffic more difficult to detect.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Content'],
  },
  {
    externalId: 'T1090',
    name: 'Proxy',
    tactics: ['Command and Control'],
    description:
      'Adversaries may use a proxy to direct network traffic between systems, hiding the origin of C2 traffic or relaying traffic through compromised infrastructure.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow'],
  },

  // ---------------------------------------------------------- Initial access
  {
    externalId: 'T1566',
    name: 'Phishing',
    tactics: ['Initial Access'],
    description:
      'Adversaries may send phishing messages to gain access to victim systems. Phishing can be targeted (spearphishing) or broad (mass phishing).',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['Network Traffic: Network Traffic Content', 'User Logon: Failed Logon Attempts'],
  },
  {
    externalId: 'T1566.001',
    name: 'Phishing: Spearphishing Attachment',
    tactics: ['Initial Access', 'Execution'],
    description:
      'Adversaries may send spearphishing emails with a malicious attachment to gain access to victim systems, typically to execute a payload on the endpoint.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['Network Traffic: Network Traffic Content'],
    isSubtechnique: true,
    parentExternalId: 'T1566',
  },
  {
    externalId: 'T1566.002',
    name: 'Phishing: Spearphishing Link',
    tactics: ['Initial Access', 'Execution'],
    description:
      'Adversaries may send spearphishing emails with a link to a malicious page to gain access to victim systems, typically harvesting credentials or triggering a download.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['Network Traffic: Network Traffic Content'],
    isSubtechnique: true,
    parentExternalId: 'T1566',
  },
  {
    externalId: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactics: ['Initial Access'],
    description:
      'Adversaries may attempt to exploit a weakness in an internet-facing host or system to initially access a network.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Content', 'Application Log: Application Logs'],
  },
  {
    externalId: 'T1195',
    name: 'Supply Chain Compromise',
    tactics: ['Initial Access'],
    description:
      'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Process Creation', 'Log File: Log Files'],
  },
  {
    externalId: 'T1078',
    name: 'Valid Accounts',
    tactics: ['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'],
    description:
      'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access, persistence, privilege escalation or defence evasion. Stolen credentials are the usual second stage of a phishing wave.',
    platforms: ['Windows', 'Linux', 'macOS', 'Cloud', 'Identity Provider'],
    dataSources: ['Logon Session: Logon Session Creation', 'User Account: User Account Authentication'],
  },

  // ---------------------------------------------------------- Persistence
  {
    externalId: 'T1053.005',
    name: 'Scheduled Task/Job: Scheduled Task',
    tactics: ['Execution', 'Persistence', 'Privilege Escalation'],
    description:
      'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code, commonly as a persistence mechanism for loaders.',
    platforms: ['Windows'],
    dataSources: ['Process: Process Creation', 'Windows Registry: Windows Registry Key Modification'],
    isSubtechnique: true,
    parentExternalId: 'T1053',
  },
  {
    externalId: 'T1547.001',
    name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
    tactics: ['Persistence', 'Defense Evasion'],
    description:
      'Adversaries may achieve persistence by adding a program to a registry run key or the startup folder to automatically launch at sign-in.',
    platforms: ['Windows'],
    dataSources: ['Windows Registry: Windows Registry Key Modification'],
    isSubtechnique: true,
    parentExternalId: 'T1547',
  },

  // ------------------------------------------------------- Defense evasion
  {
    externalId: 'T1055',
    name: 'Process Injection',
    tactics: ['Defense Evasion', 'Privilege Escalation'],
    description:
      'Adversaries may inject code into processes in order to evade process-based defences as well as possibly elevate privileges. Injected code executes in the address space of a trusted signed process.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Process Creation', 'API Monitor: API Call'],
  },
  {
    externalId: 'T1218',
    name: 'System Binary Proxy Execution',
    tactics: ['Defense Evasion'],
    description:
      'Adversaries may bypass process and signature-based defences by proxying execution of malicious content with signed binaries.',
    platforms: ['Windows'],
    dataSources: ['Process: Process Creation', 'Command: Command Execution'],
  },
  {
    externalId: 'T1027',
    name: 'Obfuscated Files or Information',
    tactics: ['Defense Evasion'],
    description:
      'Adversaries may attempt to make an executable or file difficult to discover or analyse by encrypting, encoding or otherwise obfuscating its contents.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File: File Modification'],
  },
  {
    externalId: 'T1140',
    name: 'Deobfuscate/Decode Files or Information',
    tactics: ['Defense Evasion'],
    description:
      'Adversaries may use obfuscated files or information to hide artifacts of an intrusion and make them appear benign or unexpected to system and network tools.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File: File Modification', 'Process: Process Creation'],
  },
  {
    externalId: 'T1070.004',
    name: 'Indicator Removal: File Deletion',
    tactics: ['Defense Evasion'],
    description:
      'Adversaries may delete files after they have been used to avoid forensic discovery. Deleting an installer or a staging payload after execution is a classic anti-forensic behaviour.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File: File Deletion'],
    isSubtechnique: true,
    parentExternalId: 'T1070',
  },
  {
    externalId: 'T1112',
    name: 'Modify Registry',
    tactics: ['Defense Evasion'],
    description:
      'Adversaries may interact with the Windows registry to hide configuration information, remove artefacts or disable security features.',
    platforms: ['Windows'],
    dataSources: ['Windows Registry: Windows Registry Key Modification'],
  },

  // ------------------------------------------------------------- Collection
  {
    externalId: 'T1005',
    name: 'Data from Local System',
    tactics: ['Collection'],
    description:
      'Adversaries may search local system sources to find sensitive data, e.g. browser credential stores, wallet files or cached documents. This is the collection stage of a commodity information stealer.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['File: File Access', 'Process: Process Creation'],
  },
  {
    externalId: 'T1555.003',
    name: 'Credentials from Password Stores: Credentials from Web Browsers',
    tactics: ['Credential Access'],
    description:
      'Adversaries may steal credentials from web browsers, targeting saved passwords, cookies and autofill data.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['File: File Access', 'Process: OS API Execution'],
    isSubtechnique: true,
    parentExternalId: 'T1555',
  },
  {
    externalId: 'T1056.003',
    name: 'Input Capture: Web Portal Capture',
    tactics: ['Collection', 'Credential Access'],
    description:
      'Adversaries may create applications that mimic legitimate websites to capture user credentials as they are entered - the defining behaviour of a phishing-kit landing page.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['Network Traffic: Network Traffic Content'],
    isSubtechnique: true,
    parentExternalId: 'T1056',
  },
  {
    externalId: 'T1185',
    name: 'Browser Session Hijacking',
    tactics: ['Credential Access', 'Collection'],
    description:
      'Adversaries may steal or forge authentication cookies so they can reuse an authenticated browser session without the user re-entering credentials.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['File: File Modification', 'Network Traffic: Network Traffic Content'],
  },
  {
    externalId: 'T1560.001',
    name: 'Archive Collected Data: Archive via Utility',
    tactics: ['Collection'],
    description:
      'Adversaries may archive collected data prior to exfiltration, commonly by compressing it with a built-in utility.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Process Creation'],
    isSubtechnique: true,
    parentExternalId: 'T1560',
  },
  {
    externalId: 'T1074.001',
    name: 'Data Staged: Local Data Staging',
    tactics: ['Collection'],
    description:
      'Adversaries may stage data collected from a host in a local directory prior to exfiltration.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File: File Creation', 'File: File Modification'],
    isSubtechnique: true,
    parentExternalId: 'T1074',
  },

  // ---------------------------------------------------------- Exfiltration
  {
    externalId: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactics: ['Exfiltration'],
    description:
      'Adversaries may steal data by sending it out through the existing command and control channel, avoiding a second, easily detected egress path.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Content', 'Network Traffic: Network Connection Creation'],
  },
  {
    externalId: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactics: ['Exfiltration'],
    description:
      'Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel, such as FTP or DNS.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow'],
  },
  {
    externalId: 'T1029',
    name: 'Scheduled Transfer',
    tactics: ['Exfiltration'],
    description:
      'Adversaries may schedule data exfiltration to occur at fixed times to avoid generating regular data transfer anomalies.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow', 'Scheduled Job/Task: Scheduled Job/Task Creation'],
  },

  // ------------------------------------------------------ Resource development
  {
    externalId: 'T1583.001',
    name: 'Acquire Infrastructure: Domains',
    tactics: ['Resource Development'],
    description:
      'Adversaries may buy or register domains for C2 or phishing infrastructure. Newly registered domains are a common early-warning signal.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Content'],
    isSubtechnique: true,
    parentExternalId: 'T1583',
  },
  {
    externalId: 'T1584.001',
    name: 'Compromise Infrastructure: Domains',
    tactics: ['Resource Development'],
    description:
      'Adversaries may hijack legitimate domains or register look-alike domains to host malicious content and inherit the victimised domain reputation.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Content'],
    isSubtechnique: true,
    parentExternalId: 'T1584',
  },
  {
    externalId: 'T1587.001',
    name: 'Develop Capabilities: Malware',
    tactics: ['Resource Development'],
    description:
      'Adversaries may develop custom malware to avoid detection by off-the-shelf tooling, as observed with the bespoke implant in the ThreatLens demo scenario.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['N/A'],
    isSubtechnique: true,
    parentExternalId: 'T1587',
  },
  {
    externalId: 'T1588.001',
    name: 'Obtain Capabilities: Malware',
    tactics: ['Resource Development'],
    description:
      'Adversaries may obtain or develop capabilities by purchasing or leasing access to existing tooling and infrastructure.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['N/A'],
    isSubtechnique: true,
    parentExternalId: 'T1588',
  },
  {
    externalId: 'T1589.003',
    name: 'Search Open Websites/Domains: Search Engines',
    tactics: ['Reconnaissance'],
    description:
      'Adversaries may use search engines to research their targets before initial access - for example to identify the technology used by the phishing target.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['N/A'],
    isSubtechnique: true,
    parentExternalId: 'T1589',
  },
  {
    externalId: 'T1568',
    name: 'Dynamic Resolution',
    tactics: ['Command and Control'],
    description:
      'Adversaries may dynamically generate or resolve infrastructure at runtime to evade blocklisting, for example through domain generation algorithms or dead-drop resolvers.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow'],
  },
  {
    externalId: 'T1568.002',
    name: 'Dynamic Resolution: DNS Names',
    tactics: ['Command and Control'],
    description:
      'Adversaries may generate domains using a domain generation algorithm (DGA) or resolve dead-drop records, producing high-entropy, algorithmically generated hostnames.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Flow', 'Network Traffic: Network Traffic Content'],
    isSubtechnique: true,
    parentExternalId: 'T1568',
  },
  {
    externalId: 'T1562.001',
    name: 'Impair Defenses: Disable or Modify Tools',
    tactics: ['Defense Evasion'],
    description:
      'Adversaries may disable or modify security tooling to avoid detection, including disabling endpoint agents or altering logging configuration.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Process Creation', 'Service: Service Modification'],
    isSubtechnique: true,
    parentExternalId: 'T1562',
  },

  // ----------------------------------------------------------------- Impact
  {
    externalId: 'T1486',
    name: 'Data Encrypted for Impact',
    tactics: ['Impact'],
    description:
      'Adversaries may encrypt data on target systems to interrupt availability to system and network resources.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['File: File Modification'],
  },
  {
    externalId: 'T1496',
    name: 'Resource Hijacking',
    tactics: ['Impact'],
    description:
      'Adversaries may hijack victim resources - including compute, storage or network resources - to mine cryptocurrency or to satisfy attacker resource needs.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process: Process Creation', 'Network Traffic: Network Traffic Flow'],
  },
];

/** Technique id -> seed lookup. */
export const TECHNIQUE_BY_ID = new Map(TECHNIQUES.map((t) => [t.externalId, t]));

/** Build the canonical ATT&CK URL for a technique or sub-technique. */
export const attackUrl = (externalId: string): string => {
  const [base, sub] = externalId.split('.');
  return sub ? `https://attack.mitre.org/techniques/${base}/${sub}/` : `https://attack.mitre.org/techniques/${base}/`;
};

/**
 * Human-readable name of the primary tactic, used in the UI badge.
 * ATT&CK orders tactics by kill-chain phase; the first entry is the phase the
 * technique is *most* associated with.
 */
export const primaryTactic = (seed: TechniqueSeed): string => seed.tactics[0] ?? 'unknown';

export interface TechniqueView extends TechniqueSeed {
  primaryTactic: string;
  reference: string;
  /** Coarse mapping phase used by the correlation graph. */
  relation: TechniqueRelation;
}

/** Map a tactic name onto the correlation-graph relation vocabulary. */
const RELATION_BY_TACTIC: Record<string, TechniqueRelation> = {
  'initial access': 'initial-access',
  execution: 'execution',
  persistence: 'persistence',
  'privilege escalation': 'privilege-escalation',
  'defense evasion': 'defense-evasion',
  'credential access': 'credential-access',
  discovery: 'discovery',
  'lateral movement': 'lateral-movement',
  collection: 'collection',
  'command and control': 'command-and-control',
  'exfiltration': 'exfiltration',
  impact: 'impact',
  'resource development': 'resource-development',
  reconnaissance: 'evasion',
};

export const relationForTactic = (tactic: string): TechniqueRelation =>
  RELATION_BY_TACTIC[tactic.toLowerCase()] ?? 'evasion';

export const techniqueView = (externalId: string): TechniqueView | null => {
  const seed = TECHNIQUE_BY_ID.get(externalId);
  if (!seed) return null;
  return {
    ...seed,
    primaryTactic: primaryTactic(seed),
    reference: attackUrl(externalId),
    relation: relationForTactic(primaryTactic(seed)),
  };
};

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

/** Confidence vocabulary re-exported for the mapper. */
export type { Confidence };
