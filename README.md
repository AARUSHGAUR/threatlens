# ThreatLens

### Cyber Threat Intelligence & IOC Investigation Platform

A working CTI platform for indicator-of-compromise (IOC) investigation: an analyst submits an
indicator, ThreatLens enriches it across multiple threat-intelligence sources, correlates it into
an entity graph, computes an **explainable** risk score, maps relevant MITRE ATT&CK® techniques,
builds an investigation timeline and produces a professional CTI report.

Built as a capstone project for a Cyber Threat Intelligence course.

> **Runs with zero configuration and zero API keys.** Out of the box ThreatLens starts in
> **DEMO MODE** against a built-in, clearly-labelled fictional dataset. Add API keys to switch to
> live intelligence.

---

## Table of contents

1. [Problem statement](#1-problem-statement)
2. [Objectives](#2-objectives)
3. [Feature overview](#3-feature-overview)
4. [Screenshots](#4-screenshots)
5. [Quick start](#5-quick-start)
6. [Configuration](#6-configuration)
7. [Demo mode](#7-demo-mode)
8. [Architecture](#8-architecture)
9. [The CTI lifecycle in this system](#9-the-cti-lifecycle-in-this-system)
10. [How this project implements Cyber Threat Intelligence](#10-how-this-project-implements-cyber-threat-intelligence)
11. [IOC detection & validation](#11-ioc-detection--validation)
12. [Threat intelligence providers](#12-threat-intelligence-providers)
13. [Risk scoring methodology](#13-risk-scoring-methodology)
14. [MITRE ATT&CK integration](#14-mitre-attck-integration)
15. [IOC correlation & the relationship graph](#15-ioc-correlation--the-relationship-graph)
16. [Intelligence reports](#16-intelligence-reports)
17. [Recommended defensive actions](#17-recommended-defensive-actions)
18. [Database schema](#18-database-schema)
19. [API reference](#19-api-reference)
20. [Technology stack](#20-technology-stack)
21. [Security design](#21-security-design)
22. [Testing](#22-testing)
23. [Project layout](#23-project-layout)
24. [Limitations & future enhancements](#24-limitations--future-enhancements)
25. [Academic context](#25-academic-context)
26. [License](#26-license)
27. [Credits](#27-credits)

---

## 1. Problem statement

A SOC analyst receives an indicator — an IP address from a firewall alert, a domain from an email
header, a hash from an EDR triage, a URL from a proxy log — and has to answer four questions:

1. **Is this real?** (validation: is it even a well-formed indicator?)
2. **Is it dangerous?** (enrichment: what do other sources say?)
3. **How dangerous, and why?** (analysis: a defensible, auditable assessment)
4. **What do I do about it?** (dissemination: specific, defensive, actionable steps)

Doing that well means querying several unrelated APIs, each with its own schema, its own rate limit
and its own failure modes, then reconciling the results by hand. The pain points this project
addresses are real and observable:

- **Fragmentation.** Reputation (VirusTotal), abuse history (AbuseIPDB), campaign context (OTX),
  payload hosting (URLhaus), scanner exposure (GreyNoise, Shodan) live behind different schemas.
  A hand-rolled spreadsheet of "which API said what" is slow and unauditable.
- **Opaque scoring.** "The tool says this IP is 87% malicious" is not an answer an analyst can
  defend to a manager or a regulator. Most free dashboards give a number with no arithmetic.
- **Correlation blindness.** A single lookup shows one indicator in isolation. The value in CTI is
  in the *relationships* between indicators over time.
- **Fabrication risk.** A tool that quietly invents plausible-looking data to fill a gap is worse
  than a tool that admits it knows nothing. This is the failure mode this project is most
  deliberately designed to avoid.

## 2. Objectives

| # | Objective | Where it is implemented |
|---|-----------|--------------------------|
| O1 | Accept IPv4, IPv6, domain, URL, MD5, SHA1, SHA256 and email indicators and determine the type automatically | `server/src/core/ioc/detect.ts` |
| O2 | Validate indicators and reject the ones that are not analytically meaningful | `server/src/core/ioc/validate.ts` |
| O3 | Enrich indicators from multiple CTI sources behind a single provider interface | `server/src/providers/*` |
| O4 | Produce a deterministic, fully explainable 0–100 risk score | `server/src/core/risk/engine.ts` |
| O5 | Map MITRE ATT&CK techniques only where documented evidence exists | `server/src/core/mitre/mapper.ts` |
| O6 | Correlate indicators into a typed, navigable entity graph | `server/src/core/correlation/correlator.ts` |
| O7 | Persist evidence, timelines and assessments in a normalised relational schema | `server/src/db/schema.sql` |
| O8 | Produce a professional CTI report (PDF / JSON / Markdown) that separates fact, external intelligence and analysis | `server/src/services/reportBuilder.ts`, `pdfRenderer.ts` |
| O9 | Generate defensive, type-aware and risk-aware recommendations | `server/src/core/recommendations/engine.ts` |
| O10 | Work completely without API keys, never presenting simulated data as real | `server/src/providers/demo/*`, `providers/registry.ts` |

## 3. Feature overview

**Supported indicator types**

ThreatLens accepts eight indicator classes, detected automatically in the order shown (see
[§11](#11-ioc-detection--validation) for the exact rules):

| Type | Example | Notes |
|------|---------|-------|
| IPv4 | `203.0.113.50` | Octet-range validated; leading zeros rejected (octal-ambiguity defence) |
| IPv6 | `2001:db8::50` | Full, `::`-compressed and IPv4-mapped forms |
| Domain | `c2-nightfall.example.com` | RFC 1035/1123, public-suffix aware |
| URL | `https://c2-nightfall.example.com/gate.php` | `http`/`https` only, host and path parsed |
| MD5 | `d41d8cd98f00b204e9800998ecf8427e` | Flagged as a weak hash |
| SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | — |
| SHA256 | `e3b0c442…2b855` | — |
| Email | `no-reply@updates-lantern.example.com` | Domain extracted for correlation |

All eight are covered by the built-in demo dataset, so every type can be demonstrated without API keys.

**Investigation**

- Prominent IOC search with **live type detection** as you type (server-side rules, one source of truth)
- Automatic **de-fanging** of analyst-style indicators (`hxxp://evil[.]com` → `http://evil.com`)
- Real pipeline progress: the investigation console streams the actual pipeline timeline
  (validation → enrichment → correlation → scoring → ATT&CK → persistence), polled from the server
- Detailed result page with tabs for Summary, Intelligence, Correlation, ATT&CK, Defensive actions,
  Timeline and Report
- Per-source enrichment cards with detection bars, latency, error detail and a truncated raw-payload
  audit excerpt
- Analyst notes and triage outcome (true positive / false positive / benign / needs triage)
- Re-analysis creates a new snapshot; history keeps the old one

**Analytics**

- Dashboard with 6 headline metrics and 6 charts (investigations over time, risk distribution, IOC
  types, threat categories, top malicious countries, top ATT&CK techniques)
- Investigation history with search, multi-filter (type, risk level, mode), sorting, deep-linkable
  filter state and deletion
- Indicator library with per-indicator correlation memory
- ATT&CK coverage view: which techniques this platform has actually observed
- Threat actor / malware / campaign knowledge views

**Reporting**

- 11-section investigation report rendered on screen and exportable as PDF, JSON and Markdown
- TLP:AMBER classification and an explicit provenance block

**Platform**

- JWT session auth (httpOnly cookie, bcrypt password hashing, login rate limiting)
- Provider health page showing exactly which credentials are configured — values never leave the server
- Runtime switch between LIVE INTELLIGENCE and DEMO MODE
- Security headers, CSP, in-memory rate limiting, structured logging with credential redaction
- 31 unit tests covering the deterministic engines

## 4. Screenshots

All screenshots below were captured from the application running in DEMO MODE (the "DEMO DATA" badge
is visible in the top bar of every page).

| Screenshot | What it shows |
|------------|---------------|
| [`login.png`](docs/screenshots/login.png) | Sign-in with the seeded analyst credentials and the active intelligence mode |
| [`dashboard.png`](docs/screenshots/dashboard.png) | SOC dashboard: six headline metrics, six charts, recent investigations, provider usage |
| [`investigate.png`](docs/screenshots/investigate.png) | IOC search with live type detection plus the demo walkthrough catalogue |
| [`result-summary.png`](docs/screenshots/result-summary.png) | Result header (IOC, type, score, level, confidence) and the explainable risk breakdown |
| [`result-correlation.png`](docs/screenshots/result-correlation.png) | Interactive entity relationship graph — actor → malware → C2 domain → C2 IP → related hash |
| [`result-attack.png`](docs/screenshots/result-attack.png) | ATT&CK mappings, each with the evidence that produced it and a link to attack.mitre.org |
| [`result-actions.png`](docs/screenshots/result-actions.png) | Defensive actions with pasteable SIEM/EDR hunt queries |
| `investigation console` | Live pipeline console streaming real enrichment events (shown in §5, step 2) |

To regenerate them, run `npm run build && npm start` and open the pages in a browser.

## 5. Quick start

**Requirements:** Node.js 20 or newer. Nothing else — no database server, no Docker, no API keys.

```bash
# 1. install dependencies (root + both workspaces)
npm install

# 2. create your environment file (optional — demo mode works without it)
cp .env.example .env

# 3. create the database and populate it with sample investigations
npm run seed

# 4. run the API and the web client in watch mode
npm run dev
```

Then open **<http://localhost:5173>** and sign in:

```
email    : analyst@threatlens.local
password : ThreatLens!2024
```

(The seeded account is created on first boot and the credentials are configurable in `.env` via
`SEED_ANALYST_EMAIL` / `SEED_ANALYST_PASSWORD`.)

**Single-origin production mode** (API serves the built client on one port — simplest for a demo or
submission):

```bash
npm run build
npm start          # http://localhost:4000
```

### All commands

| Command | Description |
|---------|-------------|
| `npm run dev` | API (tsx watch, port 4000) + Vite dev server (port 5173, proxies `/api`) |
| `npm run build` | Type-check and compile the server, then build the client bundle |
| `npm start` | Run the compiled server; serves the client from `web/dist` if present |
| `npm run seed` | Create the schema, seed ATT&CK + analyst, run the sample investigations |
| `npm run db:reset` | Delete the SQLite database (then run `npm run seed` again) |
| `npm test` | Run the server unit tests |
| `npm run typecheck` | Type-check both workspaces |

### Walkthrough for a demo (5 minutes)

1. Sign in → **Dashboard**. Six metrics, six charts, ~29 investigations across all five risk bands.
2. **Investigate** → click the sample card `203.0.113.50`. Watch the console stream
   `VALIDATE → ENRICH → CORRELATE → SCORE → ATT&CK → PERSIST`.
3. Land on the result page. Risk **100/100 CRITICAL**, 6 sources, raw factor sum **119 → clamped to
   100** (the clamp is disclosed, not hidden).
4. **Correlation** → drag nodes, click to focus. Actor → malware → C2 domain → C2 IP → related hash.
5. **ATT&CK** → 6 techniques, each with the specific evidence that produced it and a link to
   attack.mitre.org.
6. **Defensive actions** → P1 containment steps with copy-paste SIEM/EDR hunt queries.
7. Now investigate `8.8.8.8`. Risk **0/100 CLEAN**, no ATT&CK mappings
   ("*No MITRE ATT&CK technique identified*"), and a visible **trusted-infrastructure offset** —
   the same engine, a defensible opposite conclusion.
8. **Settings** → show that no API key is stored client-side; switch to LIVE mode and re-run an
   investigation to see every provider report `unconfigured` rather than silently faking data.

## 6. Configuration

All configuration is environment-based. Copy `.env.example` to `.env`; every value has a working
default and **none are required**.

| Variable | Default | Purpose |
|----------|---------|---------|
| `NODE_ENV` | `development` | `production` enables secure cookies + HSTS |
| `PORT` | `4000` | API port |
| `CLIENT_ORIGIN` | `http://localhost:5173` | Primary allowed CORS origin |
| `ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated CORS allowlist |
| `DATABASE_PATH` | `data/threatlens.sqlite` | SQLite file (created automatically) |
| `JWT_SECRET` | dev fallback | **Set this in any real deployment** (see below) |
| `JWT_EXPIRES_IN` | `8h` | Session lifetime |
| `SEED_ANALYST_EMAIL` | `analyst@threatlens.local` | Seeded account email |
| `SEED_ANALYST_PASSWORD` | `ThreatLens!2024` | Seeded account password |
| `INTELLIGENCE_MODE` | `auto` | `auto` \| `live` \| `demo` (Settings page can override at runtime) |
| `SHOW_DEMO_BADGE` | `true` | Render the "DEMO DATA" indicator |
| `VIRUSTOTAL_API_KEY` | – | VirusTotal API v3 |
| `ABUSEIPDB_API_KEY` | – | AbuseIPDB API v2 |
| `OTX_API_KEY` | – | AlienVault OTX |
| `URLHAUS_ENABLED` | `true` | abuse.ch URLhaus (keyless) |
| `GREYNOISE_API_KEY` | – | GreyNoise community API |
| `SHODAN_API_KEY` | – | Shodan host/DNS API |
| `PROVIDER_MIN_INTERVAL_MS` | `1500` | Client-side throttle between calls to the same provider |
| `PROVIDER_TIMEOUT_MS` | `12000` | Hard per-request upstream timeout |
| `MISP_URL` / `MISP_API_KEY` | – | Reserved for MISP ingestion (future enhancement) |
| `STIX_BUNDLE_PATH` | – | Reserved for local STIX 2.1 bundle ingestion |

Generate a strong JWT secret:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

In `NODE_ENV=production` the server **refuses to boot** with a missing or short `JWT_SECRET`.

## 7. Demo mode

The project requirement is that it works with no API keys, and that simulated data is never
presented as real. Both are enforced structurally, not just by convention:

**1. Every verdict carries an origin.** `ProviderVerdict.origin` is `'live' | 'demo'`. The UI renders
a `DEMO DATA` badge for any demo-sourced value, the persistence layer stores it in
`enrichment_results.origin`, and the report prints a provenance block naming every source and
whether it was simulated.

**2. The UI says so globally.** A persistent banner states why demo mode is active, and the
Settings page shows a per-provider table of which credentials are configured — reporting only
booleans, never values.

**3. Unknown indicators get no intelligence.** In demo mode, an indicator outside the built-in
catalog returns `not_found` with an explanation, and the investigation completes as `failed` with
**no risk score assigned**. The platform explicitly refuses to report a "clean" verdict when it
simply has no data — see `insufficientIntelligence` in the API and section 5 of the report.

**4. Safety of the fictional data** (`server/src/providers/demo/dataset.ts`):

- All IP indicators are inside IETF documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24` (RFC 5737) and `2001:db8::/32` (RFC 3849). They cannot be live infrastructure.
- All domains use the RFC 2606 reserved namespaces (`example.com`, `example.net`, `example.org`,
  `.example`). They cannot resolve.
- All file hashes are `sha` digests of ThreatLens-specific labels, so they cannot collide with a
  real malware sample.
- Threat actors, malware families and campaigns are invented and carry a `DEMO-` prefix and a
  `(fictional)` suffix. No real actor or malware family is impersonated.
- The only real-world addresses in the dataset are `8.8.8.8`, `1.1.1.1` and `9.9.9.9`, correctly
  labelled as public DNS resolvers and used deliberately to demonstrate the CLEAN verdict path and
  the trusted-infrastructure offset.
- `rawExcerpt` on every demo verdict embeds the literal string
  `SIMULATED DEMO DATA - NOT A REAL API RESPONSE`.

**Demo catalogue (29 profiles across all 8 indicator types)** includes a C2 server, a phishing
domain, a loader URL, an actor-attributed implant hash, a stealer with weak engine consensus (to show
the engine is *not* over-confident), a single-engine-hit hash (to show a `not enough evidence`
verdict), an IDN lookalike domain, a DGA-style hostname, a shared-hosting address with light abuse
history, and several clean control cases.

## 8. Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Web client (React 18 + TypeScript + Vite + Recharts)                    │
│  /dashboard  /investigate  /investigation/:id  /history  /indicators     │
│  /threat-actors  /mitre  /reports  /settings                            │
│  · httpOnly-cookie session, no credentials, no provider URLs in the bundle│
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTPS / JSON over /api
┌───────────────────────────────────┴──────────────────────────────────────┐
│  Express API  (auth, rate limiting, CSP, validation, error envelope)     │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴──────────────────────────────────────┐
│  CTI service layer                                                       │
│  investigationService (orchestration) · resultService (view assembly)     │
│  reportBuilder + pdfRenderer · registry (mode resolution)                │
├──────────────────────────────────────────────────────────────────────────┤
│  Core engines (pure, deterministic, unit-tested)                         │
│  ioc/detect · ioc/validate · aggregate · risk/engine                     │
│  mitre/mapper · correlation/correlator · recommendations/engine          │
├──────────────────────────────────────────────────────────────────────────┤
│  Provider layer — one interface, many adapters                           │
│  virustotal/ abuseipdb/ otx/ urlhaus/ greynoise/ shodan/ demo/ mitre/     │
│  http.ts (timeout, client-side throttle, error taxonomy)                 │
├──────────────────────────────────────────────────────────────────────────┤
│  Repositories (normalised, parameterised SQL)                            │
│  users · indicators · investigations · knowledge · analytics              │
├──────────────────────────────────────────────────────────────────────────┤
│  SQLite (better-sqlite3, WAL, FK enforcement) — data/threatlens.sqlite  │
└──────────────────────────────────────────────────────────────────────────┘
```

**Layering rules that the code actually follows**

- The **core engines have no I/O.** `scoreRisk`, `mapTechniques`, `buildCorrelationGraph`,
  `buildDefensiveActions` and `aggregateIntelligence` are pure functions of their input. This is
  what makes them unit-testable and what makes the scores reproducible.
- The **provider interface is the only thing the service layer knows about.** Adding a feed means
  writing one file that returns a `ProviderVerdict`; no orchestration, scoring, UI or report code
  changes.
- **Provider HTTP calls happen outside database transactions.** better-sqlite3 is synchronous, so
  this is deliberate: the event loop is never blocked for long, because the slow part (network) is
  async and the fast part (writes) is one short transaction.
- **Evidence is stored; derived views are recomputed.** Reopening an old investigation re-derives the
  risk breakdown, ATT&CK mapping, graph and recommendations from the *stored* enrichment snapshot,
  so the numbers always match the evidence shown next to them, and no provider quota is consumed by
  browsing history.

## 9. The CTI lifecycle in this system

```
  ① COLLECTION      Analyst submits an indicator (UI, or a deep link such as
                    /investigate?q=203.0.113.50). The value is normalised and
                    stored once as a reusable indicator entity.
                          ↓
  ② PROCESSING      detectIocType() classifies it using ordered, anchored rules;
                    validateIoc() runs syntactic → semantic → policy checks and
                    attaches warnings (documentation range, IDN, deep subdomain,
                    entropy, private address).
                          ↓
  ③ ENRICHMENT      All applicable providers are queried in parallel with a
                    per-provider throttle, hard timeouts and error isolation.
                    Each returns a normalised ProviderVerdict or a typed failure.
                          ↓
  ④ CORRELATION     aggregateIntelligence() merges verdicts with field-level
                    provenance and a documented provider priority order;
                    the correlator builds a typed entity graph; indicator-to-
                    indicator relationships are persisted as the platform's memory.
                          ↓
  ⑤ ANALYSIS        scoreRisk() produces a 0–100 score with a full factor
                    breakdown; mapTechniques() maps ATT&CK techniques only where
                    evidence exists; buildDefensiveActions() produces the checklist.
                          ↓
  ⑥ PRODUCTION      Evidence, factors, technique mappings, entity links, related
                    indicators and a 13-event timeline are written in one
                    transaction. The analyst adds notes and a triage rating.
                          ↓
  ⑦ DISSEMINATION   REST API → dashboard aggregates → PDF/JSON/Markdown report,
                    each section labelled by evidence class.
```

Each stage writes a timeline event, so the console and the report show the pipeline as it actually
ran rather than a reconstruction.

## 10. How this project implements Cyber Threat Intelligence

This section maps the seven functions of the intelligence cycle onto concrete code.

### Collection

Indicators arrive from three directions:

1. **Analyst submission** — the `/investigate` endpoint. The value is defanged-aware, type-detected
   and validated before anything else happens (`core/ioc/detect.ts`, `core/ioc/validate.ts`).
2. **Derived indicators** — while enriching, every related entity a provider reports is itself
   stored as an indicator (`repositories/indicators.ts::upsertIoc`). Investigating a C2 IP therefore
   grows the platform's indicator library with its domain, sibling IP, URLs and hashes.
3. **Analyst-curated library** — indicators carry notes and a triage rating, so the library
   accumulates analyst judgement over time, not just tool output.

Reserve hooks for automated collection (MISP/STIX) are declared in the environment but not wired in;
see [Future enhancements](#24-limitations--future-enhancements).

### Processing

`core/ioc/detect.ts` implements processing as a **pure, ordered rule table** (SHA-256 → SHA-1 → MD5 →
IPv4 → IPv6 → URL → email → domain), with fully anchored regexes so `999.1.1.1` cannot silently
become a "domain" and a 33-character hex string cannot be guessed into a hash type. The module also
performs public-suffix-aware registrable-domain extraction, punycode detection and Shannon entropy
calculation for DGA-style labels.

`core/ioc/validate.ts` then applies three layers: syntactic, semantic (documentation range, private
space, reserved namespace) and policy (loopback, multicast, length bound, metacharacter rejection).

### Enrichment

`providers/` holds one directory per source, all implementing `ThreatIntelProvider`
(`providers/types.ts`). Each adapter's only job is to translate a vendor-specific response into the
shared `ProviderVerdict` vocabulary — detection statistics, reputation score, network attribution,
related entities, behavioural tags, dates, latency and a truncated raw excerpt.

Cross-cutting concerns live in `providers/http.ts`:

- **Timeouts** via `AbortController`, so a hanging upstream cannot stall an investigation.
- **Client-side rate limiting** — a per-provider minimum interval (`PROVIDER_MIN_INTERVAL_MS`).
  Free tiers are extremely tight (VirusTotal 4 req/min, AbuseIPDB 1000 checks/day) and exceeding them
  gets a key suspended, so the platform throttles *before* sending.
- **A single error taxonomy** — `auth_error`, `forbidden`, `quota_exceeded`, `rate_limited`,
  `not_found`, `upstream_error`, `network_error`, `timeout`, `malformed_response` — understood
  identically by the UI, the timeline and the confidence model.

Aggregation (`core/aggregate.ts`) then merges provider verdicts using documented rules: most severe
verdict wins; detection counts are summed per provider (not double counted across sources);
network fields resolve in a **fixed provider priority order** rather than arrival order, so two
providers disagreeing about geolocation cannot make the output depend on network timing.

### Analysis

Two engines, both deterministic:

- `core/risk/engine.ts` — a weighted factor model. Every factor records its evidence string, the
  provider ids it came from and a rule id; the total is clamped to 0–100 and **the pre-clamp sum is
  disclosed** so the arithmetic can be audited even when clamping occurred.
- `core/mitre/mapper.ts` — a rule engine that only asserts a technique when one of three documented
  evidence classes supports it (provider-published id, malware-family behaviour, behavioural rule),
  and refuses to map anything for an indicator with no malicious signal.

A third analysis product is `core/recommendations/engine.ts`, which turns risk and behaviour into
defensive actions with pasteable hunt queries.

### Correlation

`core/correlation/correlator.ts` builds a typed graph: indicator↔indicator edges are named by the
entity types involved (`resolves-to`, `served-by`, `staged-on`, `communicates-with`), and
malware/actor/campaign nodes are attached with the relation a source actually asserted. Actor→malware
and actor→campaign edges are only emitted when **one source reported both for the same indicator**,
and the edge description says so.

Relationships are persisted in `ioc_relationships` with an observation count, so the platform
accumulates a genuine intelligence base: investigating a *new* indicator surfaces entities learned
during *earlier* investigations, rendered at `low` confidence because the observation is second-hand.

### Intelligence production

`services/reportBuilder.ts` builds one structured report object that drives the on-screen preview,
the Markdown export and the PDF (`services/pdfRenderer.ts`). Each section is tagged with an
**evidence class**:

- `observed-fact` — values ThreatLens measured directly (indicator parsing, pipeline events, timing)
- `external-intelligence` — third-party claims, reported verbatim with the source attached
- `analyst-assessment` — the risk score, its factor arithmetic, ATT&CK mappings, recommended actions
- `context` — caveats, coverage gaps and data-quality warnings

The report also carries a provenance block naming every source, whether it was live or simulated, and
a TLP:AMBER classification.

### Dissemination

- **REST API** consumed by the React client (no provider credentials cross the boundary).
- **Dashboard aggregation** (`repositories/analytics.ts`) — every number is a live `GROUP BY` over the
  normalised schema, so a dashboard can never disagree with the history it links to.
- **Exports** — PDF for submission/hand-off, JSON for machine ingestion (re-ingestible, versioned
  schema `threatlens.cti.report/v1`), Markdown for wiki paste.
- **Analyst-to-analyst** — indicators, notes and triage ratings persist in the shared library, and
  related indicators are one click away from re-investigation.

## 11. IOC detection & validation

**Detection is ordered, anchored and pure.** The first matching rule wins, so the result is
deterministic and unit-testable.

| Order | Rule | Accepts | Rejects |
|-------|------|---------|---------|
| 1 | `sha256` | exactly 64 hex chars | 63/65 chars, non-hex |
| 2 | `sha1` | exactly 40 hex chars | — |
| 3 | `md5` | exactly 32 hex chars | — |
| 4 | `ipv4` | dotted-quad, each octet 0–255, **no leading zeros** | `999.1.1.1`, `01.2.3.4` |
| 5 | `ipv6` | full, `::`-compressed and IPv4-mapped forms | zone/other syntax |
| 6 | `url` | `http(s)://` + valid host | other schemes, malformed host |
| 7 | `email` | `local@domain` with a valid domain | no TLD, bad local part |
| 8 | `domain` | RFC 1035/1123 hostname, ≤253 chars | embedded spaces, single labels |

Leading zeros are rejected on purpose: in some resolvers `0177.0.0.1` is interpreted as octal
(`127.0.0.1`), an ambiguity that has been used to slip past naive filters.

**Validation adds semantics, not just syntax.** Warnings are surfaced, not hidden, because they
change how the analyst should read the result:

| Code | Meaning |
|------|---------|
| `DOCUMENTATION_RANGE` | RFC 5737 / 3849 — no public feed can hold data; used by the demo dataset |
| `PRIVATE_ADDRESS`, `LINK_LOCAL` | RFC 1918 / link-local — public feeds will return little |
| `RESERVED_DOMAIN` | RFC 2606 reserved namespace |
| `HIGH_ENTROPY_LABEL` | Shannon entropy ≥ 3.4 on the first label — DGA-consistent |
| `DEEP_SUBDOMAIN` | ≥ 4 levels — tracking or evasion pattern |
| `NON_STANDARD_PORT` | URL port outside {80, 443, 8080, 8443} |
| `PUNYCODE` | IDN hostname — deceptive-registration signal |
| `WEAK_HASH` | MD5 — cryptographically broken, treat identity matches with caution |

Hard refusals (loopback, multicast, broadcast, whitespace/metacharacters, >2048 chars) return a typed
error code that the UI shows verbatim.

**De-fanging** is handled before detection: `hxxp`→`http`, `[.]`/`(.)`/`{.}``→`.`, `[at]`/`[@]`→`@`,
brackets stripped. The UI tells the analyst when this happened.

## 12. Threat intelligence providers

All adapters implement one interface (`providers/types.ts`):

```ts
interface ThreatIntelProvider {
  readonly id: string; readonly name: string; readonly requiresKey: boolean;
  readonly supports: readonly IocType[];
  isConfigured(): boolean;
  lookup(ioc: NormalizedIoc, ctx: ProviderContext): Promise<ProviderVerdict>;
}
```

A provider **must** never throw (errors are returned as `status` + `error`, so one dead feed can never
fail an investigation), never fabricate data (unknown fields are `null`, not invented), and must label
the origin of everything it returns.

| Provider | Indicators | What it contributes | Key required |
|----------|-----------|---------------------|--------------|
| **VirusTotal** v3 | IP, domain, URL, file hash | Multi-engine detection stats, community reputation, passive-DNS resolutions, ASN/geo, signature names | yes |
| **AbuseIPDB** v2 | IPv4, IPv6 | Abuse confidence score, report count, distinct reporters, usage type, ISP, hostnames | yes |
| **AlienVault OTX** | all | Pulse membership, adversary, malware families, campaign names, tags | yes |
| **URLhaus** (abuse.ch) | IP, domain, URL | Confirmed payload-hosting listings, threat family, tags, payload status | no |
| **GreyNoise** | IPv4, IPv6 | Internet-scanner context and benign/malicious classification | yes |
| **Shodan** | IP, domain | Open ports, service exposure, hosting ASN, malware/C2 tags | yes |
| **ThreatLens Demo** | all | Fictional dataset expanded into 6 independent simulated sources | no |

Notes on the adapters that are easy to get wrong:

- **VirusTotal** identifies URLs by a base64url-encoded (unpadded) URL, and a second `resolutions`
  call is issued for IPs/domains to populate the correlation graph. If that optional call fails, the
  primary verdict still succeeds.
- **AbuseIPDB** has no engine statistics, so the adapter *derives* a comparable detection block from
  the abuse confidence score (`malicious ≈ score/20`, `harmless = 70 − malicious`) and marks the
  result as derived. It never pretends AbuseIPDB ran AV engines.
- **GreyNoise** answers "does this host scan the internet?", which is not "is this host malicious?".
  The risk engine therefore treats it as a *context* signal with modest weight, and its
  benign/educational classification becomes an explicit negative offset.
- **OTX** pulse membership is context, not proof: a pulse reference alone yields `suspicious`, never
  `malicious`. Only OTX community validation marked malicious produces a malicious verdict.

**Adding a provider**

```
server/src/providers/<name>/index.ts    # class <Name>Provider implements ThreatIntelProvider
server/src/providers/registry.ts        # add to buildLiveProviders()
```

Nothing else changes — orchestration, scoring, ATT&CK mapping, UI and reports are all
provider-agnostic.

## 13. Risk scoring methodology

The score is the sum of independent, weighted factors. Every factor records its evidence string, the
provider ids it came from and a rule id, and the UI renders the arithmetic in full.

| Factor | Cap | Rule | Evidence shown |
|--------|-----|------|-----------------|
| `malicious_reputation` | +30 | `20 + 10 × min(1, ratio/0.1)` when malicious detections exist; +12 for suspicious-only | "26 of 351 engines flagged this indicator (7.4% ratio), 4 further marked suspicious" |
| `abuse_confidence` | +20 | ≥90 → 20, ≥75 → 16, ≥50 → 12, ≥25 → 8, ≥1 → 4 | "Abuse confidence 96/100 (near-certain abuse) with 47 community reports" |
| `multi_engine_consensus` | +12 | `4 + maliciousCount` when ≥5 engines flag it | "26 independent detection engines flagged this indicator" |
| `malware_association` | +15 | 1 family → +10, 2 → +13, ≥3 → +15 | "Associated with 3 malware families: …" |
| `c2_association` | +15 | +15 confirmed C2, +8 adjacent (botnet / C&C hosting) | "Intelligence sources explicitly identify this indicator as command-and-control infrastructure" |
| `multi_source_corroboration` | +10 | 2 sources → +4, 3 → +7, ≥4 → +10 | "5 independent sources returned a reputation verdict (…)" |
| `recent_activity` | +10 | ≤7d → +10, ≤30d → +7, ≤90d → +4, ≤180d → +2 | "Most recent sighting within the last 7 days (…)" |
| `actor_attribution` | +10 | A named adversary appears in community intelligence | "Community intelligence attributes this indicator to Nightfall Jackal (fictional) in campaign(s) …" |
| `infrastructure_anomaly` | +10 | non-standard port +4, punycode +3, high entropy +3, deep subdomain +2 | "Static analysis of the indicator itself flags: non-standard port 8443; punycode (IDN) hostname" |
| `trusted_infrastructure` | −20 | Recognised public-service infrastructure (documented prefix list) | "Google Public DNS (AS15169): high connection volume and report count are expected for this class of infrastructure" |
| `clean_consensus` | −10 | ≥2 sources report clean and none report malicious | "2 independent sources report this indicator as clean with no malicious detections" |

**Total positive capacity: 120 → clamped to 100.** When clamping occurs the UI states
`raw 119 → clamped 100` rather than hiding it, and a unit test asserts that the factor sum always
reconciles with the disclosed raw total.

**Risk levels**

| Score | Level | Meaning |
|-------|-------|---------|
| 0–19 | `CLEAN` | No threat signal; no containment warranted |
| 20–39 | `LOW` | Weak suspicion; monitor, do not block |
| 40–59 | `MEDIUM` | Questionable; scoped hunting recommended |
| 60–79 | `HIGH` | Likely threat; same-day defensive action |
| 80–100 | `CRITICAL` | Active threat; immediate containment |

**Insufficient intelligence is its own state.** If no source returned usable data, no score is
assigned at all. Reporting `0 = CLEAN` when the platform simply has no data would be the most
damaging possible error, so the API sets `insufficientIntelligence: true`, the UI renders
`INSUFFICIENT INTELLIGENCE` instead of a score, and the report states it in the executive summary and
in section 5.

**Confidence is a separate question from risk.** Confidence answers *"how much do we actually know?"*,
not *"how dangerous is it?"*. It is computed from coverage — successful sources (+40 base, +8 per
additional), detection statistics (+8), network data (+10), categorisation (+6), last-seen (+5),
multiple opinions (+5) — minus penalties for failed sources (−20 each, capped at −40) and for demo
provenance (−5), and is capped at 97 because absolute certainty is never an honest claim. A failed
source therefore lowers *confidence* without changing the *score*, which is the correct behaviour: we
still know what the successful sources said.

**Design properties**

- **Deterministic.** No randomness, no time-of-day dependence beyond the explicit recency windows,
  no dependence on provider availability beyond what the evidence states. A unit test asserts two
  runs over identical input produce byte-identical factors.
- **Explainable and auditable.** The factor arithmetic is displayed and reproducible by hand; the
  full methodology is also exposed at `GET /api/settings` and printed in report section 6.
- **Contestable.** Offsets (especially `trusted_infrastructure`) are visible so a reviewer can
  disagree with them; they are not hidden constants.
- **Type-aware.** Hashes, domains and IPs get different treatment: a download URL is scored
  differently from the host that serves it, and a file hash supports ATT&CK mapping in ways an IP
  cannot.

## 14. MITRE ATT&CK integration

**Knowledge base.** `providers/mitre/index.ts` ships a curated offline subset of the ATT&CK matrix
(44 techniques, Enterprise domain, stamped `v14.1`). A subset rather than the full ~30 MB STIX bundle
because reproducibility matters more than coverage here: every mapping decision is traceable to a
documented rule, and every technique links to its official page. Technique ids, names and tactics are
public factual data.

**Mapping engine.** `core/mitre/mapper.ts` accepts only three evidence classes, and records which
one produced each mapping:

| `mappingBasis` | Trigger | Confidence |
|----------------|---------|------------|
| `provider-signal` | A source published the technique id (e.g. an OTX pulse tagged `T1059.001`) | medium |
| `malware-family-intel` | The identified family has publicly documented behaviour (e.g. Cobalt Strike → T1059.001, T1071.001, T1105, T1055, T1218) | medium / low |
| `behavioural-rule` | A documented rule over normalised intelligence (C2 tag + http(s) → T1071.001; phishing + lure type → T1566.002; payload URL → T1105; non-standard port + C2 → T1571; DGA-like hosting → T1568.002; …) | high / medium / low |

**Safety gate.** If the indicator has no malicious signal at all, all mappings are discarded except
high-confidence provider-published ones. A clean public DNS resolver therefore receives **no**
techniques — a unit test asserts this.

**When nothing matches**, the UI and the report both state:

> **No MITRE ATT&CK technique identified.** No mapping rule matched the evidence for this indicator,
> and ThreatLens does not assign techniques speculatively.

The ATT&CK page additionally shows coverage: how many techniques in the knowledge base this platform
has actually observed, and when they were last seen.

## 15. IOC correlation & the relationship graph

`core/correlation/correlator.ts` turns merged intelligence into a typed graph. Every edge carries a
relation name, a human description and a confidence — an unexplained edge in a CTI graph is worse
than no edge.

| Edge type | Relation | Example |
|-----------|----------|---------|
| IP ↔ domain | `resolves-to` / `reverse-resolves-to` | passive DNS observation |
| URL → domain/IP | `served-by` | the URL was served from this host |
| Hash → host/URL | `staged-on` / `retrieved-from` | the sample was downloaded from here |
| Email → domain | `sent-from` | observed as an envelope sender |
| IP ↔ IP | `communicates-with` | observed traffic between them |
| Indicator → malware | `associated-malware` | source identifies this infrastructure as belonging to the family |
| Indicator → actor | `attributed-to` | community attribution |
| Indicator → campaign | `part-of-campaign` | reported in campaign context |
| Actor → malware / campaign | `contextually-associated` | **only when one source reported both for this indicator**; the description says so |
| Indicator → technique | `mapped-technique` | ATT&CK mapping rationale |
| Indicator → learned entity | typed as above | from an earlier investigation, rendered at `low` confidence |

**Cross-investigation memory.** Discovered relationships are persisted in `ioc_relationships` with an
observation count and timestamps. A later investigation of a *different* indicator surfaces the same
entities, labelled with the earlier investigation reference and provider — which is how the platform
grows into an intelligence base rather than a lookup tool.

**The visualisation** (`web/src/components/IOCRelationshipGraph.tsx`) is a hand-written force-directed
graph in SVG. That is a deliberate choice, and defensible on three grounds:

1. **Auditability** — the algorithm (Coulomb repulsion, Hooke springs, weak centring, cooling
   schedule) is ~60 readable lines, which matters more for a viva than saving 40 KB.
2. **Determinism** — initial positions come from the node index on a golden-angle spiral and the
   simulation runs a fixed iteration count, so the same investigation always renders the same
   picture. A library with a random start would make screenshots unstable.
3. **Zero supply-chain weight** — one less dependency in a security project.

Interaction: drag nodes, pan, wheel-zoom, click a node to focus its neighbourhood, hover for the
entity's metadata, and a greedy label-de-collision pass so a dense graph never becomes unreadable.

## 16. Intelligence reports

`GET /api/reports/:id` returns the report object; `/export.pdf`, `/export.json` and `/export.md`
render it. The on-screen preview renders the same object, so what is reviewed is what is exported.

1. Executive summary (narrative + key findings + risk/confidence/verdict)
2. Indicator information *(observed fact)*
3. Threat reputation *(external intelligence)*
4. Enrichment results by source — including failed and unconfigured sources *(external intelligence)*
4b. Network intelligence, with per-field source *(external intelligence)*
5. Risk score *(analyst assessment)*
6. Risk score explanation — every factor, its points, evidence and sources *(analyst assessment)*
7. Related indicators with relation, confidence and reporting source *(external intelligence)*
8. MITRE ATT&CK mapping with per-mapping rationale and basis *(analyst assessment)*
9. Investigation timeline *(observed fact)*
10. Analyst assessment *(analyst assessment)*
11. Recommended defensive actions *(analyst assessment)*
12. Data quality and caveats *(context)*

The PDF is generated server-side with PDFKit (no headless browser, no client-side renderer) with
control characters stripped from every dynamic string, plus page footers carrying the report id and
TLP marking.

## 17. Recommended defensive actions

`core/recommendations/engine.ts` selects actions by rule from **(IOC type × risk level × observed
behaviour)**, so the checklist is deterministic. Actions are containment, detection engineering,
eradication, hunting and monitoring only — strictly defensive. Where a hunt is useful, a pasteable
query is emitted for the analyst's SIEM/EDR.

Examples of the rule set:

- **CRITICAL IP** — block at the perimeter; search firewall/proxy/DNS/EDR history *before* blocking
  so evidence survives; investigate outbound initiators; treat C2-labelled addresses as beaconing and
  hunt for periodic low-volume connections; block the related domains in the same change window
  (blocking only the address leaves domain fallback open).
- **Domain/URL** — DNS filtering and proxy block with NXDOMAIN enforcement; retroactive proxy/DNS
  search; for phishing, mailbox purge **plus** forced credential reset for every recipient (a
  harvested credential is the real loss, not the blocked URL).
- **File hash** — EDR fleet search; quarantine while preserving a sample for analysis; investigate the
  parent process chain (build the rule around the delivery vector, not the hash); submit to sandbox
  and feed recovered config back as new indicators.
- **Email** — sender blocklist *paired with* a rule on the linked domain/URL, because mailboxes are
  disposable and rarely the durable indicator.
- **Shared hosting / clean / documentation range** — explicitly **monitor rather than block**, since
  blocking a bulk-hosting address denies service to unrelated tenants.
- **Documentation range** — no defensive action required; investigate any sighting as a test-data or
  misconfiguration signal.

## 18. Database schema

SQLite via better-sqlite3 (WAL, foreign keys on, `busy_timeout` 5000). Timestamps are ISO-8601 UTC
strings, which sort lexicographically in chronological order.

| Table | Purpose |
|-------|---------|
| `users` | Analyst accounts; bcrypt hash, role, last login |
| `iocs` | Indicator library, one row per (type, value_hash). `times_seen` counts investigations |
| `investigations` | One row per analysis run: status, mode, score, level, confidence, counts, analyst fields |
| `enrichment_results` | **One row per provider per investigation** — the raw intelligence snapshot, forever |
| `risk_factors` | The factor breakdown as displayed (id, label, points, category, evidence, sources) |
| `mitre_techniques` | ATT&CK knowledge base (tactics, platforms, data sources, official URL) |
| `threat_actors` / `malware` / `campaigns` | Reference entities, upserted by external id |
| `investigation_techniques` | Junction: investigation ↔ technique, with relationship, confidence, basis, rationale |
| `investigation_actors` / `_malware` / `_campaigns` | Junctions with confidence and basis text |
| `investigation_related_iocs` | Junction: investigation ↔ related indicator, typed and attributed |
| `ioc_relationships` | Indicator ↔ indicator edges with observation count, first/last observed, provider |
| `investigation_timeline` | Ordered pipeline events (kind, title, description, source, meta) |
| `reports` | Generated-report audit log |
| `tags` / `investigation_tags` | Free-form analyst tagging |
| `audit_log` | Who did what |
| `settings` | Runtime overrides (e.g. intelligence mode) |

**Normalisation decisions worth defending**

- **Indicators are entities, investigations are snapshots.** Re-investigating the same value updates
  one `iocs` row (`times_seen++`) and appends a new `investigations` row, so the platform keeps an
  indicator "case file" with many intelligence snapshots over time — and old reports still reflect
  what was known at the time.
- **Enrichment is append-only and never merged.** Merging happens in `aggregateIntelligence` at read
  time. This is what allows a three-month-old investigation to be reopened and re-rendered with
  field-level provenance intact.
- **Many-to-many uses junction tables, not JSON blobs**, so graph queries stay relational
  (`SELECT t.external_id, COUNT(*) FROM investigation_techniques … GROUP BY t.id`).
- **Deleting an investigation cascades** to its evidence, factors, timeline and mappings, but keeps
  the shared `iocs` row, which may be referenced by other investigations.

## 19. API reference

All analyst endpoints require a session (`httpOnly` JWT cookie). Errors use one envelope:
`{ "error": { "code", "message", "hint" } }`.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/public/bootstrap` | App metadata, provider registry, demo catalogue, IOC types (public) |
| `POST` | `/api/auth/login` · `/api/auth/logout` | Session lifecycle (login rate limited) |
| `GET`/`PATCH` | `/api/auth/me` | Current user / profile update |
| `POST` | `/api/auth/password` | Change password (policy-enforced) |
| `GET` | `/api/dashboard` | All metrics and chart series |
| `POST` | `/api/iocs/detect` | Type detection + validation for one indicator |
| `POST` | `/api/investigations` | Start an investigation → `202` + id |
| `GET` | `/api/investigations/:id/progress` | Live status + accumulated timeline |
| `GET` | `/api/investigations/:id` | Full analyst-facing result |
| `GET` | `/api/investigations` | History with `search`, `type[]`, `level[]`, `status[]`, `mode[]`, `sort`, `limit`, `offset` |
| `PATCH` | `/api/investigations/:id/analyst-notes` | Analyst notes, assessment, triage rating |
| `POST` | `/api/investigations/:id/reanalyse` | Re-run and open a new snapshot |
| `DELETE` | `/api/investigations/:id` | Delete an investigation |
| `GET` | `/api/iocs` · `/api/iocs/:id/relationships` | Indicator library, correlation memory |
| `GET` | `/api/knowledge/mitre` · `/actors` · `/malware` · `/campaigns` | Knowledge base views |
| `GET` | `/api/reports` | Reportable investigations + generated-report log |
| `GET` | `/api/reports/:id` · `/export.{json,pdf,md}` | Report object and exports |
| `GET` | `/api/settings` | Mode, provider health, key **presence** flags, methodology, audit trail |
| `POST` | `/api/settings/mode` | Switch `live` / `demo` / `auto` at runtime |
| `GET` | `/api/health` | Liveness + database + mode |

## 20. Technology stack

| Layer | Choice | Why |
|-------|--------|-----|
| Frontend | React 18 + TypeScript + Vite 6 | Fast builds, strict types across the API boundary |
| Routing | react-router-dom 6 | Nested layouts and deep links (`/investigate?q=…`, filtered history URLs) |
| Charts | Recharts 2 | Declarative, themeable via CSS variables, no canvas theming fights |
| Graph | Hand-written SVG force layout | Deterministic, auditable, zero dependency (see §15) |
| Backend | Node 20 + Express 4 + TypeScript (ESM) | Small, boring, well understood |
| Database | SQLite via better-sqlite3 | Synchronous transactions suit this workload; zero external service to install |
| Validation | Zod 3 | One schema at the API boundary, inferred types end-to-end |
| Auth | jsonwebtoken + bcryptjs | httpOnly-cookie JWT, bcrypt cost 12 |
| PDF | PDFKit | Server-side, no headless browser, text-only streams (safe) |
| HTTP | Native `fetch` + `AbortController` | No HTTP client dependency; timeouts built in |
| Tests | `node:test` | Built into Node; no test-runner dependency |

**No UI framework, no ORM, no state-management library, no HTTP client, no graph library** — a
deliberate constraint that keeps the dependency surface small enough to audit, which matters for a
security project.

## 21. Security design

**Secrets**

- All credentials come from environment variables via a typed config object. Providers receive that
  object instead of reading `process.env`, which makes them testable and prevents accidental leakage.
- The API **never returns a key value**. `/api/settings` reports booleans and documentation links
  only. The browser bundle contains no provider URL or credential.
- `.env` is git-ignored; `.env.example` is committed with empty values. `.gitignore` also excludes
  `*.sqlite`, `data/` and `*.log`.
- The structured logger redacts any key matching `api[-_]?key|authorization|cookie|password|secret|token|x-api-key`.

**Authentication & sessions**

- JWT in an `httpOnly`, `sameSite=lax` cookie, `secure` in production — an XSS bug cannot read the
  session token because no token exists in JavaScript.
- Passwords hashed with bcrypt at cost 12. Failed logins run the same work whether or not the user
  exists, to blunt a timing oracle.
- Login rate limited to 10 attempts / 15 min / IP; password changes to 5 / 15 min / user; the general
  API to 300 requests/min.
- The token payload holds only user id, role and display name — no email, no secrets.

**Input handling**

- Every request body is validated with Zod before reaching a service.
- SQL is exclusively parameterised (`better-sqlite3` prepared statements). The search endpoint was
  explicitly tested with a `'; OR 1=1--` payload: it returns 0 rows, no error.
- IOC validation rejects whitespace, shell/HTML metacharacters and over-length input before any
  lookup, storage or rendering.
- `X-Content-Security-Policy: script-src 'self'` — no inline script and no third-party script can
  run. `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`. `style-src` allows
  `'unsafe-inline'` because Recharts sets inline style attributes; scripts are unaffected.
- Plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy`, `Permissions-Policy` and HSTS in production.
- `trust proxy` is **off** by default: enabling it would let a client spoof `X-Forwarded-For` and
  bypass the rate limiter.

**Provider safety**

- Hard per-request timeouts; a hung upstream cannot stall an investigation.
- Client-side per-provider throttling protects free-tier quota (and therefore the API key).
- Provider failures are isolated: an exception in one adapter cannot fail an investigation, and
  partial results are reported as `partial` rather than silently presented as complete.
- Raw payloads are truncated to 8 KB before storage, and the PDF renderer strips control characters
  from every dynamic string.

**Data minimisation**

- No password-recovery flow is implemented on purpose: a local deployment has no mail transport, and
  storing recovery secrets would breach the minimisation requirement.
- Provider responses are truncated; nothing beyond the fields the risk engine consumes is retained.

**Defensive-only output** — the recommendations engine contains no offensive or exploitation content,
and a unit test asserts that wording across all generated actions.

## 22. Testing

```bash
npm test                              # 31 server unit tests
npm run typecheck                     # both workspaces
# production build + headless browser walkthrough of all 8 pages:
npm run build && npm start
```

The unit tests (`server/src/tests/core.test.ts`) cover the parts most likely to be challenged in
review:

- risk-level boundary values (0/19/20/39/40/59/60/79/80/100) and colour/semantic mapping
- detection of all 8 indicator types, plus rejection of out-of-range IPv4, wrong-length hashes,
  loopback, metacharacters and oversized input
- de-fanging and public-suffix-aware registrable-domain extraction
- **determinism**: two evaluations over identical input produce identical factors
- **arithmetic integrity**: the factor sum reconciles with the disclosed raw score, and clamping is
  disclosed
- **confidence behaviour**: a failed source lowers confidence but does not change the score; the
  score never claims certainty
- trusted-infrastructure offsets
- **no fabricated ATT&CK**: a clean resolver gets zero techniques; every emitted technique is in the
  curated knowledge base, links to attack.mitre.org, carries a basis and a rationale
- correlation graph integrity: exactly one subject node, no self-loops, every edge references
  existing nodes and is explained
- recommendations: a CRITICAL IP produces a block action and a pasteable hunt query, and no action
  contains offensive language
- aggregation: most-severe verdict wins, network fields follow the documented provider priority, and
  contextual "unknown" verdicts do not count as corroboration

During development the production bundle was additionally driven through a headless Chromium
walkthrough covering all eight pages, the full investigation flow, every result tab, report
generation, sign-out, and zero console errors (28/28 checks).

## 23. Project layout

```
threatlens/
├── package.json                  # npm workspaces + dev/build/seed scripts
├── .env.example                  # every configuration key, documented
├── README.md
│
├── server/                       # Express API + CTI service layer
│   └── src/
│       ├── index.ts              # boot: db → seed → reconcile → listen
│       ├── app.ts                # express assembly, static SPA, error handling
│       ├── config/
│       │   ├── env.ts            # typed config, .env loading, mode resolution
│       │   └── logger.ts         # structured logging + credential redaction
│       ├── core/                 # pure, deterministic engines
│       │   ├── types.ts          # shared domain contract
│       │   ├── aggregate.ts      # provider merge with field provenance
│       │   ├── ioc/detect.ts     # ordered type detection
│       │   ├── ioc/validate.ts   # syntactic / semantic / policy validation
│       │   ├── risk/engine.ts    # explainable 0-100 scoring + confidence
│       │   ├── mitre/mapper.ts   # ATT&CK mapping with evidence classes
│       │   ├── correlation/correlator.ts
│       │   └── recommendations/engine.ts
│       ├── providers/            # one directory per intelligence source
│       │   ├── types.ts          # ThreatIntelProvider interface
│       │   ├── http.ts           # timeout, throttle, error taxonomy
│       │   ├── normalize.ts      # verdict/stat normalisation
│       │   ├── registry.ts       # mode resolution + provider health
│       │   ├── virustotal/ abuseipdb/ otx/ urlhaus/ greynoise/ shodan/
│       │   ├── mitre/            # ATT&CK knowledge base
│       │   └── demo/             # fictional dataset + simulated sources
│       ├── repositories/         # normalised data access
│       │   ├── users.ts  indicators.ts  investigations.ts
│       │   ├── knowledge.ts      # techniques, actors, malware, campaigns
│       │   └── analytics.ts      # dashboard aggregations
│       ├── services/
│       │   ├── investigationService.ts   # the pipeline orchestrator
│       │   ├── resultService.ts          # stored evidence → analyst view
│       │   ├── reportBuilder.ts          # 11-section report object
│       │   └── pdfRenderer.ts            # PDFKit output
│       ├── middleware/
│       │   ├── auth.ts           # JWT cookie sessions
│       │   └── hardening.ts      # rate limit, CSP, CORS, errors
│       ├── routes/api.ts         # REST surface + Zod schemas
│       ├── db/                   # schema.sql, connection, seed, reset
│       └── tests/core.test.ts    # 31 unit tests
│
└── web/                          # React analyst console
    └── src/
        ├── main.tsx  App.tsx     # routes + protected shell
        ├── api/                  # typed client, shared types, app context
        ├── components/           # IOCSearch, RiskScoreCard/RiskBreakdown,
        │                         # ReputationCard/EnrichmentPanel,
        │                         # MITRETechniqueCard, IOCRelationshipGraph,
        │                         # InvestigationTimeline, ReportGenerator, ui
        ├── pages/                # 8 route components + login + 404
        ├── lib/format.ts         # formatting + semantic colour mapping
        └── styles/               # design system + layout (SOC dark)
```

## 24. Limitations & future enhancements

**Deliberate limitations**

- **No automated collection feed.** Indicators come from analyst submission and from relationships
  discovered during enrichment. `MISP_URL` / `STIX_BUNDLE_PATH` are reserved but not wired up.
- **Single-tenant.** One local analyst account, no roles beyond a label, no multi-analyst
  collaboration or case assignment.
- **In-memory rate limiting.** Correct for a single instance; a multi-instance deployment would move
  the counters to Redis.
- **Query-string JWT was rejected** in favour of a cookie session, which means the API is not usable
  from a third-party client without a session-priming request. For an internal analyst tool that is
  the right trade.
- **ATT&CK coverage is a curated subset** (44 techniques), not the full matrix. Feeding a local STIX
  2.1 bundle would widen coverage, at the cost of reproducibility.
- **The demo dataset is static.** Indicators outside the catalogue return no intelligence by design.

**Future enhancements**

1. **MISP / STIX 2.1 ingestion** — scheduled pull of new indicators into the library, closing the
   collection loop that currently requires analyst submission.
2. **ATT&CK mapping from the STIX bundle** with the same evidence-class discipline, plus
   version-pinned technique data and a mapping-change history.
3. **Temporal analysis** — first/last-seen sparklines per indicator, campaign timelines, and
   infrastructure reuse over time (the `ioc_relationships.observation_count` column is already the
   right substrate).
4. **Feed-quality scoring** — measure each source's precision by comparing its verdicts against
   analyst triage ratings, and weight factors accordingly. This is the natural next step given the
   analyst-rating field already exists.
5. **YARA / Sigma rule generation** for detections derived from the observed behaviour of an
   indicator (e.g. beaconing to a C2 node).
6. **Multi-analyst RBAC and case management** — assignment, escalation, SLA tracking and
   watchlists shared across investigations.
7. **Bulk submission** — paste a block of indicators and run them with a concurrency budget that
   respects provider quotas.
8. **Webhooks and outbound dissemination** — MISP/TIP-style event export so the platform can feed
   detection content back into a SIEM, plus a STIX 2.1 export of the correlation graph.
9. **Cold-storage of raw provider responses** (compressed, time-boxed) for re-scoring as the
   methodology evolves.

## 25. Academic context

**How to present this in a viva** — the three questions that usually decide a CTI capstone defence,
and where the answers live:

1. *"Why is your risk score trustworthy?"*
   It is a sum of documented, weighted factors, each carrying its evidence and its sources; the
   arithmetic is displayed in the UI and the report, the pre-clamp sum is disclosed when clamping
   occurs, and a unit test asserts the factors reconcile with the total. Confidence is scored
   separately from risk, and a failed source lowers confidence without silently moving the risk
   score. → `core/risk/engine.ts`, §13.

2. *"How do you know your ATT&CK mappings are not made up?"*
   Three accepted evidence classes only, each recorded per mapping; a safety gate that refuses to map
   anything for an indicator with no malicious signal; and an explicit "no technique identified"
   state instead of a guess. → `core/mitre/mapper.ts`, §14.

3. *"What stops your tool from lying?"*
   Three structural guarantees: every intelligence value carries a `live`/`demo` origin and is
   labelled accordingly; an indicator with no data produces "insufficient intelligence" rather than
   a clean verdict; and the demo dataset uses only reserved namespaces (RFC 5737/3849/2606) with
   synthetic hashes and invented, prefixed threat entities. → `providers/demo/`, §7.

**Traceability**

| Requirement | Implementation | Verification |
|-------------|----------------|--------------|
| IOC type detection | `core/ioc/detect.ts` | Unit tests + browser walkthrough |
| Validation | `core/ioc/validate.ts` | Unit tests, rejection matrix |
| Multi-provider enrichment | `providers/*` | Provider health page, per-source cards |
| Explainable risk scoring | `core/risk/engine.ts` | Unit tests, UI breakdown, report §6 |
| ATT&CK mapping | `core/mitre/mapper.ts` | Unit tests (incl. the "no mapping" case) |
| Correlation | `core/correlation/correlator.ts` | Unit tests, interactive graph |
| Persistence | `db/schema.sql` | Dashboard aggregates, reopening history |
| Report production | `services/report*` | PDF/JSON/MD export + audit log |
| Defensive actions | `core/recommendations/engine.ts` | Unit tests (incl. no-offensive-language) |
| Demo mode honesty | `providers/demo/*`, `registry.ts` | Origin labels, provenance blocks, mode banner |

**Ethical use.** ThreatLens is a defensive analysis tool. Its recommendations are limited to
containment, detection, eradication, hunting and monitoring. The demonstration dataset deliberately
uses only reserved address space and reserved domains, and its threat entities are invented, so the
project neither targets nor depicts real criminal infrastructure.

## 26. License

ThreatLens is released under the **MIT License**, as declared in the root `package.json`
(`"license": "MIT"`).

A `LICENSE` file is included at the repository root.

> **Note for the repository owner:** replace the `<COPYRIGHT HOLDER TO BE SET BY THE REPOSITORY OWNER>`
> placeholder on the first line of `LICENSE` with your name before publishing, so that the copyright
> attribution is correct. It was left as a placeholder deliberately rather than guessing.

MIT is a permissive licence: it allows commercial use, modification, distribution and private use,
and requires only that the copyright notice and permission notice are retained in substantial copies
of the software.

## 27. Credits

**Threat-intelligence data providers** — ThreatLens integrates with these services when the operator
supplies API keys. All intelligence remains the property of its respective provider and is subject to
each provider's terms of use and rate limits:

| Provider | Used for |
|----------|----------|
| [VirusTotal](https://www.virustotal.com) | Multi-engine file, URL, domain and IP reputation |
| [AbuseIPDB](https://www.abuseipdb.com) | Crowd-sourced IP abuse confidence and reporting |
| [AlienVault OTX](https://otx.alienvault.com) | Community pulses, adversaries, malware families, campaigns |
| [URLhaus / abuse.ch](https://urlhaus.abuse.ch) | Malware distribution (payload hosting) intelligence |
| [GreyNoise](https://www.greynoise.io) | Internet scanner context and benign/malicious classification |
| [Shodan](https://www.shodan.io) | Host and DNS service-exposure data |

**MITRE ATT&CK®** — technique identifiers, names, tactics and descriptions are used under the
[MITRE ATT&CK terms of use](https://attack.mitre.org/resources/terms-of-use/). ATT&CK® is a
registered trademark of The MITRE Corporation. Every technique card in ThreatLens links back to the
official page at [attack.mitre.org](https://attack.mitre.org).

**Reserved namespaces** — the demonstration dataset deliberately uses only IETF-reserved ranges so
that no real infrastructure is ever named:
RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`) and
RFC 2606 (`example.com`, `example.net`, `example.org`, `.example`). All threat actors, malware
families and campaigns in the demo dataset are invented and carry a `DEMO-` prefix.

**Open-source dependencies** — the project intentionally keeps its dependency surface small so it can
be audited. Principal dependencies: [React](https://react.dev), [Vite](https://vitejs.dev),
[Recharts](https://recharts.org), [Express](https://expressjs.com), [better-sqlite3](https://github.com/WiseLibs/better-sqlite3),
[Zod](https://zod.dev), [PDFKit](https://pdfkit.org), [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
and [bcryptjs](https://github.com/dcodeIO/bcrypt.js). No graph-visualisation library is used: the
relationship graph is an original deterministic force-directed SVG implementation (see
[§15](#15-ioc-correlation--the-relationship-graph)).

**The analyst** — the demo dataset's behavioural patterns are modelled on publicly reported TTP
summaries; no real threat actor or malware family is impersonated or characterised in this project.

---

**ThreatLens** — Cyber Threat Intelligence & IOC Investigation Platform
Capstone project · Node 20 · React 18 · Express · SQLite · MITRE ATT&CK®
