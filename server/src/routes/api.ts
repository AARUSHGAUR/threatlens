/**
 * API routes.
 *
 * All analyst endpoints require a session (httpOnly JWT cookie). Input is
 * validated with zod before it reaches any service, and no provider credential
 * is ever returned to the client - `/api/settings` exposes only a boolean
 * "configured" flag plus the documentation URL.
 */
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { config } from '../config/env.js';
import { clearSessionCookie, optionalAuth, requireAuth, setSessionCookie, signSession } from '../middleware/auth.js';
import { HttpError, rateLimit } from '../middleware/hardening.js';
import { detectIocType } from '../core/ioc/detect.js';
import { validateIoc, IOC_TYPE_LABEL, isDocumentationIpv4, isDocumentationIpv6 } from '../core/ioc/validate.js';
import { IOC_TYPES } from '../core/types.js';
import { DEMO_CATALOG } from '../providers/demo/dataset.js';
import { getModeOverride, registrySnapshot, resolveMode, setModeOverride } from '../providers/registry.js';
import { listTechniques, techniqueUsage, listActors, listMalware, listCampaigns, ATTACK_VERSION, countTechniques } from '../repositories/knowledge.js';
import { countIocs, listIocs, relationshipsForIoc, setIocNotes } from '../repositories/indicators.js';
import {
  deleteInvestigation,
  findInvestigation,
  investigationStats,
  listInvestigations,
  timelineFor,
  updateInvestigation,
} from '../repositories/investigations.js';
import * as analytics from '../repositories/analytics.js';
import { buildInvestigationDetail } from '../services/resultService.js';
import { startInvestigation, reconcileStaleInvestigations } from '../services/investigationService.js';
import { buildReport, reportToMarkdown } from '../services/reportBuilder.js';
import { renderReportPdf } from '../services/pdfRenderer.js';
import {
  audit,
  changePassword,
  countUsers,
  createUser,
  findUserByEmail,
  recentAudit,
  touchLastLogin,
  updateProfile,
  verifyPassword,
} from '../repositories/users.js';
import { getDb, nowIso, q } from '../db/index.js';
import { METHODOLOGY } from '../core/risk/engine.js';

export const api = Router();

// ===========================================================================
// AUTH
// ===========================================================================
const loginLimiter = rateLimit({ name: 'login', windowMs: 15 * 60 * 1000, max: 10 });
const apiLimiter = rateLimit({ name: 'api', windowMs: 60 * 1000, max: 300, keyByUser: true });

const loginSchema = z.object({
  email: z.string().trim().min(3).max(200),
  password: z.string().min(1).max(200),
});

api.post('/auth/login', loginLimiter, (req: Request, res: Response) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new HttpError(400, 'invalid_request', 'Email and password are required.');
  }
  const user = findUserByEmail(parsed.data.email);
  // Constant-ish work whether or not the user exists, to reduce timing oracle.
  const ok = user
    ? verifyPassword(parsed.data.password, user.password_hash)
    : verifyPassword(parsed.data.password, '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidiu');
  if (!user || !ok) {
    audit({ userId: null, action: 'auth.login_failed', entity: 'user', entityId: parsed.data.email });
    throw new HttpError(401, 'invalid_credentials', 'Email or password is incorrect.');
  }
  touchLastLogin(user.id);
  const publicUser = {
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    role: user.role,
    organisation: user.organisation,
    createdAt: user.created_at,
    lastLoginAt: nowIso(),
  };
  setSessionCookie(res, signSession(publicUser));
  audit({ userId: user.id, action: 'auth.login', entity: 'user', entityId: String(user.id) });
  res.json({ user: publicUser });
});

api.post('/auth/logout', (req: Request, res: Response) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

api.get('/auth/me', optionalAuth, (req: Request, res: Response) => {
  res.json({ user: req.user ?? null });
});

const profileSchema = z.object({
  displayName: z.string().trim().min(2).max(80).optional(),
  organisation: z.string().trim().max(120).nullable().optional(),
});

api.patch('/auth/me', requireAuth, (req: Request, res: Response) => {
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) throw new HttpError(400, 'invalid_request', 'Profile update is not valid.');
  const updated = updateProfile(req.user!.id, parsed.data);
  if (!updated) throw new HttpError(404, 'not_found', 'User not found.');
  res.json({ user: updated });
});

const passwordSchema = z.object({
  currentPassword: z.string().min(1).max(200),
  newPassword: z
    .string()
    .min(12, 'Use at least 12 characters.')
    .max(200)
    .regex(/[a-z]/, 'Include a lowercase letter.')
    .regex(/[A-Z]/, 'Include an uppercase letter.')
    .regex(/[0-9]/, 'Include a digit.'),
});

api.post('/auth/password', requireAuth, rateLimit({ name: 'password', windowMs: 15 * 60 * 1000, max: 5, keyByUser: true }), (req: Request, res: Response) => {
  const parsed = passwordSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new HttpError(400, 'weak_password', parsed.error.issues[0]?.message ?? 'Password does not meet the policy.');
  }
  const ok = changePassword(req.user!.id, parsed.data.currentPassword, parsed.data.newPassword);
  if (!ok) throw new HttpError(401, 'invalid_credentials', 'Current password is incorrect.');
  audit({ userId: req.user!.id, action: 'auth.password_changed', entity: 'user', entityId: String(req.user!.id) });
  res.json({ ok: true });
});

// Everything below requires a session.
api.use('/dashboard', apiLimiter, requireAuth);
api.use('/investigations', apiLimiter, requireAuth);
api.use('/indicators', apiLimiter, requireAuth);
api.use('/knowledge', apiLimiter, requireAuth);
api.use('/reports', apiLimiter, requireAuth);
api.use('/settings', apiLimiter, requireAuth);
api.use('/iocs', apiLimiter, requireAuth);

// ===========================================================================
// PUBLIC (pre-auth) - demo catalogue + detection helper for the login screen
// ===========================================================================
api.get('/public/bootstrap', (req: Request, res: Response) => {
  res.json({
    appName: 'ThreatLens',
    version: '1.0.0',
    environment: config.env,
    registry: registrySnapshot(),
    demoCatalog: DEMO_CATALOG,
    iocTypes: IOC_TYPES.map((t) => ({ value: t, label: IOC_TYPE_LABEL[t] })),
  });
});

const detectSchema = z.object({ indicator: z.string().trim().min(1).max(2048) });

/** Live type-detection endpoint - powers the "detected: IPv4" hint in the UI. */
api.post('/iocs/detect', rateLimit({ name: 'detect', windowMs: 60 * 1000, max: 120, keyByUser: true }), (req: Request, res: Response) => {
  const parsed = detectSchema.safeParse(req.body);
  if (!parsed.success) throw new HttpError(400, 'invalid_request', 'Provide an `indicator` string.');
  const detection = detectIocType(parsed.data.indicator);
  const validation = validateIoc(parsed.data.indicator);
  res.json({
    detection: detection
      ? { type: detection.type, typeLabel: IOC_TYPE_LABEL[detection.type], value: detection.value, rule: detection.rule, defanged: detection.defanged, notes: detection.notes }
      : null,
    valid: validation.ok,
    error: validation.ok ? null : validation.error,
    warnings: validation.ok ? validation.warnings : [],
    isDocumentationExample:
      validation.ok && (validation.ioc.type === 'ipv4'
        ? isDocumentationIpv4(validation.ioc.value)
        : validation.ioc.type === 'ipv6'
          ? isDocumentationIpv6(validation.ioc.value)
          : false),
  });
});

// ===========================================================================
// DASHBOARD
// ===========================================================================
api.get('/dashboard', (_req: Request, res: Response) => {
  const stats = investigationStats();
  res.json({
    stats: {
      totalIocsInvestigated: stats.total,
      uniqueIndicators: q.get<{ n: number }>('SELECT COUNT(DISTINCT ioc_id) AS n FROM investigations')?.n ?? 0,
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      clean: stats.clean ?? 0,
      critical: stats.critical ?? 0,
      high: stats.high ?? 0,
      thisWeek: stats.thisWeek ?? 0,
      completed: stats.completed ?? 0,
      partial: stats.partial ?? 0,
      failed: stats.failed ?? 0,
      pending: stats.pending ?? 0,
      averageRisk: analytics.averageRisk(),
    },
    charts: {
      iocTypes: analytics.iocTypeDistribution(),
      riskDistribution: analytics.riskDistribution(),
      verdicts: analytics.verdictDistribution(),
      timeline: analytics.investigationsOverTime(14),
      categories: analytics.threatCategories(10),
      countries: analytics.topCountries(8),
      asns: analytics.topAsns(6),
      malware: analytics.topMalware(8),
      providers: analytics.providerUsage(),
    },
    techniques: techniqueUsage().slice(0, 10),
    mostInvestigated: analytics.mostInvestigated(8),
    recent: listInvestigations({ limit: 8, sort: 'newest' }).items,
    mode: registrySnapshot(),
  });
});

// ===========================================================================
// INVESTIGATIONS
// ===========================================================================
const startSchema = z.object({
  indicator: z.string().trim().min(1).max(2048),
  mode: z.enum(['live', 'demo']).optional(),
});

api.post('/investigations', async (req: Request, res: Response, next) => {
  try {
  const parsed = startSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new HttpError(400, 'invalid_request', 'Provide an `indicator` string of at most 2048 characters.');
  }
  const outcome = await startInvestigation({
    indicator: parsed.data.indicator,
    userId: req.user!.id,
    forceMode: parsed.data.mode,
  });
  if (!outcome.ok) {
    throw new HttpError(400, outcome.error.code, outcome.error.message, outcome.error.hint);
  }
  res.status(202).json({
    investigationId: outcome.investigation.id,
    reference: outcome.investigation.reference,
    status: outcome.investigation.status,
    mode: outcome.mode,
    ioc: {
      id: outcome.ioc.id,
      value: outcome.ioc.value,
      type: outcome.ioc.type,
      typeLabel: IOC_TYPE_LABEL[outcome.ioc.type],
    },
    warnings: outcome.warnings,
  });
  } catch (err) {
    next(err);
  }
});

api.get('/investigations', (req: Request, res: Response) => {
  const query = req.query as Record<string, string | string[] | undefined>;
  const one = (key: string): string | undefined => {
    const v = query[key];
    return Array.isArray(v) ? v[0] : v;
  };
  const list = (key: string): string[] => {
    const v = query[key];
    if (!v) return [];
    const raw = Array.isArray(v) ? v : String(v).split(',');
    return raw.map((s) => s.trim()).filter(Boolean);
  };

  const types = list('type').filter((t): t is (typeof IOC_TYPES)[number] => (IOC_TYPES as string[]).includes(t));
  const levels = list('level').filter((l) => ['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(l));
  const statuses = list('status').filter((s) => ['pending', 'enriching', 'analyzing', 'completed', 'partial', 'failed'].includes(s));
  const modes = list('mode').filter((m) => m === 'live' || m === 'demo');
  const sort = one('sort');
  const limit = Math.min(200, Math.max(1, Number.parseInt(one('limit') ?? '50', 10) || 50));
  const offset = Math.max(0, Number.parseInt(one('offset') ?? '0', 10) || 0);

  const result = listInvestigations({
    search: one('search'),
    types,
    levels: levels as never[],
    statuses: statuses as never[],
    modes: modes as Array<'live' | 'demo'>,
    from: one('from'),
    to: one('to'),
    sort: (['newest', 'oldest', 'risk_desc', 'risk_asc', 'ioc_asc'].includes(sort ?? '') ? sort : 'newest') as never,
    limit,
    offset,
  });
  res.json(result);
});

const idParam = (req: Request): number => {
  const id = Number.parseInt(String(req.params.id), 10);
  if (!Number.isFinite(id) || id <= 0) throw new HttpError(400, 'invalid_id', 'Investigation id must be a positive integer.');
  return id;
};

api.get('/investigations/:id/progress', (req: Request, res: Response) => {
  const id = idParam(req);
  const row = findInvestigation(id);
  if (!row) throw new HttpError(404, 'not_found', 'Investigation not found.');
  const events = timelineFor(id);
  res.json({
    id,
    reference: row.reference,
    status: row.status,
    riskScore: row.risk_score,
    riskLevel: row.risk_level,
    progress: {
      completed: events.filter((e) => ['validation', 'provider', 'provider-error', 'correlation', 'scoring', 'attack'].includes(e.kind)).length,
      lastEventAt: events.length ? events[events.length - 1].at : null,
    },
    timeline: events.map((e) => ({ seq: e.seq, at: e.at, kind: e.kind, title: e.title, description: e.description, source: e.source })),
  });
});

api.get('/investigations/:id', (req: Request, res: Response) => {
  const detail = buildInvestigationDetail(idParam(req));
  if (!detail) throw new HttpError(404, 'not_found', 'Investigation not found.');
  res.json(detail);
});

api.delete('/investigations/:id', (req: Request, res: Response) => {
  const id = idParam(req);
  const deleted = deleteInvestigation(id);
  if (!deleted) throw new HttpError(404, 'not_found', 'Investigation not found.');
  audit({ userId: req.user!.id, action: 'investigation.delete', entity: 'investigation', entityId: String(id) });
  res.json({ ok: true, deleted: id });
});

const notesSchema = z.object({
  notes: z.string().max(8000).nullable().optional(),
  assessment: z.string().max(8000).nullable().optional(),
  rating: z.enum(['true-positive', 'false-positive', 'suspicious', 'benign', 'unclassified']).nullable().optional(),
});

api.patch('/investigations/:id/analyst-notes', (req: Request, res: Response) => {
  const id = idParam(req);
  const parsed = notesSchema.safeParse(req.body);
  if (!parsed.success) throw new HttpError(400, 'invalid_request', 'Analyst note fields are not valid.');
  if (!findInvestigation(id)) throw new HttpError(404, 'not_found', 'Investigation not found.');
  updateInvestigation(id, {
    analyst_notes: parsed.data.notes ?? null,
    analyst_assessment: parsed.data.assessment ?? null,
    analyst_rating: parsed.data.rating ?? null,
  });
  audit({ userId: req.user!.id, action: 'investigation.annotate', entity: 'investigation', entityId: String(id) });
  res.json({ ok: true });
});

api.post('/investigations/:id/reanalyse', async (req: Request, res: Response, next) => {
  try {
  const id = idParam(req);
  const row = findInvestigation(id);
  if (!row) throw new HttpError(404, 'not_found', 'Investigation not found.');
  const ioc = q.get<{ value: string }>('SELECT value FROM iocs WHERE id = ?', [row.ioc_id]);
  if (!ioc) throw new HttpError(404, 'not_found', 'Indicator not found.');
  const outcome = await startInvestigation({ indicator: ioc.value, userId: req.user!.id });
  if (!outcome.ok) throw new HttpError(400, outcome.error.code, outcome.error.message, outcome.error.hint);
  res.status(202).json({ investigationId: outcome.investigation.id, reference: outcome.investigation.reference, status: outcome.investigation.status });
  } catch (err) {
    next(err);
  }
});

// ===========================================================================
// INDICATORS (indicator library + correlation memory)
// ===========================================================================
api.get('/iocs', (req: Request, res: Response) => {
  const query = req.query as Record<string, string | undefined>;
  const limit = Math.min(500, Math.max(1, Number.parseInt(query.limit ?? '100', 10) || 100));
  const offset = Math.max(0, Number.parseInt(query.offset ?? '0', 10) || 0);
  res.json({ total: countIocs(), items: listIocs(limit, offset), limit, offset });
});

const iocNotesSchema = z.object({ notes: z.string().max(4000) });

api.patch('/iocs/:id/notes', (req: Request, res: Response) => {
  const id = Number.parseInt(String(req.params.id), 10);
  if (!Number.isFinite(id)) throw new HttpError(400, 'invalid_id', 'Invalid indicator id.');
  const parsed = iocNotesSchema.safeParse(req.body);
  if (!parsed.success) throw new HttpError(400, 'invalid_request', 'Notes must be a string of at most 4000 characters.');
  setIocNotes(id, parsed.data.notes);
  res.json({ ok: true });
});

api.get('/iocs/:id/relationships', (req: Request, res: Response) => {
  const id = Number.parseInt(String(req.params.id), 10);
  if (!Number.isFinite(id)) throw new HttpError(400, 'invalid_id', 'Invalid indicator id.');
  const rows = relationshipsForIoc(id);
  res.json({
    items: rows.map((r) => ({
      otherIocId: r.other_id,
      otherValue: r.other_value,
      otherType: r.other_type,
      relation: r.relation,
      confidence: r.confidence,
      sourceProvider: r.source_provider,
      observations: r.observation_count,
      firstObserved: r.first_observed_at,
      lastObserved: r.last_observed_at,
      sourceInvestigationId: r.inv_id,
    })),
  });
});

// ===========================================================================
// KNOWLEDGE (ATT&CK, actors, malware, campaigns)
// ===========================================================================
api.get('/knowledge/mitre', (req: Request, res: Response) => {
  const usage = new Map(techniqueUsage().map((t) => [t.external_id, t]));
  res.json({
    version: ATTACK_VERSION,
    techniques: listTechniques().map((t) => ({
      id: t.external_id,
      name: t.name,
      tactic: t.tactic,
      tactics: JSON.parse(t.tactics_json) as string[],
      description: t.description,
      platforms: JSON.parse(t.platforms_json) as string[],
      dataSources: JSON.parse(t.data_sources_json) as string[],
      isSubtechnique: Boolean(t.is_subtechnique),
      parentId: t.parent_external_id,
      reference: t.reference_url,
      investigationCount: usage.get(t.external_id)?.count ?? 0,
      lastObserved: usage.get(t.external_id)?.last_seen ?? null,
    })),
    total: countTechniques(),
  });
});

api.get('/knowledge/actors', (_req: Request, res: Response) => {
  res.json({
    actors: listActors().map((a) => ({
      id: a.external_id,
      name: a.name,
      aliases: JSON.parse(a.aliases_json) as string[],
      origin: a.origin,
      sophistication: a.sophistication,
      motivation: JSON.parse(a.motivation_json) as string[],
      firstSeenYear: a.first_seen_year,
      description: a.description,
      investigationCount: a.investigation_count,
      indicatorCount: a.indicator_count,
      malwareCount: a.malware_count,
      campaignCount: a.campaign_count,
      lastSeen: a.last_seen,
    })),
  });
});

api.get('/knowledge/malware', (_req: Request, res: Response) => {
  res.json({
    malware: listMalware().map((m) => ({
      id: m.external_id,
      name: m.name,
      aliases: JSON.parse(m.aliases_json) as string[],
      type: m.malware_type,
      platforms: JSON.parse(m.platform_json) as string[],
      capabilities: JSON.parse(m.capabilities_json) as string[],
      origin: m.origin,
      description: m.description,
      investigationCount: m.investigation_count,
      actorCount: m.actor_count,
      lastSeen: m.last_seen,
    })),
  });
});

api.get('/knowledge/campaigns', (_req: Request, res: Response) => {
  res.json({
    campaigns: listCampaigns().map((c) => ({
      id: c.external_id,
      name: c.name,
      origin: c.origin,
      firstSeen: c.first_seen,
      description: c.description,
      investigationCount: c.investigation_count,
      lastSeen: c.last_seen,
    })),
  });
});

// ===========================================================================
// REPORTS
// ===========================================================================
const reportFor = (id: number) => {
  const detail = buildInvestigationDetail(id);
  if (!detail) throw new HttpError(404, 'not_found', 'Investigation not found - cannot generate a report.');
  return detail;
};

api.get('/reports', (req: Request, res: Response) => {
  const { items } = listInvestigations({ limit: 200, sort: 'newest' });
  const reports = q.all<{ id: number; investigation_id: number; title: string; classification: string; generated_at: string; format: string; byte_size: number | null }>(
    'SELECT id, investigation_id, title, classification, generated_at, format, byte_size FROM reports ORDER BY id DESC LIMIT 200',
  );
  res.json({
    investigations: items.map((i) => ({
      id: i.id,
      reference: i.reference,
      ioc: i.iocValue,
      iocType: i.iocTypeLabel,
      riskScore: i.riskScore,
      riskLevel: i.riskLevel,
      status: i.status,
      mode: i.mode,
      createdAt: i.createdAt,
    })),
    generated: reports,
  });
});

/**
 * Persist a record of every generated report so the Reports page can show what
 * was produced, when, and by whom (auditability requirement).
 */
const saveReport = (input: {
  investigationId: number;
  title: string;
  format: 'json' | 'pdf' | 'markdown';
  byteSize: number;
  userId: number;
}): void => {
  q.run(
    'INSERT INTO reports (investigation_id, title, classification, generated_by, generated_at, format, byte_size) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [input.investigationId, input.title.slice(0, 200), 'TLP:AMBER', input.userId, nowIso(), input.format, input.byteSize],
  );
};

api.get('/reports/:id', (req: Request, res: Response) => {
  const id = idParam(req);
  const detail = reportFor(id);
  const report = buildReport(detail, detail.requestedBy?.name ?? req.user!.displayName);
  res.json(report);
});

api.get('/reports/:id/export.:format', async (req: Request, res: Response, next) => {
  const id = idParam(req);
  const format = String(req.params.format).toLowerCase();
  if (!['json', 'md', 'markdown', 'pdf'].includes(format)) {
    throw new HttpError(400, 'unsupported_format', 'Supported export formats are json, md and pdf.');
  }
  try {
    const detail = reportFor(id);
    const report = buildReport(detail, detail.requestedBy?.name ?? req.user!.displayName);
    const userId = req.user!.id;

    if (format === 'json') {
      const buffer = Buffer.from(JSON.stringify(report, null, 2), 'utf8');
      saveReport({ investigationId: id, title: report.title, format: 'json', byteSize: buffer.length, userId });
      audit({ userId: req.user!.id, action: 'report.export', entity: 'investigation', entityId: String(id), meta: { format: 'json' } });
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="threatlens-${detail.reference}.json"`);
      res.send(buffer);
      return;
    }

    if (format === 'md' || format === 'markdown') {
      const buffer = Buffer.from(reportToMarkdown(report), 'utf8');
      saveReport({ investigationId: id, title: report.title, format: 'markdown', byteSize: buffer.length, userId });
      audit({ userId: req.user!.id, action: 'report.export', entity: 'investigation', entityId: String(id), meta: { format: 'markdown' } });
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="threatlens-${detail.reference}.md"`);
      res.send(buffer);
      return;
    }

    const buffer = await renderReportPdf(report);
    saveReport({ investigationId: id, title: report.title, format: 'pdf', byteSize: buffer.length, userId });
    audit({ userId: req.user!.id, action: 'report.export', entity: 'investigation', entityId: String(id), meta: { format: 'pdf' } });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="threatlens-${detail.reference}.pdf"`);
    res.setHeader('Content-Length', String(buffer.length));
    res.end(buffer);
  } catch (err) {
    next(err);
  }
});

// ===========================================================================
// SETTINGS
// ===========================================================================
api.get('/settings', (req: Request, res: Response) => {
  const snapshot = registrySnapshot();
  res.json({
    registry: snapshot,
    modeOverride: getModeOverride(),
    environment: {
      nodeEnv: config.env,
      port: config.port,
      database: config.databasePath.replace(process.cwd(), '.'),
      providerMinIntervalMs: config.providerMinIntervalMs,
      providerTimeoutMs: config.providerTimeoutMs,
      showDemoBadge: config.showDemoBadge,
    },
    riskMethodology: METHODOLOGY,
    // Which environment variables exist and whether they are populated - the
    // VALUES are never returned, only the boolean.
    apiKeys: {
      VIRUSTOTAL_API_KEY: Boolean(config.providerKeys.virustotal),
      ABUSEIPDB_API_KEY: Boolean(config.providerKeys.abuseipdb),
      OTX_API_KEY: Boolean(config.providerKeys.otx),
      URLHAUS_ENABLED: Boolean(config.providerKeys.urlhaus),
      GREYNOISE_API_KEY: Boolean(config.providerKeys.greynoise),
      SHODAN_API_KEY: Boolean(config.providerKeys.shodan),
    },
    analyst: {
      id: req.user!.id,
      email: req.user!.email,
      displayName: req.user!.displayName,
      role: req.user!.role,
      lastLoginAt: req.user!.lastLoginAt,
    },
    totals: {
      users: countUsers(),
      investigations: investigationStats().total ?? 0,
    },
    audit: recentAudit(15),
  });
});

const modeSchema = z.object({ mode: z.enum(['live', 'demo', 'auto']) });

api.post('/settings/mode', (req: Request, res: Response) => {
  const parsed = modeSchema.safeParse(req.body);
  if (!parsed.success) throw new HttpError(400, 'invalid_request', 'mode must be live, demo or auto.');
  const next = parsed.data.mode === 'auto' ? null : parsed.data.mode;
  setModeOverride(next);
  audit({ userId: req.user!.id, action: 'settings.mode', entity: 'settings', entityId: 'intelligence_mode', meta: { mode: parsed.data.mode } });
  res.json({ mode: resolveMode(), override: getModeOverride(), registry: registrySnapshot() });
});

api.post('/settings/seed-demo-users', (req: Request, res: Response) => {
  // Explicit, idempotent bootstrap used by the setup guide. Creates the demo
  // analyst only if the users table is empty.
  if (countUsers() > 0) throw new HttpError(409, 'already_seeded', 'Users already exist in this database.');
  const user = createUser({
    email: config.seedAnalyst.email,
    password: config.seedAnalyst.password,
    displayName: config.seedAnalyst.name,
    role: 'analyst',
  });
  res.status(201).json({ user });
});

api.get('/health', (_req: Request, res: Response) => {
  let dbOk = true;
  try {
    getDb().prepare('SELECT 1').get();
  } catch {
    dbOk = false;
  }
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? 'ok' : 'degraded',
    database: dbOk,
    mode: resolveMode(),
    uptimeSeconds: Math.round(process.uptime()),
  });
});

export { reconcileStaleInvestigations };
