/**
 * API hardening middleware: rate limiting, security headers, request id and a
 * single error shape.
 *
 * ThreatLens is a single-tenant capstone deployment, so the rate limiter is an
 * in-memory fixed-window counter keyed by client IP + route class. It is
 * intentionally dependency-free; a production deployment would move this to
 * Redis so limits are shared across instances.
 */
import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { logger } from '../config/logger.js';
import { config } from '../config/env.js';

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  name: string;
  /** Requests from the same authenticated user are counted separately. */
  keyByUser?: boolean;
}

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

const clientIp = (req: Request): string => {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) return forwarded.split(',')[0].trim();
  return req.ip ?? req.socket.remoteAddress ?? 'unknown';
};

export function rateLimit(options: RateLimitOptions) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const identity = options.keyByUser && req.user ? `u:${req.user.id}` : `ip:${clientIp(req)}`;
    const key = `${options.name}:${identity}`;
    const now = Date.now();
    const bucket = buckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + options.windowMs });
      next();
      return;
    }
    bucket.count += 1;
    if (bucket.count > options.max) {
      const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({
        error: {
          code: 'rate_limited',
          message: `Too many requests. The ${options.name} limit is ${options.max} requests per ${Math.round(options.windowMs / 1000)}s. Retry in ${retryAfter}s.`,
          retryAfterSeconds: retryAfter,
        },
      });
      return;
    }
    next();
  };
}

/** Periodic cleanup so the bucket map cannot grow without bound. */
export function startRateLimitJanitor(intervalMs = 5 * 60 * 1000): NodeJS.Timeout {
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key);
    }
  }, intervalMs);
  timer.unref();
  return timer;
}

/**
 * Security headers.
 *
 * The CSP allows `'unsafe-inline'` for styles only, because Recharts and PDF
 * preview surfaces inject inline style attributes. Scripts are restricted to
 * same-origin, so no third-party code and no inline script can run.
 */
export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "object-src 'none'",
    ].join('; '),
  );
  if (config.env === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

/** Attach a correlation id to every response and log. */
export function requestId(req: Request, res: Response, next: NextFunction): void {
  const incoming = req.headers['x-request-id'];
  const id = typeof incoming === 'string' && incoming.length <= 64 ? incoming : randomUUID();
  res.setHeader('X-Request-Id', id);
  const started = Date.now();
  res.on('finish', () => {
    logger.info('http', {
      id,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - started,
    });
  });
  next();
}

/** CORS limited to the configured client origins (the Vite dev server). */
export function cors(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;
  const allowed = config.allowedOrigins;
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Request-Id');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly hint?: string,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export const notFound = (_req: Request, res: Response): void => {
  res.status(404).json({ error: { code: 'not_found', message: 'The requested API endpoint does not exist.' } });
};

/** Central error handler - never leaks a stack trace to the client. */
export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message, hint: err.hint } });
    return;
  }
  if (err instanceof Error) {
    logger.error('unhandled error', { message: err.message, stack: err.stack?.split('\n').slice(0, 4).join(' | ') });
    res.status(500).json({
      error: {
        code: 'internal_error',
        message: 'The server could not complete the request. The failure has been logged with a request id.',
      },
    });
    return;
  }
  logger.error('unhandled non-error throwable');
  res.status(500).json({ error: { code: 'internal_error', message: 'Unexpected server error.' } });
}
