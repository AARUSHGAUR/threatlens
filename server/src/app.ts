/**
 * Express application assembly.
 *
 * In production the compiled SPA is served from the same origin as the API,
 * which keeps the session cookie first-party and means `npm run build &&
 * npm start` gives a single-URL deployment for the demo.
 */
import path from 'node:path';
import fs from 'node:fs';
import express, { type Express } from 'express';
import { config, ROOT_DIR } from './config/env.js';
import { logger } from './config/logger.js';
import { api } from './routes/api.js';
import { cors, errorHandler, notFound, requestId, securityHeaders } from './middleware/hardening.js';

export function createApp(): Express {
  const app = express();

  // The API is mounted at /api, so `trust proxy` affects req.ip used by the
  // rate limiter. We do NOT enable it by default: trusting X-Forwarded-For
  // blindly would let a client spoof its IP and bypass the limiter.
  app.set('trust proxy', false);
  app.disable('x-powered-by');
  app.set('etag', false);

  app.use(requestId);
  app.use(securityHeaders);
  app.use(cors);
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false, limit: '64kb' }));

  // Cookie parsing is intentionally minimal and dependency-free.
  app.use((req, _res, next) => {
    const header = req.headers.cookie;
    const cookies: Record<string, string> = {};
    if (header) {
      for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx <= 0) continue;
        const key = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        if (!key) continue;
        try {
          cookies[key] = decodeURIComponent(value);
        } catch {
          cookies[key] = value;
        }
      }
    }
    (req as express.Request & { cookies: Record<string, string> }).cookies = cookies;
    next();
  });

  app.use('/api', api);
  app.use('/api', notFound);

  // ---- static SPA (production single-origin deployment) -------------------
  const clientDist = path.join(ROOT_DIR, 'web', 'dist');
  if (fs.existsSync(path.join(clientDist, 'index.html'))) {
    app.use(
      express.static(clientDist, {
        index: false,
        maxAge: config.env === 'production' ? '1h' : 0,
        setHeaders: (res, filePath) => {
          if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
        },
      }),
    );
    // SPA fallback for client-side routes (/investigation/12 etc.)
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) return next();
      res.sendFile(path.join(clientDist, 'index.html'));
    });
  } else {
    app.get('/', (_req, res) => {
      res.type('text/plain').send(
        [
          'ThreatLens API is running.',
          '',
          'The web client has not been built yet. Run one of:',
          '  npm run dev            (API + Vite dev server on :5173)',
          '  npm run build && npm start   (single-origin deployment on this port)',
        ].join('\n'),
      );
    });
  }

  app.use(errorHandler);
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    errorHandler(err, _req, res, _next);
  });

  logger.info('express app initialised', { env: config.env, mode: config.intelligenceMode });
  return app;
}
