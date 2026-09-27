/**
 * Server entry point.
 *
 * Boot sequence:
 *   1. initialise the database (schema is idempotent)
 *   2. seed the ATT&CK knowledge base and the demo analyst if needed
 *   3. reconcile investigations that were interrupted by a restart
 *   4. start the HTTP listener
 */
import { createApp } from './app.js';
import { config } from './config/env.js';
import { logger } from './config/logger.js';
import { closeDb, getDb } from './db/index.js';
import { seedTechniques } from './repositories/knowledge.js';
import { countUsers, createUser } from './repositories/users.js';
import { reconcileStaleInvestigations } from './services/investigationService.js';
import { startRateLimitJanitor } from './middleware/hardening.js';
import { registrySnapshot } from './providers/registry.js';

function bootstrap(): void {
  getDb();

  const techniques = seedTechniques();
  if (techniques > 0) logger.info('seeded MITRE ATT&CK knowledge base', { entries: techniques });

  if (countUsers() === 0) {
    const user = createUser({
      email: config.seedAnalyst.email,
      password: config.seedAnalyst.password,
      displayName: config.seedAnalyst.name,
      role: 'analyst',
    });
    logger.info('seeded demo analyst account', { email: user.email });
    console.log('');
    console.log('  ┌──────────────────────────────────────────────────────────────┐');
    console.log('  │  ThreatLens demo analyst account created                      │');
    console.log(`  │  email:    ${user.email.padEnd(52)}│`);
    console.log(`  │  password: ${config.seedAnalyst.password.padEnd(52)}│`);
    console.log('  │  (change it in Settings after signing in)                     │');
    console.log('  └──────────────────────────────────────────────────────────────┘');
    console.log('');
  }

  const stale = reconcileStaleInvestigations();
  if (stale > 0) logger.warn('marked interrupted investigations as failed', { count: stale });
}

const app = createApp();

bootstrap();
startRateLimitJanitor();

const server = app.listen(config.port, () => {
  const snapshot = registrySnapshot();
  logger.info('threatlens api listening', { port: config.port, env: config.env });
  console.log('');
  console.log('  ThreatLens - Cyber Threat Intelligence & IOC Investigation Platform');
  console.log(`  API      : http://localhost:${config.port}/api`);
  console.log(`  Health   : http://localhost:${config.port}/api/health`);
  console.log(`  Mode     : ${snapshot.modeLabel}${snapshot.hasLiveKeys ? '' : '  (no API keys configured)'}`);
  if (snapshot.mode === 'demo') {
    console.log('            All intelligence is SIMULATED and labelled DEMO DATA.');
  }
  console.log(`  Database : ${config.databasePath}`);
  console.log('');
});

const shutdown = (signal: string): void => {
  logger.info('shutting down', { signal });
  server.close(() => {
    closeDb();
    process.exit(0);
  });
  // Force exit if connections linger.
  setTimeout(() => process.exit(0), 4000).unref();
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (reason) => logger.error('unhandled rejection', { reason: String(reason) }));
process.on('uncaughtException', (err) => {
  logger.error('uncaught exception', { message: err.message, stack: err.stack });
});
