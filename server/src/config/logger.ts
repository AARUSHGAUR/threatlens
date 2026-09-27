/**
 * Tiny structured logger.
 *
 * Redaction: any key that looks like a credential is replaced with `***`, so a
 * careless `logger.info({ headers })` can never leak an API key into a log file
 * that might be shared for the capstone submission.
 */
type Level = 'debug' | 'info' | 'warn' | 'error';

const SECRET_PATTERN = /(api[-_]?key|authorization|cookie|password|secret|token|x-api-key)/i;

function redact(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[deep]';
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redact(v, depth + 1));
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_PATTERN.test(k) ? '***' : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

const LEVEL_ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN_LEVEL: Level = (process.env.LOG_LEVEL as Level) || 'info';

function emit(level: Level, message: string, meta?: unknown): void {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[MIN_LEVEL]) return;
  const line = {
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...(meta !== undefined ? { meta: redact(meta) } : {}),
  };
  const out = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  out.write(`${JSON.stringify(line)}\n`);
}

export const logger = {
  debug: (m: string, meta?: unknown) => emit('debug', m, meta),
  info: (m: string, meta?: unknown) => emit('info', m, meta),
  warn: (m: string, meta?: unknown) => emit('warn', m, meta),
  error: (m: string, meta?: unknown) => emit('error', m, meta),
};
