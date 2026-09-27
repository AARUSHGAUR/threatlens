/**
 * Environment configuration loader.
 *
 * DESIGN DECISION (viva talking point):
 * Every secret is read from `process.env` (populated from a git-ignored `.env`
 * file). Provider modules receive a *typed credential map* instead of reading
 * `process.env` themselves, which makes it trivially testable (a test can
 * inject a fake config object) and guarantees that no key can leak into a log
 * line by accident.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

// ESM has no __dirname; derive it from import.meta.url.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');

/** Walk up from `server/src/config` to the repository root. */
function findRepoRoot(start: string): string {
  let dir = start;
  for (let i = 0; i < 6; i += 1) {
    if (fs.existsSync(path.join(dir, 'package.json')) && fs.existsSync(path.join(dir, '.env.example'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return start;
}

export const ROOT_DIR = findRepoRoot(REPO_ROOT);

// Load `.env` from the repository root (and from server/ as a fallback).
dotenv.config({ path: path.join(ROOT_DIR, '.env') });
dotenv.config({ path: path.join(ROOT_DIR, 'server', '.env') });

const str = (key: string, fallback = ''): string => {
  const v = process.env[key];
  return v === undefined || v === null ? fallback : String(v).trim();
};

const bool = (key: string, fallback: boolean): boolean => {
  const v = str(key).toLowerCase();
  if (v === '') return fallback;
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
};

const int = (key: string, fallback: number): number => {
  const v = Number.parseInt(str(key), 10);
  return Number.isFinite(v) ? v : fallback;
};

export type IntelligenceMode = 'auto' | 'live' | 'demo';

const modeRaw = str('INTELLIGENCE_MODE', 'auto').toLowerCase();
export const INTELLIGENCE_MODE: IntelligenceMode = (
  ['auto', 'live', 'demo'].includes(modeRaw) ? modeRaw : 'auto'
) as IntelligenceMode;

const resolveDbPath = (): string => {
  const configured = str('DATABASE_PATH', 'data/threatlens.sqlite');
  return path.isAbsolute(configured) ? configured : path.join(ROOT_DIR, configured);
};

export interface ProviderKeys {
  virustotal: string;
  abuseipdb: string;
  otx: string;
  urlhaus: string; // 'enabled' sentinel, no secret
  greynoise: string;
  shodan: string;
}

export interface AppConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  clientOrigin: string;
  allowedOrigins: string[];
  databasePath: string;
  jwtSecret: string;
  jwtExpiresIn: string;
  seedAnalyst: { email: string; password: string; name: string };
  intelligenceMode: IntelligenceMode;
  showDemoBadge: boolean;
  providerKeys: ProviderKeys;
  providerMinIntervalMs: number;
  providerTimeoutMs: number;
  misp: { url: string; apiKey: string };
  stixBundlePath: string;
  /** True when at least one credential-requiring provider is configured. */
  hasAnyLiveKey: boolean;
  /** Keyless providers (URLhaus) that can still enrich in LIVE mode. */
  hasKeylessLiveProvider: boolean;
}

function buildConfig(): AppConfig {
  const providerKeys: ProviderKeys = {
    virustotal: str('VIRUSTOTAL_API_KEY'),
    abuseipdb: str('ABUSEIPDB_API_KEY'),
    otx: str('OTX_API_KEY'),
    // URLhaus is an open API; the flag only toggles whether we call it.
    urlhaus: bool('URLHAUS_ENABLED', true) ? 'enabled' : '',
    greynoise: str('GREYNOISE_API_KEY'),
    shodan: str('SHODAN_API_KEY'),
  };

  // `auto` mode resolves to LIVE only when a provider that REQUIRES a
  // credential is present. URLhaus is keyless, so counting it here would make a
  // zero-configuration install resolve to LIVE and immediately hit the network -
  // which contradicts the project requirement that ThreatLens works without any
  // API keys (Demo Mode).
  const hasAnyLiveKey = Boolean(
    providerKeys.virustotal ||
      providerKeys.abuseipdb ||
      providerKeys.otx ||
      providerKeys.greynoise ||
      providerKeys.shodan,
  );

  const nodeEnv = str('NODE_ENV', 'development');

  let jwtSecret = str('JWT_SECRET');
  if (!jwtSecret || jwtSecret.length < 16) {
    // Development fallback keeps `npm run dev` working with zero configuration.
    // In production we refuse to boot with a weak secret (fail closed).
    if (nodeEnv === 'production') {
      throw new Error(
        'JWT_SECRET is missing or too short. Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"',
      );
    }
    jwtSecret = 'threatlens-development-only-insecure-secret';
  }

  return {
    env: nodeEnv === 'production' ? 'production' : nodeEnv === 'test' ? 'test' : 'development',
    port: int('PORT', 4000),
    clientOrigin: str('CLIENT_ORIGIN', 'http://localhost:5173'),
    allowedOrigins: str('ALLOWED_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    databasePath: resolveDbPath(),
    jwtSecret,
    jwtExpiresIn: str('JWT_EXPIRES_IN', '8h'),
    seedAnalyst: {
      email: str('SEED_ANALYST_EMAIL', 'analyst@threatlens.local'),
      password: str('SEED_ANALYST_PASSWORD', 'ThreatLens!2024'),
      name: str('SEED_ANALYST_NAME', 'Demo Analyst'),
    },
    intelligenceMode: INTELLIGENCE_MODE,
    showDemoBadge: bool('SHOW_DEMO_BADGE', true),
    providerKeys,
    providerMinIntervalMs: int('PROVIDER_MIN_INTERVAL_MS', 1500),
    providerTimeoutMs: int('PROVIDER_TIMEOUT_MS', 12000),
    misp: { url: str('MISP_URL'), apiKey: str('MISP_API_KEY') },
    stixBundlePath: str('STIX_BUNDLE_PATH'),
    hasAnyLiveKey,
    hasKeylessLiveProvider: Boolean(providerKeys.urlhaus),
  };
}

export const config: AppConfig = buildConfig();
