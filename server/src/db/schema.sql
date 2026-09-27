-- ============================================================================
-- ThreatLens - relational schema (SQLite / better-sqlite3)
--
-- DESIGN NOTES (for the viva)
--  * Timestamps are stored as ISO-8601 UTC strings. In SQLite an ISO-8601
--    string sorts lexicographically in the same order as chronologically, so
--    `ORDER BY created_at` is a real time sort without a date library.
--  * An indicator is normalised into `iocs` and referenced by every other
--    table. Re-investigating the same indicator therefore *updates* one row
--    (`times_seen`) instead of creating duplicates - this mirrors how a real
--    CTI platform keeps a single indicator "case file" with many enrichment
--    snapshots.
--  * Many-to-many relationships (investigation <-> technique / malware /
--    actor / campaign) use explicit junction tables instead of JSON blobs so
--    the graph queries stay relational.
--  * `enrichment_results` keeps one row *per provider per investigation*: the
--    raw intelligence snapshot is preserved forever, so an old report always
--    reflects what was known at the time, not what is known now.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------ Identity
CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  email          TEXT    NOT NULL UNIQUE,
  password_hash  TEXT    NOT NULL,
  display_name   TEXT    NOT NULL,
  role           TEXT    NOT NULL DEFAULT 'analyst'
                 CHECK (role IN ('analyst', 'senior_analyst', 'admin')),
  organisation   TEXT,
  created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_login_at  TEXT
);

-- ---------------------------------------------------------------- Indicators
CREATE TABLE IF NOT EXISTS iocs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  type            TEXT    NOT NULL
                  CHECK (type IN ('ipv4','ipv6','domain','url','md5','sha1','sha256','email')),
  value           TEXT    NOT NULL,
  -- value_hash allows an index lookup without a case/whitespace-sensitive compare
  value_hash      TEXT    NOT NULL,
  is_documentation INTEGER NOT NULL DEFAULT 0,
  is_private      INTEGER NOT NULL DEFAULT 0,
  times_seen      INTEGER NOT NULL DEFAULT 0,
  first_seen_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_seen_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  notes           TEXT,
  created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (type, value_hash)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value   ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type    ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_seen    ON iocs(last_seen_at DESC);

-- ------------------------------------------------------------ Investigations
CREATE TABLE IF NOT EXISTS investigations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  reference         TEXT    NOT NULL UNIQUE,      -- e.g. INV-2026-000042
  ioc_id            INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  requested_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  status            TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','enriching','analyzing','completed','partial','failed')),
  mode              TEXT    NOT NULL DEFAULT 'demo'
                    CHECK (mode IN ('live','demo')),
  risk_score        INTEGER CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)),
  risk_level        TEXT    CHECK (risk_level IS NULL OR risk_level IN ('CLEAN','LOW','MEDIUM','HIGH','CRITICAL')),
  confidence_score  INTEGER,
  verdict           TEXT    CHECK (verdict IS NULL OR verdict IN ('malicious','suspicious','clean','harmless','unknown')),
  providers_ok      INTEGER NOT NULL DEFAULT 0,
  providers_failed  INTEGER NOT NULL DEFAULT 0,
  providers_skipped INTEGER NOT NULL DEFAULT 0,
  duration_ms       INTEGER,
  error_code        TEXT,
  error_message     TEXT,
  analyst_notes     TEXT,
  analyst_assessment TEXT,
  analyst_rating    TEXT,
  started_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  completed_at      TEXT,
  created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_inv_ioc     ON investigations(ioc_id);
CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_risk    ON investigations(risk_level);
CREATE INDEX IF NOT EXISTS idx_inv_status  ON investigations(status);

-- --------------------------------------------------------- Enrichment store
CREATE TABLE IF NOT EXISTS enrichment_results (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id   INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  ioc_id             INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  provider_id        TEXT    NOT NULL,
  provider_name      TEXT    NOT NULL,
  origin             TEXT    NOT NULL CHECK (origin IN ('live','demo')),
  status             TEXT    NOT NULL CHECK (status IN ('ok','not_found','unconfigured','error','rate_limited','timeout')),
  verdict            TEXT    NOT NULL DEFAULT 'unknown'
                     CHECK (verdict IN ('malicious','suspicious','clean','harmless','unknown')),
  reputation_score   INTEGER,
  report_count       INTEGER,
  malicious_count    INTEGER,
  suspicious_count   INTEGER,
  harmless_count     INTEGER,
  unsupported_count  INTEGER,
  undetected_count   INTEGER,
  detection_ratio    REAL,
  country            TEXT,
  asn                TEXT,
  isp                TEXT,
  network_json       TEXT,                       -- full network intel snapshot (JSON)
  related_json       TEXT,                       -- related entities (JSON)
  first_seen_at      TEXT,
  last_seen_at       TEXT,
  raw_excerpt        TEXT,                       -- truncated upstream payload for audit
  error_code         TEXT,
  error_message      TEXT,
  duration_ms        INTEGER NOT NULL DEFAULT 0,
  created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_enr_inv      ON enrichment_results(investigation_id);
CREATE INDEX IF NOT EXISTS idx_enr_provider ON enrichment_results(provider_id);
CREATE INDEX IF NOT EXISTS idx_enr_verdict  ON enrichment_results(verdict);

-- --------------------------------------------------------- Risk explanation
CREATE TABLE IF NOT EXISTS risk_factors (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  seq              INTEGER NOT NULL,
  factor_id        TEXT    NOT NULL,
  label            TEXT    NOT NULL,
  points           INTEGER NOT NULL,
  category         TEXT    NOT NULL,
  evidence         TEXT    NOT NULL,
  sources_json     TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_rf_inv ON risk_factors(investigation_id, seq);

-- ------------------------------------------------------------ Threat intel
CREATE TABLE IF NOT EXISTS threat_actors (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id      TEXT    NOT NULL UNIQUE,
  name             TEXT    NOT NULL,
  aliases_json     TEXT    NOT NULL DEFAULT '[]',
  origin           TEXT    NOT NULL DEFAULT 'live' CHECK (origin IN ('live','demo','community')),
  sophistication   TEXT,
  motivation_json  TEXT    NOT NULL DEFAULT '[]',
  first_seen_year  INTEGER,
  description      TEXT,
  reference_url    TEXT,
  created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_actor_name ON threat_actors(name);

CREATE TABLE IF NOT EXISTS malware (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id      TEXT    NOT NULL UNIQUE,
  name             TEXT    NOT NULL,
  aliases_json     TEXT    NOT NULL DEFAULT '[]',
  malware_type     TEXT,                    -- e.g. RAT, stealer, loader
  platform_json    TEXT    NOT NULL DEFAULT '[]',
  capabilities_json TEXT   NOT NULL DEFAULT '[]',
  origin           TEXT    NOT NULL DEFAULT 'live' CHECK (origin IN ('live','demo','community')),
  description      TEXT,
  reference_url    TEXT,
  created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_malware_name ON malware(name);

CREATE TABLE IF NOT EXISTS campaigns (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id      TEXT    NOT NULL UNIQUE,
  name             TEXT    NOT NULL,
  origin           TEXT    NOT NULL DEFAULT 'live' CHECK (origin IN ('live','demo','community')),
  first_seen       TEXT,
  description      TEXT,
  reference_url    TEXT,
  created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- ---------------------------------------------------------- MITRE ATT&CK
CREATE TABLE IF NOT EXISTS mitre_techniques (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id        TEXT    NOT NULL UNIQUE,   -- e.g. T1059.001
  name               TEXT    NOT NULL,
  is_subtechnique    INTEGER NOT NULL DEFAULT 0,
  parent_external_id TEXT,
  tactic             TEXT    NOT NULL,          -- primary tactic for display
  tactics_json       TEXT    NOT NULL DEFAULT '[]', -- all tactics (ATT&CK is many-to-many)
  description        TEXT,
  platforms_json     TEXT    NOT NULL DEFAULT '[]',
  data_sources_json  TEXT    NOT NULL DEFAULT '[]',
  detection_json     TEXT    NOT NULL DEFAULT '[]',
  reference_url      TEXT    NOT NULL,
  attack_version     TEXT,
  created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_tech_tactic ON mitre_techniques(tactic);

-- ------------------------------------------- Investigation <-> intel junctions
CREATE TABLE IF NOT EXISTS investigation_techniques (
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  technique_id     INTEGER NOT NULL REFERENCES mitre_techniques(id) ON DELETE CASCADE,
  relationship     TEXT    NOT NULL,
  confidence       TEXT    NOT NULL CHECK (confidence IN ('high','medium','low')),
  mapping_basis    TEXT    NOT NULL CHECK (mapping_basis IN ('provider-signal','behavioural-rule','malware-family-intel')),
  rationale        TEXT    NOT NULL,
  sort_order       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (investigation_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_invtech_tech ON investigation_techniques(technique_id);

CREATE TABLE IF NOT EXISTS investigation_actors (
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  actor_id         INTEGER NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
  confidence       TEXT    NOT NULL CHECK (confidence IN ('high','medium','low')),
  basis            TEXT    NOT NULL,
  PRIMARY KEY (investigation_id, actor_id)
);

CREATE TABLE IF NOT EXISTS investigation_malware (
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  malware_id       INTEGER NOT NULL REFERENCES malware(id) ON DELETE CASCADE,
  confidence       TEXT    NOT NULL CHECK (confidence IN ('high','medium','low')),
  basis            TEXT    NOT NULL,
  detections       INTEGER,
  PRIMARY KEY (investigation_id, malware_id)
);

CREATE TABLE IF NOT EXISTS investigation_campaigns (
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  campaign_id      INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  confidence       TEXT    NOT NULL CHECK (confidence IN ('high','medium','low')),
  basis            TEXT    NOT NULL,
  PRIMARY KEY (investigation_id, campaign_id)
);

-- ------------------------------------------ Correlation between indicators
CREATE TABLE IF NOT EXISTS investigation_related_iocs (
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  related_ioc_id   INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  relation         TEXT    NOT NULL,   -- related_domain | related_ip | related_url | related_hash | related_email
  confidence       TEXT    NOT NULL CHECK (confidence IN ('high','medium','low')),
  source           TEXT    NOT NULL,   -- provider id
  PRIMARY KEY (investigation_id, related_ioc_id, relation)
);

-- Indicator <-> indicator relationships learned from intelligence feeds.
-- Self-referencing many-to-many; `direction` keeps the edge meaningful.
CREATE TABLE IF NOT EXISTS ioc_relationships (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  source_ioc_id      INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  target_ioc_id      INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  relation           TEXT    NOT NULL,
  direction          TEXT    NOT NULL DEFAULT 'directed'
                     CHECK (direction IN ('directed','undirected')),
  confidence         TEXT    NOT NULL CHECK (confidence IN ('high','medium','low')),
  source_provider    TEXT    NOT NULL,
  observation_count  INTEGER NOT NULL DEFAULT 1,
  first_observed_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_observed_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  meta_json          TEXT    NOT NULL DEFAULT '{}',
  UNIQUE (source_ioc_id, target_ioc_id, relation)
);
CREATE INDEX IF NOT EXISTS idx_rel_src ON ioc_relationships(source_ioc_id);
CREATE INDEX IF NOT EXISTS idx_rel_tgt ON ioc_relationships(target_ioc_id);

-- -------------------------------------------------------------- Timeline
CREATE TABLE IF NOT EXISTS investigation_timeline (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  seq              INTEGER NOT NULL,
  at               TEXT    NOT NULL,
  kind             TEXT    NOT NULL
                   CHECK (kind IN ('investigation','validation','provider','provider-error',
                                   'correlation','scoring','attack','report','note')),
  title            TEXT    NOT NULL,
  description      TEXT    NOT NULL,
  source           TEXT,
  meta_json        TEXT
);
CREATE INDEX IF NOT EXISTS idx_tl_inv ON investigation_timeline(investigation_id, seq);

-- ------------------------------------------------------- Reports & metadata
CREATE TABLE IF NOT EXISTS reports (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  title            TEXT    NOT NULL,
  classification   TEXT    NOT NULL DEFAULT 'TLP:AMBER',
  generated_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  generated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  format           TEXT    NOT NULL CHECK (format IN ('json','pdf','html','markdown')),
  byte_size        INTEGER,
  sha256           TEXT
);
CREATE INDEX IF NOT EXISTS idx_rep_inv ON reports(investigation_id);

CREATE TABLE IF NOT EXISTS tags (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS investigation_tags (
  investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  tag_id           INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (investigation_id, tag_id)
);

-- Lightweight audit trail (who did what) - supports the security requirement.
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,
  entity     TEXT,
  entity_id  TEXT,
  at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  meta_json  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);

-- Runtime configuration that the Settings page may change (e.g. mode override).
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
