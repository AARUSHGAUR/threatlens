/**
 * Settings: intelligence mode, provider health, analyst profile and platform
 * information.
 *
 * The API key section deliberately reports only BOOLEAN "configured" flags plus
 * documentation links - the values themselves are never sent to the browser.
 */
import { useState } from 'react';
import { api, ApiError, type SettingsData } from '../api/client';
import { useApp, useFetch } from '../api/AppContext';
import { Alert, ErrorState, Loading, Panel, PanelFlush, KV } from '../components/ui';
import { formatDate, formatRelative } from '../lib/format';

const KEY_DOCS: Record<string, { label: string; env: string; url: string; required: boolean }> = {
  VIRUSTOTAL_API_KEY: { label: 'VirusTotal', env: 'VIRUSTOTAL_API_KEY', url: 'https://www.virustotal.com/gui/my-apikey', required: true },
  ABUSEIPDB_API_KEY: { label: 'AbuseIPDB', env: 'ABUSEIPDB_API_KEY', url: 'https://www.abuseipdb.com/account/api', required: true },
  OTX_API_KEY: { label: 'AlienVault OTX', env: 'OTX_API_KEY', url: 'https://otx.alienvault.com/settings', required: false },
  URLHAUS_ENABLED: { label: 'URLhaus (abuse.ch)', env: 'URLHAUS_ENABLED', url: 'https://urlhaus.abuse.ch/api/', required: false },
  GREYNOISE_API_KEY: { label: 'GreyNoise', env: 'GREYNOISE_API_KEY', url: 'https://docs.greynoise.io/', required: false },
  SHODAN_API_KEY: { label: 'Shodan', env: 'SHODAN_API_KEY', url: 'https://account.shodan.io/', required: false },
};

export const SettingsPage = () => {
  const { registry, demoMode, setMode, refreshRegistry, user } = useApp();
  const { data, error, loading, reload } = useFetch<SettingsData>(() => api.settings(), []);
  const [switching, setSwitching] = useState<string | null>(null);
  const [displayName, setDisplayName] = useState<string | null>(null);
  const [savingProfile, setSavingProfile] = useState(false);
  const [profileMsg, setProfileMsg] = useState<string | null>(null);
  const [password, setPassword] = useState({ current: '', next: '', confirm: '' });
  const [passwordMsg, setPasswordMsg] = useState<{ kind: 'success' | 'danger'; text: string } | null>(null);
  const [savingPassword, setSavingPassword] = useState(false);

  if (loading) return <Loading label="Loading settings" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return null;

  const changeMode = async (mode: 'live' | 'demo' | 'auto') => {
    setSwitching(mode);
    try {
      await setMode(mode);
      await refreshRegistry();
    } catch (err) {
      setProfileMsg(err instanceof ApiError ? err.message : 'Mode change failed');
    } finally {
      setSwitching(null);
    }
  };

  const saveProfile = async () => {
    setSavingProfile(true);
    setProfileMsg(null);
    try {
      await api.updateProfile({ displayName: displayName ?? undefined });
      setProfileMsg('Profile updated.');
      window.setTimeout(() => window.location.reload(), 600);
    } catch (err) {
      setProfileMsg(err instanceof Error ? err.message : 'Update failed');
    } finally {
      setSavingProfile(false);
    }
  };

  const changePassword = async () => {
    setPasswordMsg(null);
    if (password.next !== password.confirm) {
      setPasswordMsg({ kind: 'danger', text: 'New passwords do not match.' });
      return;
    }
    setSavingPassword(true);
    try {
      await api.changePassword({ currentPassword: password.current, newPassword: password.next });
      setPasswordMsg({ kind: 'success', text: 'Password changed. It applies on your next sign-in.' });
      setPassword({ current: '', next: '', confirm: '' });
    } catch (err) {
      setPasswordMsg({ kind: 'danger', text: err instanceof Error ? err.message : 'Password change failed.' });
    } finally {
      setSavingPassword(false);
    }
  };

  const liveProviders = data.registry.providers.filter((p) => !p.id.startsWith('demo:') && p.id !== 'demo');
  const demoProviders = data.registry.providers.filter((p) => p.id.startsWith('demo:') || p.id === 'demo');

  return (
    <div className="flex flex-col gap-3">
      {/* ------------------------------------------------------ mode */}
      <Panel title="Intelligence mode" subtitle="Choose where enrichment data comes from">
        <div className="mode-switch">
          <button
            type="button"
            className={`mode-card ${!demoMode ? 'on' : ''}`}
            onClick={() => changeMode('live')}
            disabled={switching !== null}
          >
            <div className="flex items-center gap-2">
              <span className="mode-card-title">LIVE INTELLIGENCE</span>
              {switching === 'live' ? <span className="spinner" /> : null}
            </div>
            <div className="mode-card-desc">
              Query real providers. Requires API keys. If a provider is unreachable or has no key, the failure is
              reported explicitly — ThreatLens never substitutes demo data for live intelligence.
            </div>
          </button>

          <button
            type="button"
            className={`mode-card demo ${demoMode ? 'on' : ''}`}
            onClick={() => changeMode('demo')}
            disabled={switching !== null}
          >
            <div className="flex items-center gap-2">
              <span className="mode-card-title">DEMO MODE</span>
              {switching === 'demo' ? <span className="spinner" /> : null}
            </div>
            <div className="mode-card-desc">
              Use the built-in fictional dataset: documentation IP ranges, RFC 2606 domains, synthetic hashes and
              invented actors. Every result is labelled DEMO DATA. Works with zero API keys.
            </div>
          </button>
        </div>

        <div className="mt-3">
          <Alert kind={demoMode ? 'demo' : data.registry.hasLiveKeys ? 'success' : 'warning'} icon="◈">
            {data.registry.notice ?? 'Mode resolved automatically.'}{' '}
            <span className="dim">
              (source: {data.registry.modeSource}, override: {data.modeOverride ?? 'none'})
            </span>
          </Alert>
        </div>
      </Panel>

      {/* ------------------------------------------------- api keys */}
      <Panel title="Provider credentials" subtitle="Only configuration state is shown — key values never leave the server">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Environment variable</th>
                <th>Status</th>
                <th>Indicators supported</th>
                <th className="right">Key request</th>
              </tr>
            </thead>
            <tbody>
              {liveProviders.map((p) => {
                const keyEnv = p.id === 'urlhaus' ? 'URLHAUS_ENABLED' : `${p.id.toUpperCase()}_API_KEY`;
                const doc = KEY_DOCS[keyEnv];
                return (
                  <tr key={p.id}>
                    <td>
                      <div className="small" style={{ color: 'var(--ink-0)' }}>
                        {p.name}
                      </div>
                      <div className="tiny dim">{p.description}</div>
                    </td>
                    <td>
                      <code className="inline-code">{keyEnv}</code>
                    </td>
                    <td>
                      {p.configured ? (
                        <span className="badge badge-clean">configured</span>
                      ) : (
                        <span className="badge badge-unknown">not configured</span>
                      )}
                      {p.requiresKey && !p.configured ? <div className="tiny dim mt-2">add the key to .env</div> : null}
                    </td>
                    <td>
                      <div className="flex gap-2 wrap">
                        {p.supports.map((t) => (
                          <span key={t} className="tag tiny">
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="right">
                      <a className="btn btn-sm btn-ghost" href={doc?.url ?? p.documentationUrl} target="_blank" rel="noreferrer noopener">
                        Get key ↗
                      </a>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="mt-3 small dim">
          Keys are read from environment variables at boot. To change one: edit <code className="inline-code">.env</code>,
          restart the API (<code className="inline-code">npm run dev</code> or <code className="inline-code">npm start</code>), then
          reload this page. <code className="inline-code">.env</code> is git-ignored and must never be committed.
        </div>
      </Panel>

      {/* ----------------------------------------------- provider health */}
      <div className="grid grid-2">
        <PanelFlush title="Live provider health" subtitle="Last observed status per source">
          <div className="panel-body">
            <div className="flex flex-col gap-2">
              {liveProviders.map((p) => (
                <div className="provider-row" key={p.id}>
                  <span className={`provider-dot ${p.lastStatus}`} />
                  <div className="grow">
                    <div className="flex items-center gap-2 wrap">
                      <strong className="small" style={{ color: 'var(--ink-0)' }}>
                        {p.name}
                      </strong>
                      <span className={`badge ${p.configured ? 'badge-neutral' : 'badge-unknown'}`}>
                        {p.configured ? 'key present' : 'no key'}
                      </span>
                      {demoMode ? <span className="badge badge-neutral">idle in demo mode</span> : null}
                    </div>
                    {p.lastMessage ? <div className="tiny dim mt-2">{p.lastMessage}</div> : null}
                    {p.lastCheckedAt ? <div className="tiny dim">last call {formatRelative(p.lastCheckedAt)}</div> : null}
                  </div>
                  <a className="btn btn-sm btn-ghost" href={p.documentationUrl} target="_blank" rel="noreferrer noopener">
                    Docs ↗
                  </a>
                </div>
              ))}
            </div>
          </div>
        </PanelFlush>

        <PanelFlush title="Demo dataset sources" subtitle="Simulated sources used in DEMO MODE">
          <div className="panel-body">
            <div className="flex flex-col gap-2">
              {demoProviders.map((p) => (
                <div className="provider-row" key={p.id}>
                  <span className="provider-dot ok" style={{ background: 'var(--demo)' }} />
                  <div className="grow">
                    <div className="flex items-center gap-2 wrap">
                      <strong className="small" style={{ color: 'var(--ink-0)' }}>
                        {p.name}
                      </strong>
                      <span className="badge badge-demo">SIMULATED</span>
                    </div>
                    <div className="tiny dim mt-2">{p.description}</div>
                    <div className="flex gap-2 wrap mt-2">
                      {p.supports.map((t) => (
                        <span key={t} className="tag tiny">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </PanelFlush>
      </div>

      {/* --------------------------------------------------- profile */}
      <div className="grid grid-2">
        <Panel title="Analyst profile">
          <KV
            items={[
              { label: 'Name', value: user?.displayName ?? data.analyst.displayName },
              { label: 'Email', value: user?.email ?? data.analyst.email },
              { label: 'Role', value: user?.role ?? data.analyst.role },
              { label: 'Last sign-in', value: user?.lastLoginAt ? formatDate(user.lastLoginAt) : '—' },
            ]}
          />
          <div className="mt-3">
            <label className="label" htmlFor="displayName">
              Display name
            </label>
            <div className="flex gap-2">
              <input
                id="displayName"
                className="input"
                defaultValue={displayName ?? data.analyst.displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
              <button className="btn btn-sm" type="button" onClick={saveProfile} disabled={savingProfile}>
                {savingProfile ? <span className="spinner" /> : 'Save'}
              </button>
            </div>
            {profileMsg ? <div className="tiny mt-2 dim">{profileMsg}</div> : null}
          </div>
        </Panel>

        <Panel title="Change password" subtitle="Minimum 12 characters with upper case, lower case and a digit">
          <div className="flex flex-col gap-2">
            <div>
              <label className="label" htmlFor="pw-current">
                Current password
              </label>
              <input
                id="pw-current"
                className="input"
                type="password"
                autoComplete="current-password"
                value={password.current}
                onChange={(e) => setPassword((p) => ({ ...p, current: e.target.value }))}
              />
            </div>
            <div>
              <label className="label" htmlFor="pw-new">
                New password
              </label>
              <input
                id="pw-new"
                className="input"
                type="password"
                autoComplete="new-password"
                value={password.next}
                onChange={(e) => setPassword((p) => ({ ...p, next: e.target.value }))}
              />
            </div>
            <div>
              <label className="label" htmlFor="pw-confirm">
                Confirm new password
              </label>
              <input
                id="pw-confirm"
                className="input"
                type="password"
                autoComplete="new-password"
                value={password.confirm}
                onChange={(e) => setPassword((p) => ({ ...p, confirm: e.target.value }))}
              />
            </div>
            <div className="flex items-center gap-2">
              <button className="btn btn-sm btn-primary" type="button" onClick={changePassword} disabled={savingPassword}>
                {savingPassword ? <span className="spinner" /> : 'Update password'}
              </button>
              {passwordMsg ? (
                <span className="small" style={{ color: passwordMsg.kind === 'success' ? 'var(--clean)' : 'var(--critical)' }}>
                  {passwordMsg.text}
                </span>
              ) : null}
            </div>
          </div>
        </Panel>
      </div>

      {/* ------------------------------------------- platform / scoring */}
      <div className="grid grid-2">
        <Panel title="Platform configuration">
          <KV
            items={[
              { label: 'Environment', value: data.environment.nodeEnv },
              { label: 'API port', value: String(data.environment.port) },
              { label: 'Database', value: <span className="mono">{data.environment.database}</span> },
              { label: 'Provider throttle', value: `${data.environment.providerMinIntervalMs} ms between calls per source` },
              { label: 'Provider timeout', value: `${data.environment.providerTimeoutMs} ms` },
              { label: 'Demo badge', value: data.environment.showDemoBadge ? 'enabled' : 'disabled' },
              { label: 'Investigations stored', value: String(data.totals.investigations) },
              { label: 'Analyst accounts', value: String(data.totals.users) },
            ]}
          />
        </Panel>

        <Panel title="Recent audit trail" subtitle="Who did what">
          {data.audit.length ? (
            <div className="table-wrap max-h-320 scroll-y">
              <table className="table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Entity</th>
                    <th className="right">When</th>
                  </tr>
                </thead>
                <tbody>
                  {data.audit.map((a) => (
                    <tr key={a.id}>
                      <td className="small mono">{a.action}</td>
                      <td className="tiny dim mono">
                        {a.entity ?? '—'}
                        {a.entityId ? `#${a.entityId}` : ''}
                      </td>
                      <td className="right small dim nowrap">{formatRelative(a.at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <span className="small dim">No activity recorded yet.</span>
          )}
        </Panel>
      </div>

      <Panel title="Risk scoring methodology" subtitle="The full rule set, as implemented in the risk engine">
        <p className="small muted" style={{ lineHeight: 1.8 }}>
          {data.riskMethodology}
        </p>
        <div className="mt-3 flex gap-2 wrap">
          {(['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map((level) => (
            <span key={level} className={`badge badge-${level.toLowerCase()}`}>
              {level === 'CLEAN' ? '0-19' : level === 'LOW' ? '20-39' : level === 'MEDIUM' ? '40-59' : level === 'HIGH' ? '60-79' : '80-100'}{' '}
              {level}
            </span>
          ))}
        </div>
      </Panel>
    </div>
  );
};
