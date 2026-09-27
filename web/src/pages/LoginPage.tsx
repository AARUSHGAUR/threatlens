/**
 * Sign-in page.
 *
 * The seeded analyst credentials are shown on the page because this is a local
 * capstone deployment - there is no mail delivery, no password reset and no
 * external identity provider. The password is hashed server-side with bcrypt
 * and the session is an httpOnly cookie, so nothing sensitive lives in this
 * component or in the browser bundle.
 */
import { useEffect, useState, type FormEvent } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import { useApp } from '../api/AppContext';
import { Alert } from '../components/ui';

export const LoginPage = () => {
  const { user, login, registry, loading } = useApp();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: string } };

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && user) navigate(location.state?.from ?? '/dashboard', { replace: true });
  }, [user, loading, navigate, location.state]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed. Is the API running?');
    } finally {
      setBusy(false);
    }
  };

  const fillDemo = () => {
    setEmail('analyst@threatlens.local');
    setPassword('ThreatLens!2024');
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-head">
          <div className="login-title">
            <div className="login-mark" aria-hidden="true">
              ⌾
            </div>
            <div>
              <h1 style={{ fontSize: 17 }}>ThreatLens</h1>
              <div className="tiny dim" style={{ textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Cyber Threat Intelligence Console
              </div>
            </div>
          </div>
        </div>

        <form className="login-body" onSubmit={submit}>
          {error ? (
            <div className="mb-3">
              <Alert kind="danger" title="Sign-in failed">
                {error}
              </Alert>
            </div>
          ) : null}

          {registry ? (
            <div className="mb-3">
              <Alert kind={registry.mode === 'demo' ? 'demo' : 'success'} icon="◈">
                {registry.mode === 'demo'
                  ? 'No provider API keys detected — ThreatLens starts in DEMO MODE with a clearly labelled fictional dataset.'
                  : 'Live provider credentials detected — investigations will query real threat intelligence.'}
              </Alert>
            </div>
          ) : null}

          <div className="mb-3">
            <label className="label" htmlFor="email">
              Analyst email
            </label>
            <input
              id="email"
              className="input"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@threatlens.local"
              required
            />
          </div>

          <div className="mb-3">
            <label className="label" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              className="input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button className="btn btn-primary btn-block" type="submit" disabled={busy || loading}>
            {busy ? <span className="spinner" /> : null}
            {busy ? 'Authenticating' : 'Sign in to console'}
          </button>
        </form>

        <div className="login-foot">
          <div className="flex items-center justify-between gap-2 wrap">
            <span>
              Seeded demo account: <code className="inline-code">analyst@threatlens.local</code> /{' '}
              <code className="inline-code">ThreatLens!2024</code>
            </span>
            <button className="btn btn-sm" type="button" onClick={fillDemo}>
              Fill demo credentials
            </button>
          </div>
          <div className="mt-2 dim">
            Change the password in Settings after signing in. Sessions are httpOnly JWT cookies and expire automatically.
          </div>
        </div>
      </div>
    </div>
  );
};
