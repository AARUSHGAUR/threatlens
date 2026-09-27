import { Link, useLocation } from 'react-router-dom';
import { useApp } from '../api/AppContext';

export const NotFoundPage = () => {
  const { user } = useApp();
  const location = useLocation();

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-head">
          <div className="login-title">
            <div className="login-mark" aria-hidden="true">
              ⌾
            </div>
            <div>
              <h1 style={{ fontSize: 16 }}>Route not found</h1>
              <div className="tiny dim mono">{location.pathname}</div>
            </div>
          </div>
        </div>
        <div className="login-body">
          <p className="small muted">
            No page matches <code className="inline-code">{location.pathname}</code>. If you followed a link to an
            investigation, check that the record still exists — investigations can be deleted from the history page.
          </p>
          <div className="flex gap-2 mt-3">
            <Link to="/dashboard" className="btn btn-sm btn-primary">
              Go to dashboard
            </Link>
            <Link to="/history" className="btn btn-sm">
              Investigation history
            </Link>
            {!user ? <Link to="/login" className="btn btn-sm btn-ghost">Sign in</Link> : null}
          </div>
        </div>
      </div>
    </div>
  );
};
