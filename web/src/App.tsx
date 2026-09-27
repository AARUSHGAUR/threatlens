/**
 * Route table.
 *
 * Two route groups:
 *   /login  - public, no session required
 *   /*      - the analyst console, requires a session (redirects to /login)
 *
 * ProtectedRoute re-checks the session on every navigation so an expired token
 * returns the analyst to the login screen with a clear message instead of
 * rendering an empty dashboard full of failed requests.
 */
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppProvider, useApp } from './api/AppContext';
import { AppShell } from './components/AppShell';
import { Loading } from './components/ui';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { InvestigatePage } from './pages/InvestigatePage';
import { InvestigationPage } from './pages/InvestigationPage';
import { HistoryPage } from './pages/HistoryPage';
import { IndicatorsPage } from './pages/IndicatorsPage';
import { ThreatActorsPage } from './pages/ThreatActorsPage';
import { MitrePage } from './pages/MitrePage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { NotFoundPage } from './pages/NotFoundPage';

const ProtectedShell = () => {
  const { user, loading } = useApp();
  const location = useLocation();

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
        <Loading label="Restoring session" />
      </div>
    );
  }
  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return <AppShell />;
};

export const App = () => (
  <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route element={<ProtectedShell />}>
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/investigate" element={<InvestigatePage />} />
      <Route path="/investigation/:id" element={<InvestigationPage />} />
      <Route path="/history" element={<HistoryPage />} />
      <Route path="/indicators" element={<IndicatorsPage />} />
      <Route path="/threat-actors" element={<ThreatActorsPage />} />
      <Route path="/mitre" element={<MitrePage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route path="/settings" element={<SettingsPage />} />
    </Route>
    <Route path="/" element={<Navigate to="/dashboard" replace />} />
    <Route path="*" element={<NotFoundPage />} />
  </Routes>
);

export { AppProvider };
