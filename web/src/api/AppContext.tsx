/**
 * Application bootstrap contexts.
 *
 *  - `AuthProvider`      : session state, login/logout, and the resolved
 *                          intelligence mode (LIVE / DEMO) that drives the
 *                          global "DEMO DATA" banner.
 *  - `RegistryProvider`  : provider health + demo catalogue, fetched once after
 *                          sign-in and refreshed when the mode changes.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, ApiError, type Bootstrap, type PublicUser, type RegistrySnapshot } from './client';

interface AppState {
  user: PublicUser | null;
  registry: RegistrySnapshot | null;
  bootstrap: Bootstrap | null;
  loading: boolean;
  demoMode: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshRegistry: () => Promise<void>;
  setMode: (mode: 'live' | 'demo' | 'auto') => Promise<void>;
}

const AppContext = createContext<AppState | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<PublicUser | null>(null);
  const [registry, setRegistry] = useState<RegistrySnapshot | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const boot = await api.bootstrap();
      setBootstrap(boot);
      setRegistry(boot.registry);
      const me = await api.me();
      setUser(me.user);
      if (me.user) {
        // Re-read the registry with the session so provider health reflects
        // anything that happened during this session.
        const settings = await api.settings().catch(() => null);
        if (settings) setRegistry(settings.registry);
      }
    } catch {
      // The login screen renders its own error state; nothing to do here.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const login = useCallback(async (email: string, password: string) => {
    const result = await api.login(email, password);
    setUser(result.user);
    const settings = await api.settings().catch(() => null);
    if (settings) setRegistry(settings.registry);
  }, []);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
  }, []);

  const refreshRegistry = useCallback(async () => {
    const settings = await api.settings().catch(() => null);
    if (settings) setRegistry(settings.registry);
    else {
      const boot = await api.bootstrap().catch(() => null);
      if (boot) {
        setBootstrap(boot);
        setRegistry(boot.registry);
      }
    }
  }, []);

  const setMode = useCallback(
    async (mode: 'live' | 'demo' | 'auto') => {
      const result = await api.setMode(mode);
      setRegistry(result.registry);
    },
    [],
  );

  const value = useMemo<AppState>(
    () => ({
      user,
      registry,
      bootstrap,
      loading,
      demoMode: registry?.mode === 'demo',
      login,
      logout,
      refreshRegistry,
      setMode,
    }),
    [user, registry, bootstrap, loading, login, logout, refreshRegistry, setMode],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppState {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used inside <AppProvider>');
  return ctx;
}

/**
 * Small data-fetching hook.
 *
 * Deliberately minimal (no react-query): the API surface is small, the caching
 * requirements are modest, and a hand-rolled hook keeps the dependency list
 * short enough to audit.
 */
export function useFetch<T>(
  loader: () => Promise<T>,
  deps: unknown[],
): { data: T | null; error: ApiError | Error | null; loading: boolean; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    loader()
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error(String(err)));
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, error, loading, reload: () => setNonce((n) => n + 1) };
}
