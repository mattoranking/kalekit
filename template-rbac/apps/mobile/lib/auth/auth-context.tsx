import { router } from 'expo-router';
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { PropsWithChildren } from 'react';

import { API_BASE_URL } from '../config';
import { onSessionExpired } from './session-events';
import { clearTokens, getAccessToken, getRefreshToken, saveTokens } from './storage';

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

interface AuthContextValue {
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: PropsWithChildren) {
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // A stored access token can be expired -- that's fine, apiFetch's
    // refresh-on-401 handles it on the first authenticated call. This only
    // needs to know whether there's a session worth trying at all.
    getAccessToken()
      .then((token) => setIsAuthenticated(token !== null))
      .finally(() => setIsLoading(false));

    // A failed refresh (triggered from apiFetch, outside this component)
    // clears tokens and navigates to sign-in on its own -- this just keeps
    // isAuthenticated in sync so a route guard reading it doesn't fight
    // that redirect with a stale "still authenticated" value.
    return onSessionExpired(() => setIsAuthenticated(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      throw new Error('Invalid email or password');
    }

    const body = (await response.json()) as TokenResponse;
    await saveTokens({ accessToken: body.access_token, refreshToken: body.refresh_token });
    setIsAuthenticated(true);
    router.replace('/');
  }, []);

  const logout = useCallback(async () => {
    // Best-effort: tell the server to revoke this session's refresh token
    // family so it can't be used again, but the local session ends either
    // way -- a network failure here must not leave the user stuck signed
    // in on this device.
    try {
      const [accessToken, refreshToken] = await Promise.all([getAccessToken(), getRefreshToken()]);
      if (accessToken && refreshToken) {
        await fetch(`${API_BASE_URL}/auth/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
      }
    } catch {
      // Ignored -- see comment above.
    }

    await clearTokens();
    setIsAuthenticated(false);
    router.replace('/sign-in');
  }, []);

  const value = useMemo(
    () => ({ isLoading, isAuthenticated, login, logout }),
    [isLoading, isAuthenticated, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
