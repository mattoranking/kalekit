import { router } from 'expo-router';

import { API_BASE_URL } from '../config';
import { emitSessionExpired } from './session-events';
import { clearTokens, getRefreshToken, saveTokens } from './storage';

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

let inFlightRefresh: Promise<string> | null = null;

/**
 * Refreshes the access token, sharing a single in-flight request across every
 * concurrent caller.
 *
 * The backend rotates the refresh token on every use and, if an
 * already-rotated (used) refresh token is presented again outside a short
 * grace window, treats it as reuse and revokes the *entire* session family
 * (see `template-rbac/backend/kalekit/auth/endpoints.py::refresh`). If two
 * requests on this client raced to refresh independently, the second one to
 * reach the server would present a token the first had already rotated away
 * -- exactly the reuse case -- and could get the whole session killed. Every
 * caller that shows up while a refresh is in flight must therefore await
 * *that* refresh instead of starting its own.
 */
export function refreshAccessToken(): Promise<string> {
  if (!inFlightRefresh) {
    inFlightRefresh = performRefresh().finally(() => {
      inFlightRefresh = null;
    });
  }

  return inFlightRefresh;
}

async function performRefresh(): Promise<string> {
  const refreshToken = await getRefreshToken();
  if (!refreshToken) {
    await signOut();
    throw new Error('No refresh token available');
  }

  const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) {
    // Invalid, expired, revoked, or reused-and-family-revoked -- in every
    // case the refresh token this client holds is now dead. There is no
    // recovery but a fresh login.
    await signOut();
    throw new Error(`Refresh failed with status ${response.status}`);
  }

  const body = (await response.json()) as TokenResponse;
  await saveTokens({ accessToken: body.access_token, refreshToken: body.refresh_token });
  return body.access_token;
}

async function signOut(): Promise<void> {
  await clearTokens();
  emitSessionExpired();
  router.replace('/sign-in');
}
