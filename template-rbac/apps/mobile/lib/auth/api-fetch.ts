import { API_BASE_URL } from '../config';
import { refreshAccessToken } from './refresh-lock';
import { getAccessToken } from './storage';

/**
 * Fetch wrapper for calls to the Kalekit API that require auth.
 *
 * Attaches the current access token, and on a 401 refreshes (joining any
 * refresh already in flight for other concurrent requests) and retries the
 * original request exactly once with the new token. If the refresh itself
 * fails, `refreshAccessToken` has already cleared stored tokens and routed
 * to sign-in -- this just surfaces the original 401 to the caller rather
 * than retrying against a session that no longer exists.
 */
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const accessToken = await getAccessToken();
  const response = await performRequest(path, init, accessToken);

  if (response.status !== 401) {
    return response;
  }

  let refreshedAccessToken: string;
  try {
    refreshedAccessToken = await refreshAccessToken();
  } catch {
    return response;
  }

  return performRequest(path, init, refreshedAccessToken);
}

function performRequest(
  path: string,
  init: RequestInit,
  accessToken: string | null,
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  return fetch(`${API_BASE_URL}${path}`, { ...init, headers });
}
