import Constants from 'expo-constants';

/**
 * Mobile reads its API base URL from `app.json`'s `extra.apiUrl` (via
 * expo-constants), not from `@kalekit/api-client`'s `API_BASE_URL` -- that
 * constant is wired to `NEXT_PUBLIC_API_URL`, a Next.js-only env convention
 * that doesn't exist in an Expo runtime.
 */
export const API_BASE_URL: string =
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ?? 'http://localhost:8000';
