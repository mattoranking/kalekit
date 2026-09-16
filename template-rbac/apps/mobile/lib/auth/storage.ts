import * as SecureStore from 'expo-secure-store';

/**
 * All token persistence goes through expo-secure-store, which is backed by
 * the iOS Keychain and Android Keystore. Never fall back to AsyncStorage or
 * a plain file for these keys -- both are unencrypted on-disk storage that
 * any file-system access (a rooted/jailbroken device, a backup, another app
 * on some Android versions) can read.
 */
const ACCESS_TOKEN_KEY = 'kalekit.accessToken';
const REFRESH_TOKEN_KEY = 'kalekit.refreshToken';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export async function getAccessToken(): Promise<string | null> {
  return SecureStore.getItemAsync(ACCESS_TOKEN_KEY);
}

export async function getRefreshToken(): Promise<string | null> {
  return SecureStore.getItemAsync(REFRESH_TOKEN_KEY);
}

export async function saveTokens(tokens: TokenPair): Promise<void> {
  await Promise.all([
    SecureStore.setItemAsync(ACCESS_TOKEN_KEY, tokens.accessToken),
    SecureStore.setItemAsync(REFRESH_TOKEN_KEY, tokens.refreshToken),
  ]);
}

export async function clearTokens(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(ACCESS_TOKEN_KEY),
    SecureStore.deleteItemAsync(REFRESH_TOKEN_KEY),
  ]);
}
