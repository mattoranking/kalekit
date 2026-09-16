/**
 * Tiny pub/sub so code outside the React tree (the refresh lock, which runs
 * from apiFetch and has no component to hook into) can tell AuthProvider
 * "the session just ended" without importing React or creating a circular
 * dependency between auth-context.tsx and refresh-lock.ts.
 */
type Listener = () => void;

const listeners = new Set<Listener>();

export function onSessionExpired(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function emitSessionExpired(): void {
  for (const listener of listeners) {
    listener();
  }
}
