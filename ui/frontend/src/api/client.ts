/**
 * API client for the BFF.
 *
 * ADR-SEC-007: there is deliberately no token handling here. No Authorization
 * header is set, nothing is read from or written to localStorage or
 * sessionStorage, and no token is parsed. The browser's only credential is an
 * HttpOnly session cookie it cannot read, which the BFF exchanges for an
 * audience-restricted access token server-side.
 *
 * Because authentication is now ambient (a cookie), CSRF protection is
 * mandatory and separate - SameSite is defence in depth, not the control. Every
 * state-changing call carries the anti-CSRF token the BFF issued.
 */

export interface Session {
  authenticated: boolean;
  subject?: string;
  authenticationLevel?: string;
}

const CSRF_COOKIE = "XSRF-TOKEN";
const CSRF_HEADER = "X-XSRF-TOKEN";

function readCsrfToken(): string | null {
  // Readable by design: the anti-CSRF token is not a credential. The session
  // cookie is the credential, and that one is HttpOnly.
  const match = document.cookie.match(new RegExp(`(^| )${CSRF_COOKIE}=([^;]+)`));
  return match ? decodeURIComponent(match[2]) : null;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const mutating = !!init.method && init.method.toUpperCase() !== "GET";

  if (mutating) {
    const csrf = readCsrfToken();
    if (csrf) headers.set(CSRF_HEADER, csrf);
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "same-origin", // send the session cookie, same-origin only
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

export function getSession(): Promise<Session> {
  return request<Session>("/api/session");
}

export function logout(): Promise<void> {
  return request<void>("/api/session/logout", { method: "POST" });
}
