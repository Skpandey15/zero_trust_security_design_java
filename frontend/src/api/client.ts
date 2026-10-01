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
  /** What THIS session proved: "MFA" only if a second factor was verified, else "PASSWORD". */
  authenticationLevel?: string;
  /** Where two-step verification is managed - on the Authorization Server, not in this app. */
  securitySettingsUrl?: string;
}

export interface RegisterInput {
  email: string;
  displayName: string;
  password: string;
}

/** An error the BFF (or the Authorization Server behind it) reported. */
export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

const CSRF_COOKIE = "XSRF-TOKEN";
const CSRF_HEADER = "X-XSRF-TOKEN";

/** The BFF's OAuth client entry point. Navigating here starts Authorization Code + PKCE. */
const LOGIN_URL = "/oauth2/authorization/zero-trust-web";

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
    if (init.body) headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "same-origin", // send the session cookie, same-origin only
  });

  // Some successful responses have no body, and a proxy error page is not JSON.
  const text = await response.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = undefined;
  }

  if (!response.ok) {
    const body = (data ?? {}) as { code?: string; message?: string };
    throw new ApiError(
      response.status,
      body.message ?? `${response.status} ${response.statusText}`,
      body.code,
    );
  }
  return data as T;
}

export function getSession(): Promise<Session> {
  return request<Session>("/api/session");
}

export function register(input: RegisterInput): Promise<unknown> {
  return request<unknown>("/api/auth/register", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

/**
 * Sign in. This is a top-level navigation, not a fetch: the browser is sent to
 * the Authorization Server to enter its credentials there, and returns to the
 * BFF, which completes the exchange. The password never passes through this app.
 */
export function startLogin(): void {
  window.location.assign(LOGIN_URL);
}

/** Ends the BFF session, then the Authorization Server's, by navigating to its end-session URL. */
export async function logout(): Promise<void> {
  const result = await request<{ logoutUrl?: string }>("/api/session/logout", {
    method: "POST",
  });
  window.location.assign(result?.logoutUrl ?? "/");
}
