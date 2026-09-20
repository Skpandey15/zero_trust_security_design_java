import { useEffect, useState } from "react";
import { getSession, type Session } from "./api/client";

/**
 * WP-UI-01 shell.
 *
 * ADR-SEC-007: this component never sees a token. Authentication state is
 * whatever the BFF reports for the session cookie the browser holds, and that
 * cookie is HttpOnly, so nothing here can read it either.
 */
export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSession()
      .then(setSession)
      .catch(() => setSession(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <main>Checking session…</main>;

  return (
    <main>
      <h1>Zero Trust Console</h1>
      {session?.authenticated ? (
        <p>Signed in as {session.subject}</p>
      ) : (
        <p>Not signed in.</p>
      )}
      <p>
        <small>
          WP-UI-01 scaffold. No access or refresh token is held in the browser —
          see ADR-SEC-007.
        </small>
      </p>
    </main>
  );
}
