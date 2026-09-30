import { useState } from "react";
import { Link } from "react-router-dom";
import { logout } from "../api/client";
import { useSession } from "../session";

export default function Home() {
  const { session } = useSession();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function signOut() {
    setBusy(true);
    setError(null);
    try {
      await logout(); // navigates away on success
    } catch {
      setError("Could not sign out. Try again.");
      setBusy(false);
    }
  }

  if (session?.authenticated) {
    return (
      <section>
        <h1>Signed in</h1>
        <p>
          You are signed in as <strong>{session.subject}</strong>.
        </p>
        <dl className="facts">
          <dt>Sign-in strength</dt>
          <dd>{session.authenticationLevel === "PASSWORD" ? "Password only" : session.authenticationLevel}</dd>
        </dl>
        {error && <p role="alert" className="error">{error}</p>}
        <button onClick={signOut} disabled={busy}>
          {busy ? "Signing out…" : "Sign out"}
        </button>
      </section>
    );
  }

  return (
    <section>
      <h1>Zero Trust Console</h1>
      <p>You are not signed in.</p>
      <p className="actions">
        <Link className="button" to="/login">Sign in</Link>
        <Link to="/register">Create an account</Link>
      </p>
    </section>
  );
}
