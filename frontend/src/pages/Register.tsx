import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, register } from "../api/client";

/** Mirrors the server's rule so the user is told early; the server remains the authority. */
const MIN_PASSWORD = 12;

export default function Register() {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    if (password.length < MIN_PASSWORD) {
      setError(`Use at least ${MIN_PASSWORD} characters for your password.`);
      return;
    }
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }

    setBusy(true);
    try {
      await register({ email: email.trim(), displayName: displayName.trim(), password });
      setPassword("");
      setConfirm("");
      setDone(true);
    } catch (e) {
      setError(
        e instanceof ApiError && e.status < 500
          ? e.message
          : "Registration is unavailable right now. Please try again later.",
      );
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <section>
        <h1>Account created</h1>
        <p>You can now sign in.</p>
        <p className="actions">
          <Link className="button" to="/login">Sign in</Link>
        </p>
      </section>
    );
  }

  return (
    <section>
      <h1>Create an account</h1>
      <form onSubmit={submit} noValidate>
        <label>
          Name
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)}
                 autoComplete="name" required maxLength={120} />
        </label>
        <label>
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                 autoComplete="email" required maxLength={320} />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 autoComplete="new-password" required minLength={MIN_PASSWORD} maxLength={128}
                 aria-describedby="pw-hint" />
        </label>
        <p id="pw-hint" className="hint">At least {MIN_PASSWORD} characters. A passphrase works well.</p>
        <label>
          Confirm password
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
                 autoComplete="new-password" required />
        </label>
        {error && <p role="alert" className="error">{error}</p>}
        <button type="submit" disabled={busy || !email || !displayName || !password}>
          {busy ? "Creating…" : "Create account"}
        </button>
      </form>
      <p>Already registered? <Link to="/login">Sign in</Link></p>
    </section>
  );
}
