import { Navigate, useSearchParams } from "react-router-dom";
import { startLogin } from "../api/client";
import { useSession } from "../session";

/**
 * Deliberately not a credentials form. Passwords are entered on the
 * Authorization Server's own page, so this app - and any script injected into
 * it - never handles one (ADR-SEC-003, ADR-SEC-007).
 */
export default function Login() {
  const { session } = useSession();
  const [params] = useSearchParams();

  if (session?.authenticated) return <Navigate to="/" replace />;

  return (
    <section>
      <h1>Sign in</h1>
      {params.has("error") && (
        <p role="alert" className="error">
          Sign-in did not complete. Please try again.
        </p>
      )}
      <p>You will be taken to the secure sign-in page to enter your credentials.</p>
      <p className="actions">
        <button onClick={startLogin}>Continue to sign in</button>
      </p>
    </section>
  );
}
