import { Link, Navigate } from "react-router-dom";
import { useSession } from "../session";

/**
 * Deliberately a hand-off, not a form. The TOTP secret IS the second factor, so
 * it is shown on the Authorization Server's own page: anything rendered here
 * could be read by a script injected into this app (ADR-SEC-007 applies to the
 * factor as much as to tokens). The server also demands a recent sign-in before
 * it will add a factor (ADR-SEC-004).
 */
export default function MfaSetup() {
  const { session } = useSession();

  if (!session?.authenticated) return <Navigate to="/login" replace />;

  const alreadyOn = session.authenticationLevel === "MFA";

  return (
    <section>
      <h1>Two-step verification</h1>
      {alreadyOn ? (
        <p>This sign-in already used an authenticator code, so two-step verification is on.</p>
      ) : (
        <>
          <p>
            Add a second step to sign-in with an authenticator app. After this, a password alone
            will no longer be enough to get into your account.
          </p>
          <p>
            You will continue on the secure sign-in site, and may be asked to confirm your
            password first.
          </p>
        </>
      )}
      <p className="actions">
        {!alreadyOn && session.securitySettingsUrl && (
          <a className="button" href={session.securitySettingsUrl}>Continue</a>
        )}
        <Link to="/">Back</Link>
      </p>
    </section>
  );
}
