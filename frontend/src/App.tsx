import { Link, Route, Routes } from "react-router-dom";
import { useSession } from "./session";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Documents from "./pages/Documents";
import MfaSetup from "./pages/MfaSetup";
import Register from "./pages/Register";

/**
 * ADR-SEC-007: nothing here ever sees a token. Authentication state is
 * whatever the BFF reports for the session cookie the browser holds, and that
 * cookie is HttpOnly, so nothing here can read it either.
 *
 * Still to build (WP-UI-02/03): /verify-email, /passkeys, the password-reset
 * and recovery routes, /step-up and the Security Center. Each needs an
 * Authorization Server capability that does not exist yet.
 */
export default function App() {
  const { loading, session } = useSession();

  return (
    <>
      <header className="bar">
        <Link to="/" className="brand">Zero Trust Console</Link>
        {session?.authenticated && <Link to="/documents">Documents</Link>}
      </header>
      <main>
        {loading ? (
          <p>Checking session…</p>
        ) : (
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/documents" element={<Documents />} />
            <Route path="/mfa/setup" element={<MfaSetup />} />
            <Route path="*" element={<section><h1>Not found</h1><p><Link to="/">Home</Link></p></section>} />
          </Routes>
        )}
      </main>
    </>
  );
}
