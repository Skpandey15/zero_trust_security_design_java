import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link, Navigate } from "react-router-dom";
import {
  ApiError,
  STEP_UP_REQUIRED,
  approveDocument,
  createDocument,
  getTenants,
  listDocuments,
  submitDocument,
} from "../api/client";
import type { DocumentView, Tenant } from "../api/client";
import { useSession } from "../session";

/**
 * Documents that need a second person's approval. Every button here is an OFFER:
 * the server re-decides each action against the document's own tenant, the role
 * held there, the session's assurance and the maker-checker rule. Hiding a button
 * is convenience, never the control.
 */
export default function Documents() {
  const { session } = useSession();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [docs, setDocs] = useState<DocumentView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState(false);
  const [busy, setBusy] = useState(false);

  const [tenantId, setTenantId] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");

  const load = useCallback(async () => {
    try {
      const [t, d] = await Promise.all([getTenants(), listDocuments()]);
      setTenants(t);
      setDocs(d);
      setTenantId((current) => current || t[0]?.id || "");
    } catch {
      setError("Could not load your documents. Try again.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (!session?.authenticated) return <Navigate to="/login" replace />;

  /** Runs one action and explains a refusal in terms the person can act on. */
  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    setStepUp(false);
    try {
      await action();
      await load();
    } catch (e) {
      if (e instanceof ApiError && e.code === STEP_UP_REQUIRED) {
        setStepUp(true);
      } else if (e instanceof ApiError && e.status === 403) {
        setError("You do not have permission to do that.");
      } else if (e instanceof ApiError && e.status === 404) {
        setError("That is not available to you.");
      } else if (e instanceof ApiError && e.status === 409) {
        setError(e.message);
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  function create(event: FormEvent) {
    event.preventDefault();
    void run(async () => {
      await createDocument({ tenantId, title: title.trim(), body: body.trim() });
      setTitle("");
      setBody("");
    });
  }

  const tenantName = (id: string) => tenants.find((t) => t.id === id)?.name ?? "Another workspace";
  const canWrite = tenants.some((t) => t.id === tenantId && (t.role === "MEMBER" || t.role === "OWNER"));

  return (
    <section className="wide">
      <h1>Documents</h1>

      {stepUp && (
        <p role="alert" className="error">
          Approving needs your authenticator code, and this sign-in did not use one.{" "}
          {session.authenticationLevel === "MFA" ? (
            <>Sign out and sign in again with your code.</>
          ) : (
            <>
              <Link to="/mfa/setup">Turn on two-step verification</Link>, then sign in with your code.
            </>
          )}
        </p>
      )}
      {error && <p role="alert" className="error">{error}</p>}

      {tenants.length > 0 && (
        <form onSubmit={create} noValidate>
          <h2>New document</h2>
          <label>
            Workspace
            <select value={tenantId} onChange={(e) => setTenantId(e.target.value)}>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>{t.name} ({t.role.toLowerCase()})</option>
              ))}
            </select>
          </label>
          <label>
            Title
            <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} required />
          </label>
          <label>
            Text
            <textarea value={body} onChange={(e) => setBody(e.target.value)} maxLength={10000} rows={3} required />
          </label>
          {!canWrite && <p className="hint">Your role in this workspace is read-only.</p>}
          <button type="submit" disabled={busy || !title.trim() || !body.trim() || !tenantId}>
            Create draft
          </button>
        </form>
      )}

      <h2>In your workspaces</h2>
      {loading ? (
        <p>Loading…</p>
      ) : docs.length === 0 ? (
        <p className="hint">Nothing here yet.</p>
      ) : (
        <ul className="docs">
          {docs.map((d) => (
            <li key={d.id}>
              <div className="doc-head">
                <strong>{d.title}</strong>
                <span className={`badge ${d.status.toLowerCase()}`}>{d.status.toLowerCase()}</span>
              </div>
              <p className="hint">{tenantName(d.tenantId)}{d.mine ? " · yours" : ""}</p>
              <p>{d.body}</p>
              <p className="actions">
                {d.mine && d.status === "DRAFT" && (
                  <button disabled={busy} onClick={() => void run(() => submitDocument(d.id))}>
                    Submit for approval
                  </button>
                )}
                {!d.mine && d.status === "SUBMITTED" && (
                  <button disabled={busy} onClick={() => void run(() => approveDocument(d.id))}>
                    Approve
                  </button>
                )}
                {d.mine && d.status === "SUBMITTED" && (
                  <span className="hint">Waiting for someone else to approve.</span>
                )}
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
