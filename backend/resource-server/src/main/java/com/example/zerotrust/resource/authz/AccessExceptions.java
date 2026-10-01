package com.example.zerotrust.resource.authz;

/** The ways an authorization decision can end other than ALLOW. */
public final class AccessExceptions {

    private AccessExceptions() {}

    /**
     * No such resource, OR no standing in its tenant: deliberately the same answer.
     * Identifiers are assumed guessable (ADR-SEC-015), so a 403 for "exists, not
     * yours" and a 404 for "does not exist" would let anyone enumerate other
     * tenants' data by watching which one comes back.
     */
    public static class NotFound extends RuntimeException {
        public NotFound() { super("not found"); }
    }

    /** Standing in the tenant, but the policy says no. */
    public static class Forbidden extends RuntimeException {
        public Forbidden(String reason) { super(reason); }
    }

    /** Allowed in principle, but the session has not proved enough yet (RFC 9470). */
    public static class StepUpRequired extends RuntimeException {
        public StepUpRequired(String reason) { super(reason); }
    }

    /** The decision could not be made. Fail closed: this is never an ALLOW (ADR-SEC-024). */
    public static class AuthorizationUnavailable extends RuntimeException {
        public AuthorizationUnavailable(Throwable cause) { super("authorization unavailable", cause); }
    }
}
