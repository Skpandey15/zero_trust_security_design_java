package com.example.zerotrust.testsupport;

/**
 * The security fitness functions every service must satisfy.
 *
 * <p>Section 18 of the architecture document states these as invariants;
 * §24.6 requires that each becomes a named, executing test, because a fitness
 * function is not a control until it runs. This interface is the contract:
 * each module implements it against its own wiring.
 *
 * <p><b>A test that cannot fail is not a gate.</b> Each of these must be shown
 * to fail when the control it covers is removed. Two traps found in practice:
 *
 * <ul>
 *   <li>Flipping the last base64url character of a 2048-bit RSA signature only
 *       alters spare bits that decode away, so the token stays valid and the
 *       tamper test passes while asserting nothing. Splice a foreign signature
 *       instead.</li>
 *   <li>A wrong-audience test can pass because the token was rejected for an
 *       unrelated reason - a stricter {@code typ} gate, say - while audience
 *       validation is entirely absent. Assert that the failure names the
 *       audience, and prove the same token succeeds with the correct one.</li>
 * </ul>
 */
public interface SecurityFitnessFunctions {

    // ---- Owned by WP-BE-01 (token issuance) ----

    /** A token whose {@code iss} is not this issuer is rejected. */
    void rejectsTokenWithWrongIssuer() throws Exception;

    /**
     * A token minted under the same issuer and key but for a different
     * audience is rejected. ADR-SEC-008: minting an {@code aud} claim is not
     * the same as validating one.
     */
    void rejectsTokenWithWrongAudience() throws Exception;

    /** An expired token is rejected. */
    void rejectsExpiredToken() throws Exception;

    /** A tampered or unsigned token is rejected. */
    void rejectsUnsignedOrInvalidSignatureToken() throws Exception;

    /** RFC 9068: an access token must declare {@code typ=at+jwt}. */
    void rejectsTokenWithWrongTypHeader() throws Exception;

    /** RFC 9068 requires {@code client_id} on an access token. */
    void rejectsTokenMissingClientId() throws Exception;

    /** ADR-SEC-009: a token issued before the security epoch is rejected mid-life. */
    void rejectsRevokedOrPreSecurityEpochSession() throws Exception;

    /**
     * ADR-SEC-009: revocation propagates within the configured SLA. Correctness
     * and latency are gated together - a control that is eventually right is
     * not a revocation control.
     */
    void revocationBecomesEffectiveWithinConfiguredSla() throws Exception;

    /** ADR-SEC-010: replaying a rotated refresh token revokes the whole family. */
    void rejectsRefreshTokenReuse() throws Exception;

    // ---- Owned by WP-BE-02 (authorization) ----

    /**
     * ADR-SEC-015: cross-tenant access is denied. This is a suite, not a test -
     * guessed ids, tampered tenant headers, stale active-tenant context,
     * multi-tenant subjects, admin paths, and bulk/list/export endpoints, which
     * is where the tenant predicate actually gets forgotten.
     */
    void rejectsCrossTenantResourceAccess() throws Exception;

    /** ADR-SEC-004: an operation requiring high assurance refuses a lower one. */
    void rejectsMissingRequiredAuthenticationLevel() throws Exception;

    /** ADR-SEC-024: a privileged write fails closed when the PDP is unavailable. */
    void deniesPolicyDecisionOnPrivilegedWriteWhenPdpUnavailable() throws Exception;

    /** ADR-SEC-023: the decision, its policy version and a correlation id are recorded. */
    void recordsCorrelatedSecurityDecisionEvent() throws Exception;
}
