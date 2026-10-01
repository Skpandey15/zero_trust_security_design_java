package com.example.zerotrust.resource.authz;

/**
 * Decides whether a subject may perform an action, given the role they hold in
 * the resource's tenant (ADR-SEC-014).
 *
 * <p>Membership is resolved BEFORE this is called and is passed in as {@code role}:
 * a decision is never asked for a subject with no standing in the tenant. This
 * interface is the seam where a remote policy service can replace
 * {@link LocalPolicyDecisionPoint}; the enforcement point treats any failure to
 * obtain a decision as DENY.
 *
 * <p>Domain invariants (maker is not checker, valid state transitions) are NOT
 * policy and are not decided here: they live in the aggregate so they hold even
 * when this component is unavailable (ADR-SEC-013).
 */
public interface PolicyDecisionPoint {

    Decision decide(Subject subject, Action action, TenantRole role);
}
