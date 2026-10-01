package com.example.zerotrust.resource.authz;

/**
 * The outcome of a policy decision (ADR-SEC-014): ALLOW, DENY, or STEP_UP - the
 * caller may do this, but not yet, because the session has not proved enough.
 * Every decision names the policy and version that produced it, so "which rule
 * allowed this?" is answerable months later.
 */
public record Decision(Outcome outcome, String policyId, int policyVersion, String reason) {

    public enum Outcome { ALLOW, DENY, STEP_UP }

    public static Decision allow(String policyId, int version) {
        return new Decision(Outcome.ALLOW, policyId, version, "permitted");
    }

    public static Decision deny(String policyId, int version, String reason) {
        return new Decision(Outcome.DENY, policyId, version, reason);
    }

    public static Decision stepUp(String policyId, int version, String reason) {
        return new Decision(Outcome.STEP_UP, policyId, version, reason);
    }

    public boolean allowed() {
        return outcome == Outcome.ALLOW;
    }
}
