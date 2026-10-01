package com.example.zerotrust.resource.authz;

import com.example.zerotrust.resource.authz.AccessExceptions.AuthorizationUnavailable;
import com.example.zerotrust.resource.authz.AccessExceptions.Forbidden;
import com.example.zerotrust.resource.authz.AccessExceptions.NotFound;
import com.example.zerotrust.resource.authz.AccessExceptions.StepUpRequired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The Policy Enforcement Point (ADR-SEC-014). Every protected operation passes
 * through here, and the order is fixed (ADR-SEC-015):
 *
 * <pre>
 *   membership(subject, tenant)?  -- no --> NOT FOUND   (before any role is read)
 *     -> policy: scope + role + assurance
 *        -> ALLOW / DENY / STEP_UP
 * </pre>
 *
 * Membership comes first so a correct role in the WRONG tenant can never reach a
 * permit. Any failure to reach a decision - the membership store or the policy
 * point throwing - is a refusal, never an allow (ADR-SEC-024).
 *
 * <p>Every decision is recorded with the policy that produced it and the
 * request's correlation id (ADR-SEC-023).
 */
@Component
public class PolicyEnforcement {

    private static final Logger decisions = LoggerFactory.getLogger("security.decisions");

    private final MembershipRepository membership;
    private final PolicyDecisionPoint pdp;

    public PolicyEnforcement(MembershipRepository membership, PolicyDecisionPoint pdp) {
        this.membership = membership;
        this.pdp = pdp;
    }

    /** Authorize one action against a tenant the RESOURCE belongs to (derived from stored state). */
    public TenantRole authorize(Subject subject, Action action, String resourceTenantId, String resourceId) {
        TenantRole role;
        try {
            role = membership.roleOf(subject.uid(), resourceTenantId).orElse(null);
        } catch (RuntimeException e) {
            record(subject, action, resourceTenantId, resourceId, "DENY", "n/a", 0, "membership store unavailable");
            throw new AuthorizationUnavailable(e);
        }
        if (role == null) {
            record(subject, action, resourceTenantId, resourceId, "DENY", "membership", 1, "no standing in tenant");
            throw new NotFound();
        }

        Decision decision;
        try {
            decision = pdp.decide(subject, action, role);
        } catch (RuntimeException e) {
            record(subject, action, resourceTenantId, resourceId, "DENY", "n/a", 0, "policy decision point unavailable");
            throw new AuthorizationUnavailable(e);
        }
        record(subject, action, resourceTenantId, resourceId, decision.outcome().name(),
                decision.policyId(), decision.policyVersion(), decision.reason());

        return switch (decision.outcome()) {
            case ALLOW -> role;
            case STEP_UP -> throw new StepUpRequired(decision.reason());
            case DENY -> throw new Forbidden(decision.reason());
        };
    }

    /**
     * The tenants in which {@code action} is permitted - derived from membership, so a
     * list can never include a tenant the subject has no standing in. A list endpoint
     * is where the tenant predicate is most often forgotten.
     */
    public Set<String> permittedTenants(Subject subject, Action action) {
        Map<String, TenantRole> mine;
        try {
            mine = membership.tenantsOf(subject.uid());
        } catch (RuntimeException e) {
            record(subject, action, "*", null, "DENY", "n/a", 0, "membership store unavailable");
            throw new AuthorizationUnavailable(e);
        }
        return mine.entrySet().stream()
                .filter(e -> {
                    try {
                        return pdp.decide(subject, action, e.getValue()).allowed();
                    } catch (RuntimeException ex) {
                        record(subject, action, e.getKey(), null, "DENY", "n/a", 0, "policy decision point unavailable");
                        throw new AuthorizationUnavailable(ex);
                    }
                })
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    /** The tenants the subject belongs to, for display. Fails closed like everything else. */
    public List<MembershipRepository.TenantInfo> visibleTenants(Subject subject) {
        try {
            return membership.describe(subject.uid());
        } catch (RuntimeException e) {
            record(subject, Action.DOCUMENT_READ, "*", null, "DENY", "n/a", 0, "membership store unavailable");
            throw new AuthorizationUnavailable(e);
        }
    }

    private static void record(Subject subject, Action action, String tenant, String resource,
                               String outcome, String policyId, int policyVersion, String reason) {
        decisions.info("event=authz_decision requestId={} subject={} action={} tenant={} resource={} decision={} policy={}@{} reason=\"{}\"",
                MDC.get("requestId"), subject.uid(), action, tenant, resource, outcome, policyId, policyVersion, reason);
    }
}
