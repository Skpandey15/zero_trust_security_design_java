package com.example.zerotrust.resource.authz;

import org.springframework.stereotype.Component;

/**
 * Policy {@code documents@1}, evaluated in-process. Three layers, each answering
 * a different question, none sufficient alone (ADR-SEC-013):
 *
 * <ol>
 *   <li><b>Scope</b>: does the token carry what this class of operation needs? A
 *       coarse gate: a token minted for reading cannot write.</li>
 *   <li><b>RBAC</b>: does the role held IN THIS TENANT permit the action?</li>
 *   <li><b>ABAC</b>: does the session meet the assurance the operation demands?
 *       Approving needs a proved second factor; if it was not, the answer is
 *       STEP_UP (prove more) rather than DENY (never).</li>
 * </ol>
 */
@Component
public class LocalPolicyDecisionPoint implements PolicyDecisionPoint {

    static final String POLICY_ID = "documents";
    static final int POLICY_VERSION = 1;

    @Override
    public Decision decide(Subject subject, Action action, TenantRole role) {
        if (!subject.hasScope(action.requiredScope())) {
            return Decision.deny(POLICY_ID, POLICY_VERSION, "token lacks scope " + action.requiredScope());
        }
        if (!role.permits(action)) {
            return Decision.deny(POLICY_ID, POLICY_VERSION, "role " + role + " does not permit " + action);
        }
        if (action == Action.DOCUMENT_APPROVE && !subject.provedSecondFactor()) {
            return Decision.stepUp(POLICY_ID, POLICY_VERSION, "approval requires a second factor");
        }
        return Decision.allow(POLICY_ID, POLICY_VERSION);
    }
}
