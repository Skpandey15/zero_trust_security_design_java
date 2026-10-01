package com.example.zerotrust.resource.authz;

import java.util.Optional;
import java.util.Set;

/**
 * The role a subject holds IN ONE TENANT. A role is meaningful only together
 * with the tenant it was granted in: the same person can be an approver in one
 * tenant and a viewer in another, and holding the right role in the wrong tenant
 * must never reach a permit (ADR-SEC-015).
 */
public enum TenantRole {
    VIEWER(Set.of(Action.DOCUMENT_READ)),
    MEMBER(Set.of(Action.DOCUMENT_READ, Action.DOCUMENT_CREATE, Action.DOCUMENT_SUBMIT)),
    APPROVER(Set.of(Action.DOCUMENT_READ, Action.DOCUMENT_APPROVE)),
    OWNER(Set.of(Action.DOCUMENT_READ, Action.DOCUMENT_CREATE, Action.DOCUMENT_SUBMIT, Action.DOCUMENT_APPROVE));

    private final Set<Action> permitted;

    TenantRole(Set<Action> permitted) {
        this.permitted = permitted;
    }

    public boolean permits(Action action) {
        return permitted.contains(action);
    }

    /** Unknown role names in the data parse to empty, which means no permissions - never a default grant. */
    public static Optional<TenantRole> parse(String name) {
        try {
            return Optional.of(valueOf(name.trim().toUpperCase()));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }
}
