package com.example.zerotrust.resource.authz;

/**
 * What a caller is trying to do. The decision function is
 * {@code subject + action + resource + tenant + context}, not
 * {@code subject + role} (ADR-SEC-013).
 */
public enum Action {
    DOCUMENT_READ("documents.read", false),
    DOCUMENT_CREATE("documents.write", true),
    DOCUMENT_SUBMIT("documents.write", true),
    /** Sensitive: needs a second factor, and the domain forbids approving your own work. */
    DOCUMENT_APPROVE("documents.approve", true);

    private final String requiredScope;
    private final boolean write;

    Action(String requiredScope, boolean write) {
        this.requiredScope = requiredScope;
        this.write = write;
    }

    /** The scope the access token must carry. A coarse gate - never the authorization itself. */
    public String requiredScope() { return requiredScope; }

    public boolean isWrite() { return write; }
}
