package com.example.zerotrust.resource.authz;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Who may act in which tenant, and as what. Explicit and relational: the ABSENCE
 * of a row is denial - there is no implicit or inherited membership and no
 * "admin sees everything" path (ADR-SEC-015).
 *
 * <p>This is authoritative server-side state. Nothing the caller sends - header,
 * body, query string or token claim - feeds it.
 */
public interface MembershipRepository {

    /** The role {@code uid} holds in {@code tenantId}, or empty if they have no standing there. */
    Optional<TenantRole> roleOf(long uid, String tenantId);

    /** Every tenant {@code uid} belongs to, with the role held in each. */
    Map<String, TenantRole> tenantsOf(long uid);

    /** The same, with each tenant's display name, for showing the subject where they can act. */
    List<TenantInfo> describe(long uid);

    /** A tenant the subject belongs to. Derived from membership: never a lookup by a supplied id. */
    record TenantInfo(String id, String name, TenantRole role) {}
}
