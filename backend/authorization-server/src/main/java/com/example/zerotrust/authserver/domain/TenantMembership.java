package com.example.zerotrust.authserver.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

/**
 * Explicit, relational membership: which subject may act in which tenant, and as
 * what. The absence of a row is denial - there is no implicit or inherited
 * membership and no "admin sees everything" path (ADR-SEC-015). The Resource
 * Server reads this table (and only this one of the identity schema) to decide.
 */
@Entity
@Table(name = "subject_tenant_membership")
@IdClass(TenantMembership.Key.class)
public class TenantMembership {

    public record Key(Long userId, String tenantId) implements Serializable {}

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Id
    @Column(name = "tenant_id", length = 36)
    private String tenantId;

    @Column(nullable = false, length = 64)
    private String role;

    @Column(name = "granted_at", nullable = false)
    private Instant grantedAt = Instant.now();

    protected TenantMembership() {}   // JPA

    public TenantMembership(Long userId, String tenantId, String role) {
        this.userId = Objects.requireNonNull(userId);
        this.tenantId = Objects.requireNonNull(tenantId);
        this.role = Objects.requireNonNull(role);
    }

    public Long getUserId() { return userId; }
    public String getTenantId() { return tenantId; }
    public String getRole() { return role; }
}
