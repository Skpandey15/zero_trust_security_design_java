package com.example.zerotrust.authserver.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * A tenant: the unit of data isolation (ADR-SEC-015). Resources belong to
 * exactly one; who may act in it is recorded in {@link TenantMembership}.
 */
@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false, length = 160)
    private String name;

    @Column(nullable = false, length = 16)
    private String status = "ACTIVE";

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected Tenant() {}   // JPA

    public Tenant(String name) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getStatus() { return status; }
}
