package com.example.zerotrust.resource.documents;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * A document that must be approved by someone other than its author.
 *
 * <p>The business rules live HERE, in the aggregate, not in a policy engine
 * (ADR-SEC-013): maker-checker separation and the legal state transitions must
 * hold even when the policy point is unreachable, and they should be testable
 * with nothing else running. They are invariants of the domain, not a matter of
 * who is asking.
 *
 * <p>{@code tenantId} is set once, from a tenant the creator was verified to
 * belong to, and is never taken from a later request: authorization derives a
 * resource's tenant from this stored value (ADR-SEC-015).
 */
@Entity
@Table(name = "documents")
public class Document {

    public enum Status { DRAFT, SUBMITTED, APPROVED }

    /** A business rule was broken. Distinct from "not allowed": the caller may act, but not like this. */
    public static class RuleViolation extends RuntimeException {
        public RuleViolation(String message) { super(message); }
    }

    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "tenant_id", nullable = false, length = 36, updatable = false)
    private String tenantId;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(nullable = false, length = 10000)
    private String body;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Status status;

    @Column(name = "created_by", nullable = false, updatable = false)
    private long createdBy;

    @Column(name = "approved_by")
    private Long approvedBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "approved_at")
    private Instant approvedAt;

    protected Document() {}   // JPA

    public static Document draft(String tenantId, String title, String body, long author) {
        Document d = new Document();
        d.id = UUID.randomUUID().toString();
        d.tenantId = tenantId;
        d.title = title;
        d.body = body;
        d.status = Status.DRAFT;
        d.createdBy = author;
        d.createdAt = Instant.now();
        return d;
    }

    /** Only the author submits their own draft. */
    public void submit(long actor) {
        if (actor != createdBy) {
            throw new RuleViolation("only the author can submit a document");
        }
        if (status != Status.DRAFT) {
            throw new RuleViolation("only a draft can be submitted");
        }
        status = Status.SUBMITTED;
    }

    /**
     * Maker is not checker: the person who wrote it cannot approve it, whatever
     * role or assurance they hold. And only a submitted document can be approved.
     */
    public void approve(long approver) {
        if (approver == createdBy) {
            throw new RuleViolation("a document cannot be approved by its author");
        }
        if (status != Status.SUBMITTED) {
            throw new RuleViolation("only a submitted document can be approved");
        }
        status = Status.APPROVED;
        approvedBy = approver;
        approvedAt = Instant.now();
    }

    public String getId() { return id; }
    public String getTenantId() { return tenantId; }
    public String getTitle() { return title; }
    public String getBody() { return body; }
    public Status getStatus() { return status; }
    public long getCreatedBy() { return createdBy; }
    public Long getApprovedBy() { return approvedBy; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getApprovedAt() { return approvedAt; }
}
