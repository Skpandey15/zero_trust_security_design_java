package com.example.zerotrust.authserver.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** SHA-256 hash of the opaque token — the raw value is never persisted. */
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    /**
     * All tokens descending from one login share a family. If a rotated
     * (already-used) token is ever presented again, the whole family is
     * revoked — the standard reuse-detection defense against token theft.
     */
    @Column(name = "family_id", nullable = false, length = 36)
    private String familyId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected RefreshToken() {}

    public RefreshToken(String tokenHash, String familyId, User user, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.familyId = familyId;
        this.user = user;
        this.expiresAt = expiresAt;
    }

    public Long getId() { return id; }
    public String getTokenHash() { return tokenHash; }
    public String getFamilyId() { return familyId; }
    public User getUser() { return user; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void revoke() { this.revoked = true; }
    public boolean isActive() { return !revoked && expiresAt.isAfter(Instant.now()); }
}
