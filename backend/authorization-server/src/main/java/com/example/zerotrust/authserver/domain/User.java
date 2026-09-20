package com.example.zerotrust.authserver.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 320)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "display_name", nullable = false, length = 120)
    private String displayName;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled = false;

    /** Base32 TOTP secret; present once MFA setup has started. */
    @Column(name = "mfa_secret", length = 64)
    private String mfaSecret;

    /**
     * Highest TOTP time-step already accepted for a login. A code is rejected if
     * its step is not strictly greater, so an observed code cannot be replayed
     * within its ±1-step validity window.
     */
    @Column(name = "mfa_last_used_step")
    private Long mfaLastUsedStep;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    /**
     * Continuous-verification watermark: access tokens issued before this instant
     * are rejected on every request. Bumped on logout-all, account disable, and
     * MFA activation so a live token can be revoked mid-life.
     */
    @Column(name = "token_valid_after")
    private Instant tokenValidAfter;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role", nullable = false)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = EnumSet.of(Role.USER);

    protected User() {}

    public User(String email, String passwordHash, String displayName, Set<Role> roles) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.displayName = displayName;
        this.roles = roles;
    }

    public Long getId() { return id; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public String getDisplayName() { return displayName; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isMfaEnabled() { return mfaEnabled; }
    public void setMfaEnabled(boolean mfaEnabled) { this.mfaEnabled = mfaEnabled; }
    public String getMfaSecret() { return mfaSecret; }
    public void setMfaSecret(String mfaSecret) { this.mfaSecret = mfaSecret; }
    public Long getMfaLastUsedStep() { return mfaLastUsedStep; }
    public void setMfaLastUsedStep(Long mfaLastUsedStep) { this.mfaLastUsedStep = mfaLastUsedStep; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getTokenValidAfter() { return tokenValidAfter; }
    public void setTokenValidAfter(Instant tokenValidAfter) { this.tokenValidAfter = tokenValidAfter; }
    public Set<Role> getRoles() { return roles; }
}
