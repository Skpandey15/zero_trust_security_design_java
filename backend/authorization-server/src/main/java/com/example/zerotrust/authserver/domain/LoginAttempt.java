package com.example.zerotrust.authserver.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Duration;
import java.time.Instant;

/**
 * Authoritative per-account failed-login counter (one row per account, keyed by
 * email). Unlike counting audit rows, this is a single mutable row that callers
 * update under a pessimistic write lock, so concurrent failures serialize and
 * the count can't be undercounted by a check-then-act race. Once the threshold
 * is hit, {@code lockedUntil} makes the lock sticky for the whole window instead
 * of being recomputed (and re-raced) on every attempt.
 */
@Entity
@Table(name = "login_attempt")
public class LoginAttempt {

    @Id
    @Column(length = 320)
    private String email;

    @Column(name = "failed_count", nullable = false)
    private int failedCount;

    @Column(name = "window_start", nullable = false)
    private Instant windowStart = Instant.now();

    @Column(name = "locked_until")
    private Instant lockedUntil;

    protected LoginAttempt() {}

    public LoginAttempt(String email, Instant now) {
        this.email = email;
        this.windowStart = now;
        this.failedCount = 0;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /** Record one failure, rolling the window over if it has elapsed. */
    public void recordFailure(Instant now, Duration window, int maxFailures) {
        if (windowStart.plus(window).isBefore(now)) {   // window elapsed → fresh start
            windowStart = now;
            failedCount = 0;
            lockedUntil = null;
        }
        failedCount++;
        if (failedCount >= maxFailures) {
            lockedUntil = now.plus(window);
        }
    }

    /**
     * Failures inside the CURRENT window. recordFailure() rolls the window over
     * lazily, so a stale failedCount can outlive its window whenever no further
     * failure arrives -- readers must not use the raw field for risk decisions.
     */
    public int activeFailedCount(Instant now, Duration window) {
        return windowStart.plus(window).isBefore(now) ? 0 : failedCount;
    }

    /** A successful login clears the counter. */
    public void reset(Instant now) {
        failedCount = 0;
        windowStart = now;
        lockedUntil = null;
    }

    public String getEmail() { return email; }
    public int getFailedCount() { return failedCount; }
    public Instant getLockedUntil() { return lockedUntil; }
}
