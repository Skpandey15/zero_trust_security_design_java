package com.example.zerotrust.authserver.service;

import com.example.zerotrust.authserver.config.SecurityMetrics;
import com.example.zerotrust.authserver.domain.LoginAttempt;
import com.example.zerotrust.authserver.domain.LoginAudit;
import com.example.zerotrust.authserver.repository.LoginAttemptRepository;
import com.example.zerotrust.authserver.repository.LoginAuditRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Brute-force protection — assume every login attempt may be hostile:
 *  - per-account lockout: 5 failed attempts within 15 minutes locks the account,
 *    tracked in a dedicated {@link LoginAttempt} row updated under a pessimistic
 *    write lock (race-free and shared across instances via the DB)
 *  - per-IP throttle: max 20 attempts per 15 minutes from one address
 *    (in-memory; swap for Redis/Bucket4j when running multiple nodes)
 */
@Service
public class LoginProtectionService {

    private static final Logger secLog = LoggerFactory.getLogger("security.events");

    private static final int MAX_FAILURES_PER_ACCOUNT = 5;
    private static final int MAX_ATTEMPTS_PER_IP = 20;
    /** Failures that make a login "risky" enough to demand step-up (below the lockout threshold). */
    private static final int STEP_UP_FAILURE_THRESHOLD = 3;
    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final LoginAuditRepository auditRepository;
    private final LoginAttemptRepository attemptRepository;
    private final Map<String, WindowCounter> ipAttempts = new ConcurrentHashMap<>();
    private final SecurityMetrics metrics;

    public LoginProtectionService(LoginAuditRepository auditRepository,
                                  LoginAttemptRepository attemptRepository,
                                  SecurityMetrics metrics) {
        this.auditRepository = auditRepository;
        this.attemptRepository = attemptRepository;
        this.metrics = metrics;
    }

    public void assertNotBlocked(String email, String ip) {
        if (ip != null) {
            WindowCounter counter = ipAttempts.compute(ip, (k, existing) ->
                    (existing == null || existing.expired()) ? new WindowCounter() : existing);
            if (counter.increment() > MAX_ATTEMPTS_PER_IP) {
                secLog.warn("event=ip_throttled ip={}", ip);
                metrics.ipThrottled();
                throw new TooManyAttemptsException("Too many login attempts from this address. Try again later.");
            }
        }
        // A plain read is enough for the gate: the lock is sticky (lockedUntil) once
        // set, so we don't recompute a race-prone count here — the authoritative
        // increment happens under a write lock in recordFailure().
        boolean locked = attemptRepository.findById(email)
                .map(a -> a.isLocked(Instant.now()))
                .orElse(false);
        if (locked) {
            secLog.warn("event=login_rejected reason=account_locked email={}", email);
            throw new TooManyAttemptsException("Account temporarily locked after repeated failures. Try again later.");
        }
    }

    /** Create the counter row for a new account (called once at registration). */
    @Transactional
    public void initAccount(String email) {
        attemptRepository.save(new LoginAttempt(email, Instant.now()));
    }

    /**
     * Record a failure: write the audit row AND increment the counter under a
     * write lock. Runs in its own transaction so the increment/audit survive the
     * rollback of the failed login. The counter is only touched for accounts that
     * exist (a seeded row) — failures against unknown emails are audited but need
     * no lockout state (the per-IP throttle covers spray attacks).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String email, String ip, String userAgent) {
        auditRepository.save(new LoginAudit(email, ip, userAgent, false));
        Instant now = Instant.now();
        attemptRepository.findForUpdate(email).ifPresent(attempt -> {
            boolean wasLocked = attempt.isLocked(now);
            attempt.recordFailure(now, WINDOW, MAX_FAILURES_PER_ACCOUNT);
            if (!wasLocked && attempt.isLocked(now)) {   // just crossed the threshold
                secLog.warn("event=account_locked email={} failures={}", email, attempt.getFailedCount());
                metrics.accountLockout();
            }
        });
    }

    /** A successful login clears the account's failure counter. */
    @Transactional
    public void recordSuccess(String email) {
        attemptRepository.findForUpdate(email).ifPresent(attempt -> attempt.reset(Instant.now()));
    }

    /**
     * Adaptive risk signal for a password-verified login: HIGH when there have
     * been several recent failures (a guessing burst in progress), OR when an
     * established account signs in from an IP it has never succeeded from before
     * (new device/location). Callers use this to demand a step-up (MFA).
     */
    public boolean isHighRisk(String email, String ip) {
        Instant now = Instant.now();
        int failures = attemptRepository.findById(email)
                .map(a -> a.activeFailedCount(now, WINDOW))
                .orElse(0);
        if (failures >= STEP_UP_FAILURE_THRESHOLD) {
            return true;
        }
        boolean established = auditRepository.existsByEmailAndSuccessTrue(email);
        boolean knownIp = ip != null && auditRepository.existsByEmailAndIpAddressAndSuccessTrue(email, ip);
        return established && !knownIp;
    }

    /**
     * Evict expired per-IP counters so the map can't grow without bound. Without
     * this, a stale entry is only replaced when the same IP is seen again, so a
     * spread of distinct source IPs would leak memory indefinitely.
     */
    @Scheduled(fixedDelay = 5 * 60 * 1000L)
    void pruneExpiredIpCounters() {
        ipAttempts.values().removeIf(WindowCounter::expired);
    }

    private static final class WindowCounter {
        private final Instant start = Instant.now();
        private final AtomicInteger count = new AtomicInteger();

        int increment() { return count.incrementAndGet(); }
        boolean expired() { return start.plus(WINDOW).isBefore(Instant.now()); }
    }

    public static class TooManyAttemptsException extends RuntimeException {
        public TooManyAttemptsException(String message) {
            super(message);
        }
    }
}
