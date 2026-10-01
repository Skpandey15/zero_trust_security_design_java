package com.example.zerotrust.authserver.service;

import com.example.zerotrust.authserver.domain.LoginAudit;
import com.example.zerotrust.authserver.domain.RefreshToken;
import com.example.zerotrust.authserver.domain.Tenant;
import com.example.zerotrust.authserver.domain.TenantMembership;
import com.example.zerotrust.authserver.domain.Role;
import com.example.zerotrust.authserver.domain.User;
import com.example.zerotrust.authserver.dto.AuthDtos.*;
import com.example.zerotrust.authserver.config.SecurityMetrics;
import com.example.zerotrust.authserver.repository.LoginAuditRepository;
import com.example.zerotrust.authserver.repository.RefreshTokenRepository;
import com.example.zerotrust.authserver.repository.TenantMembershipRepository;
import com.example.zerotrust.authserver.repository.TenantRepository;
import com.example.zerotrust.authserver.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Locale;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    /** Dedicated channel for auditable security events — easy to route/alert on. */
    private static final Logger secLog = LoggerFactory.getLogger("security.events");

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginAuditRepository loginAuditRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final TotpService totpService;
    private final LoginProtectionService loginProtection;
    private final SecurityMetrics metrics;
    private final TenantRepository tenants;
    private final TenantMembershipRepository memberships;

    /**
     * A throwaway Argon2 hash verified when the account doesn't exist, so a
     * missing user costs the same as a wrong password — no timing oracle for
     * account enumeration.
     */
    private final String dummyHash;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       LoginAuditRepository loginAuditRepository,
                       PasswordEncoder passwordEncoder,
                       TokenService tokenService,
                       TotpService totpService,
                       LoginProtectionService loginProtection,
                       SecurityMetrics metrics,
                       TenantRepository tenants,
                       TenantMembershipRepository memberships) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.loginAuditRepository = loginAuditRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.totpService = totpService;
        this.loginProtection = loginProtection;
        this.metrics = metrics;
        this.tenants = tenants;
        this.memberships = memberships;
        this.dummyHash = passwordEncoder.encode("timing-equalizer-not-a-real-password");
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String email = normalize(request.email());
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyUsedException(email);
        }
        User user = new User(
                email,
                passwordEncoder.encode(request.password()),
                request.displayName(),
                EnumSet.of(Role.USER));
        User saved = userRepository.save(user);
        UserResponse created = toResponse(saved);
        loginProtection.initAccount(email);   // seed the lockout counter row

        // Everyone starts with a workspace of their own and is its OWNER. Membership is
        // explicit (ADR-SEC-015): without a row a person has standing nowhere. Joining
        // someone else's tenant is a separate, deliberate grant - never implied by this.
        Tenant workspace = tenants.save(new Tenant(request.displayName().trim() + "'s workspace"));
        memberships.save(new TenantMembership(saved.getId(), workspace.getId(), "OWNER"));
        secLog.info("event=user_registered userId={} email={}", created.id(), created.email());
        return created;
    }

    /** A user whose credentials (and second factor, where enrolled) have been verified. */
    public record VerifiedLogin(User user, boolean otpUsed) {}

    /**
     * Zero-trust login pipeline, shared by every way of signing in:
     *   1. brute-force / lockout gate (per IP and per account)
     *   2. password verification (Argon2id) - single user load, constant-time on miss
     *   3. enabled check (a disabled account can never authenticate)
     *   4. second factor (TOTP) with single-use replay protection when MFA is on
     *   5. audit trail either way
     *
     * <p>{@code riskStepUp} is the one difference between callers. The token API
     * can answer a risky login with an enrolment-only token, so the demand is
     * satisfiable; the interactive sign-in page cannot, so it passes false and
     * lets a password-only account in at password assurance (the {@code amr}
     * claim says so) rather than lock out someone with no way to enrol.
     */
    @Transactional
    public VerifiedLogin verifyCredentials(String rawEmail, String password, String otpCode,
                                           String ip, String userAgent, boolean riskStepUp) {
        String email = normalize(rawEmail);
        loginProtection.assertNotBlocked(email, ip);

        User user = userRepository.findByEmail(email).orElse(null);
        boolean passwordOk = user != null
                ? passwordEncoder.matches(password, user.getPasswordHash())
                : passwordEncoder.matches(password, dummyHash);

        if (user == null || !user.isEnabled() || !passwordOk) {
            loginProtection.recordFailure(email, ip, userAgent);
            secLog.warn("event=login_failed reason=bad_credentials email={} ip={}", email, ip);
            metrics.loginFailure("bad_credentials");
            throw new BadCredentialsException("Invalid email or password");
        }

        boolean otpUsed = false;
        if (user.isMfaEnabled()) {
            if (otpCode == null || otpCode.isBlank()) {
                secLog.info("event=login_mfa_challenge email={} ip={}", email, ip);
                throw new MfaRequiredException();
            }
            long step = totpService.verifyAndGetStep(user.getMfaSecret(), otpCode);
            Long lastUsed = user.getMfaLastUsedStep();
            if (step < 0 || (lastUsed != null && step <= lastUsed)) {
                loginProtection.recordFailure(email, ip, userAgent);
                secLog.warn("event=login_failed reason=bad_otp email={} ip={}", email, ip);
                metrics.loginFailure("bad_otp");
                throw new BadCredentialsException("Invalid one-time code");
            }
            user.setMfaLastUsedStep(step);   // spend this step so the code can't be replayed
            userRepository.save(user);
            otpUsed = true;
        } else if (riskStepUp && loginProtection.isHighRisk(email, ip)) {
            // Adaptive auth: a risky login (guessing burst / new device) on an
            // account with no second factor is refused pending MFA enrolment,
            // rather than trusting a password alone.
            secLog.warn("event=login_stepup_required reason=risk email={} ip={}", email, ip);
            metrics.loginFailure("step_up_required");
            // Password was correct, so hand back an enrolment-only token rather than a
            // bare refusal: the user must be able to satisfy the demand we just made.
            throw new StepUpRequiredException(
                    tokenService.createStepUpToken(user), tokenService.stepUpTtlSeconds());
        }

        loginAuditRepository.save(new LoginAudit(email, ip, userAgent, true));
        loginProtection.recordSuccess(email);   // clear the failure counter
        secLog.info("event=login_success userId={} email={} ip={} mfa={}",
                user.getId(), user.getEmail(), ip, otpUsed);
        metrics.loginSuccess();
        return new VerifiedLogin(user, otpUsed);
    }

    /** Token-API login: verify, then mint an access token and a refresh-token family. */
    @Transactional
    public TokenResponse login(LoginRequest request, String ip, String userAgent) {
        User user = verifyCredentials(request.email(), request.password(), request.otpCode(),
                ip, userAgent, true).user();
        return new TokenResponse(
                tokenService.createAccessToken(user),
                tokenService.createRefreshTokenFamily(user),
                "Bearer",
                tokenService.accessTokenTtlSeconds());
    }

    /**
     * Rotation with reuse detection. An already-rotated token being presented
     * again is treated as theft: the entire family is revoked and the caller
     * must re-authenticate. Rotation is claimed atomically so two concurrent
     * refreshes of the same token can't both succeed.
     */
    @Transactional
    public TokenResponse refresh(RefreshRequest request) {
        var stored = tokenService.findAny(request.refreshToken())
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        // Already rotated → genuine reuse/theft: burn the whole family.
        if (stored.isRevoked()) {
            revokeFamilyAsReuse(stored);
            throw new BadCredentialsException("Refresh token reuse detected. Please sign in again.");
        }

        // Never rotated but past its TTL → benign expiry, NOT theft.
        if (!stored.getExpiresAt().isAfter(Instant.now())) {
            throw new BadCredentialsException("Refresh token expired. Please sign in again.");
        }

        // Atomically claim rotation. If we lose the race (0 rows updated) another
        // request already rotated this exact token → treat as reuse.
        if (!tokenService.claimForRotation(stored.getId())) {
            revokeFamilyAsReuse(stored);
            throw new BadCredentialsException("Refresh token reuse detected. Please sign in again.");
        }

        User user = stored.getUser();
        if (!user.isEnabled()) {
            // Disabled mid-session: stop minting access tokens and kill the family.
            // Use the REQUIRES_NEW revoke so it survives the rollback from the throw.
            tokenService.revokeFamily(stored.getFamilyId());
            throw new DisabledException("Account is disabled");
        }
        return new TokenResponse(
                tokenService.createAccessToken(user),
                tokenService.rotateWithinFamily(user, stored.getFamilyId()),
                "Bearer",
                tokenService.accessTokenTtlSeconds());
    }

    private void revokeFamilyAsReuse(RefreshToken stored) {
        secLog.error("event=refresh_token_reuse userId={} email={} family={} — revoking family",
                stored.getUser().getId(), stored.getUser().getEmail(), stored.getFamilyId());
        metrics.tokenReuseDetected();
        tokenService.revokeFamily(stored.getFamilyId());
    }

    /** Revokes every active refresh token for the user (logout everywhere). */
    @Transactional
    public void logout(String email) {
        userRepository.findByEmailIgnoreCase(email)
                .ifPresent(user -> {
                    refreshTokenRepository.revokeAllForUser(user.getId());
                    // Continuous verification: also invalidate every already-issued
                    // access token immediately (not just refresh tokens).
                    user.setTokenValidAfter(Instant.now());
                    userRepository.save(user);
                    secLog.info("event=logout_all userId={} email={}", user.getId(), user.getEmail());
                });
    }

    /** Admin action: disable an account AND immediately revoke its refresh tokens. */
    @Transactional
    public UserResponse disableUser(Long id) {
        User user = userRepository.findById(id).orElseThrow();
        user.setEnabled(false);
        user.setTokenValidAfter(Instant.now());   // kill live access tokens immediately
        userRepository.save(user);
        refreshTokenRepository.revokeAllForUser(user.getId());
        secLog.info("event=user_disabled userId={} email={} — refresh tokens revoked",
                user.getId(), user.getEmail());
        return toResponse(user);
    }

    // ---------- MFA lifecycle ----------

    /** Step 1: generate a secret; MFA is not active until a code is confirmed. */
    @Transactional
    public MfaSetupResponse startMfaSetup(String email) {
        User user = userRepository.findByEmailIgnoreCase(email).orElseThrow();
        // Guard against downgrade: overwriting the secret / clearing the flag on an
        // already-protected account would silently strip the second factor. Require
        // an explicit disable (with credentials) before re-enrolling.
        if (user.isMfaEnabled()) {
            throw new MfaAlreadyEnabledException();
        }
        String secret = totpService.generateSecret();
        user.setMfaSecret(secret);
        user.setMfaEnabled(false);
        user.setMfaLastUsedStep(null);
        userRepository.save(user);
        secLog.info("event=mfa_setup_started userId={} email={}", user.getId(), user.getEmail());
        return new MfaSetupResponse(secret, totpService.provisioningUri(secret, user.getEmail()));
    }

    /** Whether the account has a second factor switched on. */
    @Transactional(readOnly = true)
    public boolean isMfaEnabled(String email) {
        return userRepository.findByEmailIgnoreCase(email).map(User::isMfaEnabled).orElse(false);
    }

    /** The enrolment in progress, if one was started and not yet confirmed. */
    @Transactional(readOnly = true)
    public java.util.Optional<MfaSetupResponse> pendingMfaSetup(String email) {
        return userRepository.findByEmailIgnoreCase(email)
                .filter(u -> !u.isMfaEnabled() && u.getMfaSecret() != null)
                .map(u -> new MfaSetupResponse(u.getMfaSecret(),
                        totpService.provisioningUri(u.getMfaSecret(), u.getEmail())));
    }

    /** Step 2: confirm a valid code from the authenticator app to activate MFA. */
    @Transactional
    public void activateMfa(String email, String code) {
        User user = userRepository.findByEmailIgnoreCase(email).orElseThrow();
        if (user.getMfaSecret() == null || !totpService.verify(user.getMfaSecret(), code)) {
            throw new BadCredentialsException("Invalid one-time code");
        }
        user.setMfaEnabled(true);
        user.setTokenValidAfter(Instant.now());   // fresh trust boundary: old access tokens die too
        userRepository.save(user);
        // fresh trust boundary: all previously issued refresh tokens die
        refreshTokenRepository.revokeAllForUser(user.getId());
        secLog.info("event=mfa_activated userId={} email={}", user.getId(), user.getEmail());
        metrics.mfaActivated();
    }

    private static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    public static UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                user.getRoles().stream().map(Enum::name).collect(Collectors.toSet()),
                user.isMfaEnabled(),
                user.getCreatedAt());
    }

    public static class EmailAlreadyUsedException extends RuntimeException {
        public EmailAlreadyUsedException(String email) {
            super("Email already registered: " + email);
        }
    }

    public static class MfaRequiredException extends RuntimeException {
        public MfaRequiredException() {
            super("Multi-factor code required");
        }
    }

    public static class MfaAlreadyEnabledException extends RuntimeException {
        public MfaAlreadyEnabledException() {
            super("MFA is already enabled for this account");
        }
    }

    /** Risky login on an account without a second factor — MFA enrolment required. */
    public static class StepUpRequiredException extends RuntimeException {
        private final String stepUpToken;
        private final long expiresInSeconds;

        public StepUpRequiredException(String stepUpToken, long expiresInSeconds) {
            super("This login looks risky. Enrol multi-factor authentication to continue.");
            this.stepUpToken = stepUpToken;
            this.expiresInSeconds = expiresInSeconds;
        }

        public String getStepUpToken() { return stepUpToken; }
        public long getExpiresInSeconds() { return expiresInSeconds; }
    }
}
