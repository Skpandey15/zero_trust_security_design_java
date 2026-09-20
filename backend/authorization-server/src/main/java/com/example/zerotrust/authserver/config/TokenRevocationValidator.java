package com.example.zerotrust.authserver.config;

import com.example.zerotrust.authserver.repository.UserRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

/**
 * Continuous verification. A plain stateless JWT is trusted for its whole
 * lifetime; this re-checks it against current user state on EVERY request and
 * rejects it when:
 *   - the user no longer exists, or
 *   - the account is disabled (revocation takes effect immediately, not at expiry), or
 *   - it was issued before the user's tokenValidAfter watermark (bumped on
 *     logout-all / disable / MFA activation).
 * This is the DB lookup per request that "never trust, always verify" implies.
 */
public class TokenRevocationValidator implements OAuth2TokenValidator<Jwt> {

    private final UserRepository users;

    public TokenRevocationValidator(UserRepository users) {
        this.users = users;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Object uidClaim = jwt.getClaim("uid");
        if (!(uidClaim instanceof Number uid)) {
            // No uid → not one of our custom /api/auth access tokens (e.g. an OIDC
            // token issued by the authorization server). Continuous verification
            // doesn't apply; leave validation to the standard issuer/signature checks.
            return OAuth2TokenValidatorResult.success();
        }
        var user = users.findById(uid.longValue()).orElse(null);
        if (user == null) {
            return reject("user no longer exists");
        }
        if (!user.isEnabled()) {
            return reject("account disabled");
        }
        Instant validAfter = user.getTokenValidAfter();
        Instant issuedAt = jwt.getIssuedAt();
        // Compare at second granularity: JWT iat is epoch-seconds, so a token
        // issued in the same second as the watermark is treated as still valid
        // (lets a user log back in immediately after logging out).
        if (validAfter != null && issuedAt != null
                && issuedAt.getEpochSecond() < validAfter.getEpochSecond()) {
            return reject("token revoked");
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidatorResult reject(String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", description, null));
    }
}
