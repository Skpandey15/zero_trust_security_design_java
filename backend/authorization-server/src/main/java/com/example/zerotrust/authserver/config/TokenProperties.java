package com.example.zerotrust.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Token and issuer configuration.
 *
 * <p>ADR-SEC-008: TTL is derived from the threat model and the revocation SLA,
 * not fixed by convention. The defaults here are a starting point to be tuned
 * per route, not a recommendation to adopt unchanged.
 */
@ConfigurationProperties(prefix = "app.token")
public record TokenProperties(
        String issuer,
        String apiAudience,
        String firstPartyClientId,
        Duration accessTokenTtl,
        Duration refreshTokenTtl) {

    public TokenProperties {
        if (issuer == null || issuer.isBlank()) issuer = "http://localhost:9000";
        if (apiAudience == null || apiAudience.isBlank()) apiAudience = "zero-trust-api";
        if (firstPartyClientId == null || firstPartyClientId.isBlank()) {
            firstPartyClientId = "zero-trust-web";
        }
        if (accessTokenTtl == null) accessTokenTtl = Duration.ofMinutes(10);
        if (refreshTokenTtl == null) refreshTokenTtl = Duration.ofDays(7);
    }
}
