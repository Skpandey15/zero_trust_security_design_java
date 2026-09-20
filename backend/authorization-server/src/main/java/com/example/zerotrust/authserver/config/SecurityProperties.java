package com.example.zerotrust.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

@ConfigurationProperties(prefix = "app.security")
public record SecurityProperties(
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        RSAPrivateKey rsaPrivateKey,   // optional — Spring converts a PEM location automatically
        RSAPublicKey rsaPublicKey,
        /** Secure flag on the refresh cookie; true everywhere except local http dev. */
        Boolean cookieSecure,
        /** OIDC/JWT issuer identifier (a URL). Shared by the OAuth2 authorization server
         *  and the custom /api/auth tokens so both validate under one issuer. */
        String issuer,
        /** Audience of the custom /api/auth access tokens; the API chain requires it. */
        String apiAudience,
        /** client_id stamped on first-party /api/auth tokens (required by RFC 9068). */
        String firstPartyClientId) {

    public SecurityProperties {
        if (accessTokenTtl == null) accessTokenTtl = Duration.ofMinutes(15);
        if (refreshTokenTtl == null) refreshTokenTtl = Duration.ofDays(7);
        if (cookieSecure == null) cookieSecure = true;
        if (issuer == null || issuer.isBlank()) issuer = "http://localhost:8080";
        if (apiAudience == null || apiAudience.isBlank()) apiAudience = "auth-service-api";
        if (firstPartyClientId == null || firstPartyClientId.isBlank()) {
            firstPartyClientId = "auth-service-direct";
        }
    }
}
