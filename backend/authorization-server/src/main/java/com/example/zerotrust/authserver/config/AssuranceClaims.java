package com.example.zerotrust.authserver.config;

import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.ArrayList;
import java.util.List;

/**
 * Records HOW a session authenticated, in the standard way: the {@code amr}
 * claim (RFC 8176) on the ID token and the access token.
 *
 * <p>ADR-SEC-004: assurance is a property of the operation, so the relying
 * party needs to read what this session actually proved. {@code ["pwd"]} is a
 * password alone; {@code ["pwd","otp"]} also proved possession of the
 * authenticator. The claim comes from the authenticated session - never from
 * anything the client sent - and is omitted for machine clients, which have no
 * interactive factors to report.
 */
@Component
public class AssuranceClaims {

    /** Maps the factors a session proved to RFC 8176 amr values. */
    static List<String> amrFor(Authentication principal) {
        if (principal == null) return List.of();
        List<String> amr = new ArrayList<>();
        for (GrantedAuthority a : principal.getAuthorities()) {
            switch (a.getAuthority()) {
                case InteractiveLoginAuthenticationProvider.FACTOR_PASSWORD -> amr.add("pwd");
                case InteractiveLoginAuthenticationProvider.FACTOR_TOTP -> amr.add("otp");
                default -> { }
            }
        }
        return amr;
    }

    /** Adds the amr claim to ID and access tokens. Composed into the one customizer bean. */
    void customize(JwtEncodingContext context) {
        String type = context.getTokenType().getValue();
        boolean carriesAssurance = OidcParameterNames.ID_TOKEN.equals(type)
                || OAuth2TokenType.ACCESS_TOKEN.getValue().equals(type);
        if (!carriesAssurance) return;

        List<String> amr = amrFor(context.getPrincipal());
        if (!amr.isEmpty()) {
            context.getClaims().claim("amr", amr);
        }
    }
}
