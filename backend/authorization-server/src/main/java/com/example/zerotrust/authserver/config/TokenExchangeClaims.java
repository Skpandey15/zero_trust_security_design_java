package com.example.zerotrust.authserver.config;

import com.example.zerotrust.authserver.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Shapes the access token minted by RFC 8693 token exchange (ADR-SEC-016).
 *
 * <p>The BFF holds one broad login token and never lets it leave. For each call
 * to an API it exchanges that token for a NEW one that is:
 * <ul>
 *   <li><b>audience-restricted</b> to the API being called, and only to an API on
 *       the allow-list - a caller cannot ask for an audience of its choosing, so
 *       a compromised BFF cannot mint tokens for services it has no business
 *       with;</li>
 *   <li><b>down-scoped</b> to what that one call needs (the framework refuses
 *       scopes the subject token does not already hold, so exchange can only
 *       narrow, never widen);</li>
 *   <li>an RFC 9068 {@code at+jwt} with {@code client_id}, so the Resource
 *       Server's strict validator accepts it and nothing else does;</li>
 *   <li>carrying {@code uid} so the Resource Server can check tenant membership
 *       by identity, and {@code amr} (added by {@link AssuranceClaims}) so it can
 *       demand a second factor for a sensitive operation.</li>
 * </ul>
 * There is no fallback: a request that fails any of this is an error, never a
 * quietly broader token (ADR-SEC-016).
 */
@Component
public class TokenExchangeClaims {

    private final UserRepository users;
    private final Set<String> allowedAudiences;

    public TokenExchangeClaims(UserRepository users,
                               @Value("${app.oidc.exchange-audiences:zero-trust-api}") List<String> allowedAudiences) {
        this.users = users;
        this.allowedAudiences = Set.copyOf(allowedAudiences.stream().map(String::trim).toList());
    }

    void customize(JwtEncodingContext context) {
        if (!AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())
                || !OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }

        Set<String> requested = context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken t
                ? t.getAudiences() : Set.of();
        // Exactly the audiences asked for, every one of them allowed, and at least one:
        // an exchange with no audience would otherwise default to the client itself.
        if (requested.isEmpty() || !allowedAudiences.containsAll(requested)) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_target",
                    "The requested audience is not one this client may exchange for.", null));
        }

        // Exchange may only NARROW. The framework checks the requested scopes against
        // what the CLIENT is registered for, not against what THIS login token holds, so
        // without this a token granted only documents.read could be traded for
        // documents.approve. That would turn exchange into a privilege escalator.
        OAuth2Authorization subjectAuthorization = context.getAuthorization();
        if (subjectAuthorization == null
                || !subjectAuthorization.getAuthorizedScopes().containsAll(context.getAuthorizedScopes())) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_scope",
                    "The requested scope exceeds the scope of the subject token.", null));
        }

        // RFC 9068: the JOSE type is what stops an access token being replayed as an
        // ID token, or an ID token being presented as an access token.
        context.getJwsHeader().type("at+jwt");

        var claims = context.getClaims();
        claims.audience(new ArrayList<>(requested));
        claims.claim("client_id", context.getRegisteredClient().getClientId());

        // Subject identity for membership lookups. The login principal is the email.
        String email = context.getPrincipal().getName();
        users.findByEmailIgnoreCase(email).ifPresent(u -> claims.claim("uid", u.getId()));
    }
}
