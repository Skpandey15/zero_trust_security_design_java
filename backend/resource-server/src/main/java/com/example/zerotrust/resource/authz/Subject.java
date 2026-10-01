package com.example.zerotrust.resource.authz;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Who is calling, as established by the validated access token.
 *
 * <p>{@code uid} identifies the subject for membership lookups. It says WHO is
 * asking; it says nothing about WHICH TENANT, and nothing here carries a tenant:
 * a tenant arriving from the caller is context, never proof (ADR-SEC-015).
 *
 * <p>{@code amr} is what the session proved when the user signed in (RFC 8176).
 */
public record Subject(long uid, String sub, Set<String> scopes, Set<String> amr) {

    private static final String SECOND_FACTOR = "otp";

    public static Subject from(Jwt jwt) {
        Object uid = jwt.getClaim("uid");
        if (!(uid instanceof Number n)) {
            // No identity to look membership up by: nothing downstream can safely proceed.
            throw new IllegalArgumentException("access token has no uid claim");
        }
        List<String> amr = jwt.getClaimAsStringList("amr");
        return new Subject(n.longValue(), jwt.getSubject(), scopesOf(jwt.getClaim("scope")),
                amr == null ? Set.of() : Set.copyOf(amr));
    }

    /**
     * The {@code scope} claim in either form the ecosystem uses: RFC 9068 and RFC 6749
     * define a space-delimited STRING, but Spring Authorization Server emits a JSON
     * ARRAY. Reading only one form turns the other into "no scopes" - which fails
     * closed, but denies every legitimate call.
     */
    static Set<String> scopesOf(Object claim) {
        Set<String> scopes = new HashSet<>();
        if (claim instanceof java.util.Collection<?> items) {
            items.forEach(i -> scopes.add(String.valueOf(i)));
        } else if (claim instanceof String text) {
            for (String s : text.trim().split("\\s+")) {
                if (!s.isEmpty()) scopes.add(s);
            }
        }
        return Set.copyOf(scopes);
    }

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    /** True only when the session proved a second factor. Absence of evidence is not evidence. */
    public boolean provedSecondFactor() {
        return amr.contains(SECOND_FACTOR);
    }
}
