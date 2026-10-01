package com.example.zerotrust.resource;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Mints access tokens the way the Authorization Server's token exchange does, for
 * tests. Defaults are a VALID token for this Resource Server; each test breaks
 * exactly one thing, so a failure can only be about that one thing.
 */
final class TestTokens {

    static final String ISSUER = "http://localhost:9000";
    static final String AUDIENCE = "zero-trust-api";
    static final String CLIENT_ID = "zero-trust-web";

    static final RSAKey KEY = generate("test-key");
    static final RSAKey OTHER_KEY = generate("some-other-key");

    private TestTokens() {}

    private static RSAKey generate(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A token under construction. */
    static final class Builder {
        long uid = 1;
        String type = "at+jwt";
        String issuer = ISSUER;
        List<String> audience = List.of(AUDIENCE);
        String clientId = CLIENT_ID;
        Object scope = "documents.read documents.write documents.approve";
        List<String> amr = List.of("pwd");
        Instant expiresAt = Instant.now().plusSeconds(300);
        RSAKey signWith = KEY;
        boolean signed = true;
        Consumer<JWTClaimsSet.Builder> extra = c -> {};

        Builder uid(long v) { uid = v; return this; }
        Builder type(String v) { type = v; return this; }
        Builder issuer(String v) { issuer = v; return this; }
        Builder audience(String... v) { audience = List.of(v); return this; }
        Builder noClientId() { clientId = null; return this; }
        Builder scope(String v) { scope = v; return this; }
        /** The form Spring Authorization Server actually emits: a JSON array. */
        Builder scopeArray(String... v) { scope = List.of(v); return this; }
        Builder amr(String... v) { amr = List.of(v); return this; }
        Builder withSecondFactor() { amr = List.of("pwd", "otp"); return this; }
        Builder expiresAt(Instant v) { expiresAt = v; return this; }
        Builder signedBy(RSAKey v) { signWith = v; return this; }
        Builder unsigned() { signed = false; return this; }
        Builder claim(String name, Object value) {
            Consumer<JWTClaimsSet.Builder> prior = extra;
            extra = c -> { prior.accept(c); c.claim(name, value); };
            return this;
        }

        String build() {
            try {
                JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                        .issuer(issuer).subject("user-" + uid).audience(audience)
                        .jwtID(UUID.randomUUID().toString())
                        .issueTime(Date.from(Instant.now().minusSeconds(5)))
                        .expirationTime(Date.from(expiresAt))
                        .claim("uid", uid).claim("scope", scope).claim("amr", amr);
                if (clientId != null) claims.claim("client_id", clientId);
                extra.accept(claims);

                JWSHeader header = new JWSHeader.Builder(signed ? JWSAlgorithm.RS256 : JWSAlgorithm.RS256)
                        .type(new JOSEObjectType(type)).keyID(signWith.getKeyID()).build();
                SignedJWT jwt = new SignedJWT(header, claims.build());
                if (!signed) {
                    // alg=none style: header and payload with an empty signature part.
                    return jwt.getHeader().toBase64URL() + "." + jwt.getPayload().toBase64URL() + ".";
                }
                jwt.sign(new RSASSASigner(signWith));
                return jwt.serialize();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    static Builder token() { return new Builder(); }

    /** A signature made by a DIFFERENT key, grafted onto this token's header and payload. */
    static String withForeignSignature(String validToken) {
        String foreign = token().signedBy(OTHER_KEY).build();
        String[] parts = validToken.split("\\.");
        return parts[0] + "." + parts[1] + "." + foreign.split("\\.")[2];
    }
}
