package com.example.zerotrust.resource;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ADR-SEC-008 at the API boundary. Every test here pairs a token that is broken
 * in exactly ONE way with the same token, unbroken, being accepted - so a pass
 * means that one property was rejected, not that the token was rejected for some
 * unrelated reason. (A wrong-audience test that passes because a stricter typ
 * gate fired first proves nothing about audience.)
 */
class AccessTokenValidationTest extends ResourceServerTestSupport {

    private void rejected(String token) throws Exception {
        mvc.perform(get("/api/documents").header("Authorization", bearer(token))).andExpect(status().isUnauthorized());
    }

    private void accepted(String token) throws Exception {
        mvc.perform(get("/api/documents").header("Authorization", bearer(token))).andExpect(status().isOk());
    }

    @Test
    void controlAValidTokenIsAccepted() throws Exception {
        accepted(TestTokens.token().build());
    }

    @Test
    void rejectsTokenWithWrongAudience() throws Exception {
        // The Authorization Server's own API, or any other service, shares this issuer and key.
        rejected(TestTokens.token().audience("auth-service-api").build());
        rejected(TestTokens.token().audience("payments-api").build());
        accepted(TestTokens.token().audience(TestTokens.AUDIENCE).build());
    }

    @Test
    void rejectsATokenThatNamesThisAudienceAlongsideAnother() throws Exception {
        // Accepting "any of" would let a token meant for a broader audience in.
        accepted(TestTokens.token().audience(TestTokens.AUDIENCE, "payments-api").build());   // present = fine
        rejected(TestTokens.token().audience("payments-api", "billing-api").build());          // absent = not
    }

    @Test
    void rejectsTokenWithWrongIssuer() throws Exception {
        rejected(TestTokens.token().issuer("https://evil.example.com").build());
        accepted(TestTokens.token().issuer(TestTokens.ISSUER).build());
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        rejected(TestTokens.token().expiresAt(Instant.now().minusSeconds(120)).build());
        accepted(TestTokens.token().expiresAt(Instant.now().plusSeconds(120)).build());
    }

    @Test
    void rejectsUnsignedOrInvalidSignatureToken() throws Exception {
        // Splice a FOREIGN signature on. Flipping the last base64url character of a 2048-bit RSA
        // signature only alters spare bits that decode away, so the token would stay valid and
        // such a test would pass while asserting nothing.
        String valid = TestTokens.token().build();
        rejected(TestTokens.withForeignSignature(valid));
        rejected(TestTokens.token().unsigned().build());
        accepted(valid);
    }

    @Test
    void rejectsATokenSignedByAnotherKeyEvenWithTheRightKeyId() throws Exception {
        rejected(TestTokens.token().signedBy(TestTokens.OTHER_KEY).build());
    }

    @Test
    void rejectsTokenWithWrongTypHeader() throws Exception {
        // RFC 9068: an ID token (typ JWT) must not be accepted as an access token.
        rejected(TestTokens.token().type("JWT").build());
        accepted(TestTokens.token().type("at+jwt").build());
    }

    @Test
    void rejectsTokenMissingClientId() throws Exception {
        rejected(TestTokens.token().noClientId().build());
        accepted(TestTokens.token().build());
    }

    @Test
    void rejectsTokenIssuedToADifferentClient() throws Exception {
        rejected(TestTokens.token().claim("client_id", "some-other-client").build());
    }

    @Test
    void aRequestWithNoTokenIsRefused() throws Exception {
        mvc.perform(get("/api/documents")).andExpect(status().isUnauthorized());
    }

    @Test
    void anUnlistedPathDoesNotExist() throws Exception {
        // Zero-trust default: nothing is reachable merely because it was not forbidden.
        mvc.perform(get("/api/anything-else").header("Authorization", bearer(TestTokens.token().build())))
                .andExpect(status().isForbidden());
    }
}
