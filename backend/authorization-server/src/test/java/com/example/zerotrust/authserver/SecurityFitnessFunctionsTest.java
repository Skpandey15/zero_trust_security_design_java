package com.example.zerotrust.authserver;

import com.example.zerotrust.authserver.config.SecurityProperties;
import com.example.zerotrust.authserver.domain.Role;
import com.example.zerotrust.authserver.domain.User;
import com.example.zerotrust.authserver.repository.UserRepository;
import com.example.zerotrust.authserver.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Executable security fitness functions — the architecture document's Section 18
 * invariants expressed as release-gating tests (Section 24.6).
 *
 * These mint tokens directly instead of logging in, so they exercise the resource
 * server's validation chain in isolation and do not consume the shared per-IP
 * login counter.
 *
 * Not yet representable in this service, and owned by later work packages:
 *   - rejectsCrossTenantResourceAccess ............ WP-03 (no tenancy model yet)
 *   - rejectsMissingRequiredAuthenticationLevel ... WP-03 (no authLevel claim yet)
 *   - deniesPolicyDecisionOnPrivilegedWriteWhenPdpUnavailable ... WP-03 (no PDP yet)
 */
@SpringBootTest(properties = "app.fitness=security")
@AutoConfigureMockMvc
class SecurityFitnessFunctionsTest {

    @Autowired MockMvc mockMvc;
    @Autowired JwtEncoder jwtEncoder;
    @Autowired @org.springframework.beans.factory.annotation.Qualifier("apiJwtDecoder") JwtDecoder apiJwtDecoder;
    @Autowired TokenService tokenService;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired SecurityProperties props;

    private User user;

    @BeforeEach
    void seedUser() {
        user = users.findByEmail("fitness@example.com").orElseGet(() ->
                users.save(new User("fitness@example.com", encoder.encode("fitness-password-12"),
                        "Fitness", EnumSet.of(Role.USER))));
    }

    /** A well-formed token the service itself would issue — the positive control. */
    @Test
    void acceptsAGenuineAccessToken() throws Exception {
        callProfile(tokenService.createAccessToken(user)).andExpect(status().isOk());
    }

    @Test
    void rejectsTokenWithWrongIssuer() throws Exception {
        callProfile(mint(c -> c.issuer("https://evil.example.com"), "at+jwt"))
                .andExpect(status().isUnauthorized());
    }

    /**
     * The invariant the service previously failed: JwtValidators.createDefaultWithIssuer()
     * wires only timestamp + issuer checks, so a token minted under the same issuer and
     * key for a DIFFERENT audience — e.g. an OAuth2 token from the authorization server —
     * was accepted by the API chain. Minting an aud claim is not validating one.
     */
    @Test
    void rejectsTokenWithWrongAudience() throws Exception {
        String wrongAudience = mint(c -> c.audience(List.of("some-other-api")), "at+jwt");

        // Assert at the decoder, not only through the filter chain. Via HTTP this token
        // could return 401 for an unrelated reason (a stricter typ gate, say) and the
        // test would pass while audience validation was absent — a vacuous green. This
        // pins the failure to the audience claim itself.
        JwtValidationException denied = org.junit.jupiter.api.Assertions.assertThrows(
                JwtValidationException.class, () -> apiJwtDecoder.decode(wrongAudience));
        org.junit.jupiter.api.Assertions.assertTrue(
                denied.getMessage().toLowerCase().contains("aud"),
                "expected an audience failure, got: " + denied.getMessage());

        // Same token, correct audience: accepted. Proves the rejection was the audience.
        apiJwtDecoder.decode(mint(c -> { }, "at+jwt"));

        callProfile(wrongAudience).andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        Instant past = Instant.now().minus(30, ChronoUnit.MINUTES);
        callProfile(mint(c -> c.issuedAt(past).expiresAt(past.plusSeconds(60)), "at+jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsUnsignedOrInvalidSignatureToken() throws Exception {
        // Splice this token's header+payload onto a different token's signature. Note
        // that flipping the LAST base64url character would not work: a 2048-bit RSA
        // signature leaves spare bits in the final character, so editing it decodes to
        // the same bytes and the token stays valid.
        String[] mine = tokenService.createAccessToken(user).split(java.util.regex.Pattern.quote("."));
        String[] other = tokenService.createAccessToken(user).split(java.util.regex.Pattern.quote("."));
        callProfile(mine[0] + "." + mine[1] + "." + other[2]).andExpect(status().isUnauthorized());

        // An unsigned ("alg":"none"-style) token must not be accepted either.
        callProfile(mine[0] + "." + mine[1] + ".").andExpect(status().isUnauthorized());
    }

    /** RFC 9068: an access token must declare typ=at+jwt, so it cannot be substituted. */
    @Test
    void rejectsTokenWithWrongTypHeader() throws Exception {
        callProfile(mint(c -> { }, "JWT")).andExpect(status().isUnauthorized());
    }

    /** RFC 9068 requires client_id on an access token. */
    @Test
    void rejectsTokenMissingClientId() throws Exception {
        callProfile(mintWithoutClientId()).andExpect(status().isUnauthorized());
    }

    /**
     * Continuous verification: a token issued before the user's token_valid_after
     * watermark is rejected mid-life, not merely at expiry.
     */
    @Test
    void rejectsRevokedOrPreSecurityEpochSession() throws Exception {
        String token = tokenService.createAccessToken(user);
        callProfile(token).andExpect(status().isOk());

        user.setTokenValidAfter(Instant.now().plusSeconds(5));   // e.g. logout-all / disable
        users.save(user);

        callProfile(token).andExpect(status().isUnauthorized());

        user.setTokenValidAfter(null);   // restore for other tests
        users.save(user);
    }

    // ---------- helpers ----------

    private org.springframework.test.web.servlet.ResultActions callProfile(String token) throws Exception {
        return mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + token));
    }

    /** A valid access token with one claim deliberately altered. */
    private String mint(Consumer<JwtClaimsSet.Builder> mutate, String type) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .audience(List.of(props.apiAudience()))
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600))
                .subject(user.getEmail())
                .claim("uid", user.getId())
                .claim("client_id", props.firstPartyClientId())
                .claim("authorities", List.of("ROLE_USER", "profile:read"));
        mutate.accept(claims);
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type(type).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }

    private String mintWithoutClientId() {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .audience(List.of(props.apiAudience()))
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600))
                .subject(user.getEmail())
                .claim("uid", user.getId())
                .claim("authorities", List.of("ROLE_USER", "profile:read"))
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("at+jwt").build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
