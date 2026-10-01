package com.example.zerotrust.bff.web;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The assurance level the browser is told comes from the amr claim the
 * Authorization Server wrote - and "MFA" is claimed only when a second factor
 * was actually proved.
 */
class SessionAssuranceTest {

    private static OidcUser user(Map<String, Object> extraClaims) {
        Map<String, Object> claims = new java.util.HashMap<>(Map.of("sub", "u@example.com"));
        claims.putAll(extraClaims);
        OidcIdToken token = new OidcIdToken("tv", Instant.now(), Instant.now().plusSeconds(60), claims);
        return new DefaultOidcUser(List.of(), token);
    }

    @Test
    void passwordOnlySessionIsReportedAsPassword() {
        assertThat(SessionController.levelOf(user(Map.of("amr", List.of("pwd"))))).isEqualTo("PASSWORD");
    }

    @Test
    void aSessionThatProvedACodeIsReportedAsMfa() {
        assertThat(SessionController.levelOf(user(Map.of("amr", List.of("pwd", "otp"))))).isEqualTo("MFA");
    }

    @Test
    void noAmrClaimMeansPasswordAssuranceNeverMfa() {
        // Absence of evidence is not evidence: default to the weaker claim.
        assertThat(SessionController.levelOf(user(Map.of()))).isEqualTo("PASSWORD");
    }

    @Test
    void anUnrelatedAmrValueDoesNotUpgradeTheSession() {
        assertThat(SessionController.levelOf(user(Map.of("amr", List.of("pwd", "sms"))))).isEqualTo("PASSWORD");
    }
}
